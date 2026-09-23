// Package relaytest is an in-memory relay on httptest for the agent's tests:
// it verifies Clair-Ed25519 canonical v2 signatures as the relay does with
// AUTH_NONCE=required (a nonce on every request, spent once per key, the
// Host bound; relay ADR 2026-09.9vsq), holds pairings and per-pair
// mailboxes, streams envelopes and presence over SSE with bounded ends, and
// records what clients did. It implements the relay's published contract
// (internal/relay/testdata/openapi.json, checked by the relay package's
// contract test) for the routes the agent and the phone use, not the relay.
package relaytest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"claircode.app/clair-agent/internal/envelope"
)

// ReadHeaderTimeout is for a server that mounts the fake's handler itself.
const ReadHeaderTimeout = 10 * time.Second

// Limits the fake enforces, matching the relay's.
const (
	skewMax = 300 * time.Second
	// The relay's JSON body parser takes up to 4.5 MiB, above the 4 MiB
	// envelope and batch caps, so those answer with their own codes.
	maxBody        = envelope.MaxEnvelopeJSON + envelope.MaxEnvelopeJSON/8
	maxEnvelope    = envelope.MaxEnvelopeJSON
	batchMax       = 100
	pairingLife    = 10 * time.Minute
	pairingGrace   = 15 * time.Minute
	pollInterval   = 5 * time.Millisecond
	defaultRetryMS = 10
	maxPushToken   = 1024
)

// The relay's id shapes: a pair or pairing id, an X25519 key, a Last-Event-ID.
var (
	idPattern     = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
	keyPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	lastIDPattern = regexp.MustCompile(`^\d{1,15}$`)
	// FCM's token alphabet, as the relay checks it (`^[A-Za-z0-9_:.-]{1,1024}$`;
	// RE2 caps a repeat at 1000, so the length is checked apart).
	pushTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_:.-]+$`)
)

// The relay's Authorization parse (clair-server src/auth/canonical.ts).
var (
	authHeaderPattern = regexp.MustCompile(`(?s)^Clair-Ed25519\s+(.+)$`)
	authParamPattern  = regexp.MustCompile(`^([a-z]+)=([^,\s]+)$`)
	base64URLPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	tsPattern         = regexp.MustCompile(`^\d{1,12}$`)
	noncePattern      = regexp.MustCompile(`^[A-Za-z0-9_-]{22,43}$`)
)

// Recorded is one request the fake answered. Nonce is the one its header
// carried; Key and TS are empty unless the signature verified.
type Recorded struct {
	Method     string
	RequestURI string
	Host       string
	Key        string
	TS         int64
	Nonce      string
	Status     int
}

// Role is a device's side of a pair.
type Role string

// The two roles.
const (
	RoleHost  Role = "host"
	RolePhone Role = "phone"
)

type pairingRec struct {
	host      string
	createdAt time.Time
	expiresAt time.Time
	completed bool
	phone     string
	phonePub  string
	hello     envelope.Envelope
}

type pairRec struct {
	host, phone string
	revoked     bool
	// The stream that owns each side's presence, 0 for none: the newest
	// open wins and an older one ends quietly (relay ADR 2026-09.7fc3).
	hostStream, phoneStream int64
}

// owner is the stream id owning role's side.
func (p *pairRec) owner(role Role) *int64 {
	if role == RoleHost {
		return &p.hostStream
	}
	return &p.phoneStream
}

type row struct {
	cursor int64
	pair   string
	dir    envelope.Dir
	env    envelope.Envelope
}

// Fake is one relay. Knobs are read under the lock on each request, so a
// test may flip them mid-flight.
type Fake struct {
	// Server is the httptest server; URL is Server.URL.
	Server *httptest.Server
	// URL is the relay's base URL for relay.Options.
	URL string

	mu sync.Mutex
	// Now is the relay's clock for the skew check and pairing expiry.
	Now func() time.Time
	// StreamLimit ends every /events connection after that many envelope
	// events with the relay's closing block (`id:` + `retry:`); 0 never ends.
	StreamLimit int
	// RetryMS is the `retry:` hint of the closing block.
	RetryMS int
	// Silent makes /events send its headers and then nothing, forever.
	Silent bool
	// NoServerTime omits `serverTime` from 401 bodies (the Date fallback path).
	NoServerTime bool
	// StringCursors sends receipt cursors as JSON strings instead of the
	// relay's integers, for the tolerance relay.Cursor keeps.
	StringCursors bool
	// MailboxFull answers every upload 429 mailbox_full with Retry-After: 1.
	MailboxFull bool
	// FailNext makes the next FailNext authenticated requests answer 503.
	FailNext int
	// KeepaliveMS sends a `: keepalive` comment on /events at that cadence; 0 sends none.
	KeepaliveMS int
	// ReplayNext answers the next ReplayNext requests that verify 401
	// replay, as if their nonce had been spent already.
	ReplayNext int
	// EdgeLimitNext answers the next EdgeLimitNext requests with the
	// platform firewall's 429: plain text, no Retry-After, before the relay
	// sees them.
	EdgeLimitNext int

	pairings  map[string]*pairingRec
	pairs     map[string]*pairRec
	rows      []row
	cursor    int64
	inflight  map[string]int
	maxFlight map[string]int
	requests  []Recorded
	lastIDs   []string
	// nonces holds each spent key|nonce until its ts leaves the skew window.
	nonces    map[string]time.Time
	streamSeq int64
}

// New starts a fake relay over plain HTTP; Close it with the test's cleanup.
func New() *Fake {
	f := newFake()
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	f.URL = f.Server.URL
	return f
}

// NewTLS starts a fake relay over TLS with httptest's certificate; the
// client needs Server.Certificate() in its RootCAs.
func NewTLS() *Fake {
	f := newFake()
	f.Server = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	// A client that does not trust the certificate is a test case, not news.
	f.Server.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.Server.StartTLS()
	f.URL = f.Server.URL
	return f
}

func newFake() *Fake {
	return &Fake{
		Now:       time.Now,
		RetryMS:   defaultRetryMS,
		pairings:  make(map[string]*pairingRec),
		pairs:     make(map[string]*pairRec),
		inflight:  make(map[string]int),
		maxFlight: make(map[string]int),
		nonces:    make(map[string]time.Time),
	}
}

// Close stops the server.
func (f *Fake) Close() { f.Server.Close() }

// AddPair registers a pair without a pairing flow; keys are base64url public
// keys as relay.Client.Key reports them.
func (f *Fake) AddPair(pairID, hostKey, phoneKey string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pairs[pairID] = &pairRec{host: hostKey, phone: phoneKey}
}

// Inject appends an envelope to a pair's mailbox as if its sender uploaded it.
func (f *Fake) Inject(env envelope.Envelope) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.appendRow(env)
}

// Rows returns the mailbox rows for a pair and direction, in cursor order.
func (f *Fake) Rows(pairID string, dir envelope.Dir) []envelope.Envelope {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []envelope.Envelope
	for i := range f.rows {
		if f.rows[i].pair == pairID && f.rows[i].dir == dir {
			out = append(out, f.rows[i].env)
		}
	}
	return out
}

// Requests returns every request answered so far.
func (f *Fake) Requests() []Recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Recorded(nil), f.requests...)
}

// LastEventIDs returns the Last-Event-ID header of every /events and /wait
// connection, "" when absent.
func (f *Fake) LastEventIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.lastIDs...)
}

// MaxInFlight is the most concurrent uploads seen for a pair and direction.
func (f *Fake) MaxInFlight(pairID string, dir envelope.Dir) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.maxFlight[pairID+"/"+string(dir)]
}

// Revoke marks a pair revoked, as the other side's DELETE would.
func (f *Fake) Revoke(pairID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p, ok := f.pairs[pairID]; ok {
		p.revoked = true
	}
}

// Set changes knobs under the lock.
func (f *Fake) Set(fn func(f *Fake)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *Fake) appendRow(env envelope.Envelope) (cursor int64, dup bool) {
	for i := range f.rows {
		if f.rows[i].pair == env.Pair && f.rows[i].env.ID == env.ID {
			return f.rows[i].cursor, true
		}
	}
	f.cursor++
	f.rows = append(f.rows, row{cursor: f.cursor, pair: env.Pair, dir: env.Dir, env: env})
	return f.cursor, false
}

// authed is the verified identity of a request.
type authed struct {
	key   string
	ts    int64
	nonce string
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(mustJSON(v))
}

// refuse answers the relay's error body with one of its stable codes.
func refuse(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

// mustJSON encodes a value the fake built itself; a failure is a bug in the fake.
func mustJSON(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("relaytest: encode %T: %v", v, err))
	}
	return data
}

// serve authenticates and routes.
func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		http.Error(w, "read", http.StatusBadRequest)
		return
	}
	if len(body) > maxBody {
		// The relay's body parser refuses it before the auth guard runs.
		_, _ = io.Copy(io.Discard, r.Body)
		refuse(w, http.StatusRequestEntityTooLarge, "payload_too_large")
		return
	}
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	f.mu.Lock()
	edge := f.EdgeLimitNext > 0
	if edge {
		f.EdgeLimitNext--
	}
	f.mu.Unlock()
	var who authed
	ok := false
	if edge {
		http.Error(rec, "Too Many Requests", http.StatusTooManyRequests)
	} else {
		who, ok = f.authenticate(rec, r, body)
	}
	f.mu.Lock()
	f.requests = append(f.requests, Recorded{Method: r.Method, RequestURI: r.URL.RequestURI(), Host: r.Host, Key: who.key, TS: who.ts, Nonce: who.nonce, Status: rec.status})
	idx := len(f.requests) - 1
	fail := f.FailNext > 0
	if ok && fail {
		f.FailNext--
	}
	f.mu.Unlock()
	if !ok {
		return
	}
	switch {
	case fail:
		http.Error(rec, "cold start", http.StatusServiceUnavailable)
	default:
		f.route(rec, r, who, body)
	}
	f.mu.Lock()
	f.requests[idx].Status = rec.status
	f.mu.Unlock()
}

// statusRecorder remembers the status written.
type statusRecorder struct {
	http.ResponseWriter

	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.NewResponseController reach the flusher.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// authenticate verifies the Clair-Ed25519 header as the relay's guard does
// with AUTH_NONCE=required, in its order — parse, skew, body, signature,
// then spend the nonce — answering 401 (or 415) itself. The canonical string
// is built here, not borrowed from the client, so a client bug cannot hide.
func (f *Fake) authenticate(w http.ResponseWriter, r *http.Request, body []byte) (authed, bool) {
	f.mu.Lock()
	now := f.Now()
	noServerTime := f.NoServerTime
	f.mu.Unlock()
	unauthorized := func(reason string) bool {
		resp := map[string]any{"error": "unauthorized", "reason": reason}
		if !noServerTime {
			resp["serverTime"] = now.Unix()
		}
		w.Header().Set("WWW-Authenticate", `Clair-Ed25519 realm="clair-relay"`)
		writeJSON(w, http.StatusUnauthorized, resp)
		return false
	}
	m := authHeaderPattern.FindStringSubmatch(strings.TrimSpace(r.Header.Get("Authorization")))
	if m == nil {
		return authed{}, unauthorized("malformed")
	}
	fields := make(map[string]string)
	for part := range strings.SplitSeq(m[1], ",") {
		kv := authParamPattern.FindStringSubmatch(strings.TrimSpace(part))
		if kv == nil {
			return authed{}, unauthorized("malformed")
		}
		if _, dup := fields[kv[1]]; dup {
			return authed{}, unauthorized("malformed")
		}
		fields[kv[1]] = kv[2]
	}
	// Exactly key, ts, nonce and sig: a v1 header (no nonce) is malformed
	// once the relay requires nonces.
	nonce := fields["nonce"]
	carried := authed{nonce: nonce}
	if len(fields) != 4 || fields["key"] == "" || fields["ts"] == "" || fields["sig"] == "" || nonce == "" {
		return carried, unauthorized("malformed")
	}
	if !base64URLPattern.MatchString(fields["key"]) || !base64URLPattern.MatchString(fields["sig"]) ||
		!tsPattern.MatchString(fields["ts"]) || !noncePattern.MatchString(nonce) {
		return carried, unauthorized("malformed")
	}
	ts, _ := strconv.ParseInt(fields["ts"], 10, 64)
	if d := now.Unix() - ts; d > int64(skewMax/time.Second) || -d > int64(skewMax/time.Second) {
		return carried, unauthorized("skew")
	}
	if r.Host == "" {
		return carried, unauthorized("malformed")
	}
	// The relay hashes the bytes its JSON parser consumed; any other body
	// cannot be verified and is refused before the signature is checked.
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); len(body) > 0 && mt != "application/json" {
		refuse(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return carried, false
	}
	key, _ := base64.RawURLEncoding.DecodeString(fields["key"])
	sig, _ := base64.RawURLEncoding.DecodeString(fields["sig"])
	sum := sha256.Sum256(body)
	canonical := strings.Join([]string{
		"clair-v2", strings.ToUpper(r.Method), strings.ToLower(r.Host), r.URL.RequestURI(),
		fields["ts"], nonce, hex.EncodeToString(sum[:]),
	}, "\n")
	if len(key) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize ||
		!ed25519.Verify(ed25519.PublicKey(key), []byte(canonical), sig) {
		return carried, unauthorized("signature")
	}
	// Spent only after the signature verifies, so nobody can burn another
	// key's nonces; kept until ts leaves the skew window.
	f.mu.Lock()
	for k, exp := range f.nonces {
		if now.After(exp) {
			delete(f.nonces, k)
		}
	}
	spent := fields["key"] + "|" + nonce
	_, replayed := f.nonces[spent]
	if f.ReplayNext > 0 {
		f.ReplayNext--
		replayed = true
	} else if !replayed {
		f.nonces[spent] = time.Unix(ts, 0).Add(skewMax)
	}
	f.mu.Unlock()
	if replayed {
		return carried, unauthorized("replay")
	}
	return authed{key: fields["key"], ts: ts, nonce: nonce}, true
}

// route dispatches an authenticated request.
func (f *Fake) route(w http.ResponseWriter, r *http.Request, who authed, body []byte) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case r.Method == http.MethodPost && len(parts) == 2 && parts[0] == "v1" && parts[1] == "pairings":
		f.mintPairing(w, who)
	case r.Method == http.MethodGet && len(parts) == 4 && parts[1] == "pairings" && parts[3] == "wait":
		f.waitPairing(w, r, who, parts[2])
	case r.Method == http.MethodPost && len(parts) == 4 && parts[1] == "pairings" && parts[3] == "complete":
		f.completePairing(w, who, parts[2], body)
	case r.Method == http.MethodPost && len(parts) == 4 && parts[1] == "pairs" && parts[3] == "envelopes":
		f.upload(w, who, parts[2], body)
	case r.Method == http.MethodPost && len(parts) == 4 && parts[1] == "pairs" && parts[3] == "ack":
		f.ack(w, who, parts[2], body)
	case r.Method == http.MethodGet && len(parts) == 4 && parts[1] == "pairs" && parts[3] == "events":
		f.events(w, r, who, parts[2])
	case r.Method == http.MethodDelete && len(parts) == 3 && parts[1] == "pairs":
		f.revokePair(w, who, parts[2])
	default:
		http.NotFound(w, r)
	}
}

func (f *Fake) mintPairing(w http.ResponseWriter, who authed) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	id := base64.RawURLEncoding.EncodeToString(raw[:])
	f.mu.Lock()
	now := f.Now()
	f.pairings[id] = &pairingRec{host: who.key, createdAt: now, expiresAt: now.Add(pairingLife)}
	f.mu.Unlock()
	writeJSON(w, http.StatusCreated, map[string]any{"pairingId": id, "expiresAt": now.Add(pairingLife).UTC().Format(time.RFC3339)})
}

// member reports the caller's role in a pair, answering 404/410 itself.
func (f *Fake) member(w http.ResponseWriter, who authed, pairID string) (Role, bool) {
	f.mu.Lock()
	p, ok := f.pairs[pairID]
	ok = ok && idPattern.MatchString(pairID)
	var role Role
	revoked := false
	if ok {
		switch who.key {
		case p.host:
			role = RoleHost
		case p.phone:
			role = RolePhone
		default:
			ok = false
		}
		revoked = p.revoked
	}
	f.mu.Unlock()
	if !ok {
		refuse(w, http.StatusNotFound, "pair_not_found")
		return "", false
	}
	if revoked {
		refuse(w, http.StatusGone, "pair_revoked")
		return "", false
	}
	return role, true
}

// outbound is the direction a role uploads; inbound the one it receives.
func outbound(role Role) envelope.Dir {
	if role == RoleHost {
		return envelope.DirH2P
	}
	return envelope.DirP2H
}

// checkEnvelope validates one uploaded envelope as the relay does: its
// schema, then that it names the route's pair and the caller's direction,
// then the 4 MiB cap. A non-empty code is the refusal.
func checkEnvelope(raw json.RawMessage, pair string, dir envelope.Dir) (env envelope.Envelope, status int, code string) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&env) != nil || !idPattern.MatchString(env.Pair) || env.Validate(env.Pair, env.Dir) != nil {
		return env, http.StatusBadRequest, "invalid_envelope"
	}
	switch {
	case env.Pair != pair:
		return env, http.StatusBadRequest, "pair_mismatch"
	case env.Dir != dir:
		return env, http.StatusBadRequest, "dir_mismatch"
	case len(mustJSON(env)) > maxEnvelope:
		return env, http.StatusRequestEntityTooLarge, "envelope_too_large"
	}
	return env, 0, ""
}

func (f *Fake) completePairing(w http.ResponseWriter, who authed, id string, body []byte) {
	if !idPattern.MatchString(id) {
		refuse(w, http.StatusNotFound, "pairing_not_found")
		return
	}
	var req struct {
		PhonePub  string          `json:"phonePub"`
		PushToken *string         `json:"pushToken"`
		Envelope  json.RawMessage `json:"envelope"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if dec.Decode(&req) != nil || !keyPattern.MatchString(req.PhonePub) || req.Envelope == nil ||
		(req.PushToken != nil && (len(*req.PushToken) > maxPushToken || !pushTokenPattern.MatchString(*req.PushToken))) {
		refuse(w, http.StatusBadRequest, "invalid_body")
		return
	}
	// The hello is the first phone → host envelope; its pair is this pairing's id.
	hello, status, code := checkEnvelope(req.Envelope, id, envelope.DirP2H)
	if code != "" {
		refuse(w, status, code)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.pairings[id]
	switch {
	case !ok:
		refuse(w, http.StatusNotFound, "pairing_not_found")
	case p.host == who.key:
		refuse(w, http.StatusBadRequest, "self_pairing")
	case p.completed:
		refuse(w, http.StatusConflict, "pairing_used")
	case !f.Now().Before(p.expiresAt):
		refuse(w, http.StatusGone, "pairing_expired")
	default:
		p.completed, p.phone, p.phonePub, p.hello = true, who.key, req.PhonePub, hello
		f.pairs[id] = &pairRec{host: p.host, phone: who.key}
		writeJSON(w, http.StatusCreated, map[string]string{"pairId": id})
	}
}

// sse prepares a stream response and returns a writer of raw SSE text.
func sse(w http.ResponseWriter) func(string) bool {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	_ = rc.Flush()
	return func(s string) bool {
		if _, err := io.WriteString(w, s); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
}

// waitPairing is GET /v1/pairings/{id}/wait: `pending` at once, then
// `completed` or `expired`. A completed pairing is served again until the
// sweep removes it, pairingGrace past its expiry.
func (f *Fake) waitPairing(w http.ResponseWriter, r *http.Request, who authed, id string) {
	f.mu.Lock()
	f.lastIDs = append(f.lastIDs, r.Header.Get("Last-Event-ID"))
	p, ok := f.pairings[id]
	ok = ok && p.host == who.key
	var swept, expired bool
	var pending []byte
	if ok {
		now := f.Now()
		swept = now.After(p.expiresAt.Add(pairingGrace))
		expired = !p.completed && !now.Before(p.expiresAt)
		pending = mustJSON(map[string]any{"pairingId": id, "expiresAt": p.expiresAt.UTC().Format(time.RFC3339)})
	}
	f.mu.Unlock()
	if !ok || swept {
		refuse(w, http.StatusNotFound, "pairing_not_found")
		return
	}
	if expired {
		refuse(w, http.StatusGone, "pairing_expired")
		return
	}
	write := sse(w)
	if !write("id: 0\nevent: pending\ndata: " + string(pending) + "\n\n") {
		return
	}
	for {
		f.mu.Lock()
		done := p.completed
		expired = !done && !f.Now().Before(p.expiresAt)
		data := mustJSON(map[string]any{"pairId": id, "phonePub": p.phonePub, "envelope": p.hello})
		retry := f.RetryMS
		f.mu.Unlock()
		if done {
			write("id: 1\nevent: completed\ndata: " + string(data) + "\n\n")
			write(fmt.Sprintf("id: 1\nretry: %d\n: reconnect\n\n", retry))
			return
		}
		if expired {
			write("id: 1\nevent: expired\ndata: " + string(mustJSON(map[string]string{"pairingId": id})) + "\n\n")
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(pollInterval):
		}
	}
}

func (f *Fake) upload(w http.ResponseWriter, who authed, pairID string, body []byte) {
	role, ok := f.member(w, who, pairID)
	if !ok {
		return
	}
	dir := outbound(role)
	items, code := unwrapBatch(body)
	if code != "" {
		refuse(w, http.StatusBadRequest, code)
		return
	}
	envs := make([]envelope.Envelope, 0, len(items))
	for _, raw := range items {
		env, status, code := checkEnvelope(raw, pairID, dir)
		if code != "" {
			refuse(w, status, code)
			return
		}
		envs = append(envs, env)
	}
	// The relay measures the array of envelopes, even for a lone one.
	if len(mustJSON(envs)) > maxEnvelope {
		refuse(w, http.StatusRequestEntityTooLarge, "batch_too_large")
		return
	}
	key := pairID + "/" + string(dir)
	f.mu.Lock()
	f.inflight[key]++
	f.maxFlight[key] = max(f.maxFlight[key], f.inflight[key])
	full := f.MailboxFull
	f.mu.Unlock()
	// Hold the slot across a short delay so overlapping uploads are visible.
	time.Sleep(2 * pollInterval)
	defer func() {
		f.mu.Lock()
		f.inflight[key]--
		f.mu.Unlock()
	}()
	if full {
		w.Header().Set("Retry-After", "1")
		refuse(w, http.StatusTooManyRequests, "mailbox_full")
		return
	}
	f.mu.Lock()
	stringCursors := f.StringCursors
	accepted := make([]map[string]any, 0, len(envs))
	duplicates := []string{}
	for _, env := range envs {
		cursor, dup := f.appendRow(env)
		if dup {
			duplicates = append(duplicates, env.ID)
			continue
		}
		var c any = cursor
		if stringCursors {
			c = strconv.FormatInt(cursor, 10)
		}
		accepted = append(accepted, map[string]any{"id": env.ID, "cursor": c, "ttlSec": env.TTLSec})
	}
	f.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"accepted": accepted, "duplicates": duplicates})
}

// unwrapBatch splits an upload body into its envelopes: one bare envelope,
// or {"envelopes": [...]} with 1 to batchMax of them.
func unwrapBatch(body []byte) (items []json.RawMessage, code string) {
	if !json.Valid(body) {
		// The relay's JSON parser answers this with its generic code.
		return nil, "bad_request"
	}
	var probe map[string]json.RawMessage
	if json.Unmarshal(body, &probe) != nil || probe["envelopes"] == nil {
		return []json.RawMessage{body}, ""
	}
	if json.Unmarshal(probe["envelopes"], &items) != nil || len(items) == 0 {
		return nil, "invalid_batch"
	}
	if len(items) > batchMax {
		return nil, "too_many_envelopes"
	}
	return items, ""
}

func (f *Fake) ack(w http.ResponseWriter, who authed, pairID string, body []byte) {
	role, ok := f.member(w, who, pairID)
	if !ok {
		return
	}
	// The relay's schema is strict: {cursor} is a non-negative JSON integer,
	// never a string.
	var req struct {
		Cursor *int64 `json:"cursor"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if dec.Decode(&req) != nil || req.Cursor == nil || *req.Cursor < 0 {
		refuse(w, http.StatusBadRequest, "invalid_body")
		return
	}
	cursor := *req.Cursor
	inbound := outbound(role).Opposite()
	f.mu.Lock()
	kept := f.rows[:0]
	for i := range f.rows {
		if f.rows[i].pair != pairID || f.rows[i].dir != inbound || f.rows[i].cursor > cursor {
			kept = append(kept, f.rows[i])
		}
	}
	f.rows = kept
	f.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (f *Fake) revokePair(w http.ResponseWriter, who authed, pairID string) {
	if _, ok := f.member(w, who, pairID); !ok {
		return
	}
	f.mu.Lock()
	f.pairs[pairID].revoked = true
	f.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (f *Fake) events(w http.ResponseWriter, r *http.Request, who authed, pairID string) {
	role, ok := f.member(w, who, pairID)
	if !ok {
		return
	}
	var last int64
	if ids := r.Header.Values("Last-Event-ID"); len(ids) > 0 {
		if !lastIDPattern.MatchString(ids[0]) {
			refuse(w, http.StatusBadRequest, "invalid_last_event_id")
			return
		}
		last, _ = strconv.ParseInt(ids[0], 10, 64)
	}
	inbound := outbound(role).Opposite()
	f.mu.Lock()
	f.lastIDs = append(f.lastIDs, r.Header.Get("Last-Event-ID"))
	p := f.pairs[pairID]
	f.streamSeq++
	mine := f.streamSeq
	*p.owner(role) = mine
	silent := f.Silent
	keepaliveMS := f.KeepaliveMS
	f.mu.Unlock()
	defer func() {
		// Only the owner's close clears the side; a superseded one clears nothing.
		f.mu.Lock()
		if *p.owner(role) == mine {
			*p.owner(role) = 0
		}
		f.mu.Unlock()
	}()
	write := sse(w)
	if silent {
		<-r.Context().Done()
		return
	}
	delivered := 0
	peerState := ""
	lastKeepalive := time.Now()
	for {
		f.mu.Lock()
		limit, retry := f.StreamLimit, f.RetryMS
		revoked := p.revoked
		superseded := *p.owner(role) != mine
		peer := RolePhone
		if role == RolePhone {
			peer = RoleHost
		}
		peerOpen := *p.owner(peer) != 0
		var next *row
		for i := range f.rows {
			if f.rows[i].pair == pairID && f.rows[i].dir == inbound && f.rows[i].cursor > last {
				next = &f.rows[i]
				break
			}
		}
		f.mu.Unlock()
		if revoked {
			write(fmt.Sprintf("id: %d\nevent: revoked\ndata: %s\n\n", last, mustJSON(map[string]string{"pairId": pairID})))
			return
		}
		if superseded {
			// A newer stream owns this side: end with no event and no retry:.
			return
		}
		state := "idle"
		if peerOpen {
			state = "connected"
		}
		if state != peerState {
			peerState = state
			data := mustJSON(map[string]any{"peer": peer, "state": state, "at": f.Now().Unix()})
			if !write(fmt.Sprintf("id: %d\nevent: presence\ndata: %s\n\n", last, data)) {
				return
			}
		}
		if next != nil {
			data := mustJSON(next.env)
			if !write(fmt.Sprintf("id: %d\nevent: envelope\ndata: %s\n\n", next.cursor, data)) {
				return
			}
			last = next.cursor
			delivered++
			if limit > 0 && delivered >= limit {
				write(fmt.Sprintf("id: %d\nretry: %d\n: reconnect\n\n", last, retry))
				return
			}
			continue
		}
		if keepaliveMS > 0 && time.Since(lastKeepalive) >= time.Duration(keepaliveMS)*time.Millisecond {
			lastKeepalive = time.Now()
			if !write(": keepalive\n\n") {
				return
			}
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(pollInterval):
		}
	}
}
