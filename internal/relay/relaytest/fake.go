// Package relaytest is an in-memory relay on httptest for the agent's tests:
// it verifies Clair-Ed25519 signatures, holds pairings and per-pair
// mailboxes, streams envelopes and presence over SSE with bounded ends, and
// records what clients did. It implements the relay's contract as the agent
// sees it (RELAY.md §7 as pinned by the relay's own plan), not the relay.
package relaytest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"time"

	"claircode.app/clair-agent/internal/envelope"
	"claircode.app/clair-agent/internal/relay"
)

// ReadHeaderTimeout is for a server that mounts the fake's handler itself.
const ReadHeaderTimeout = 10 * time.Second

// Limits the fake enforces, matching the relay's.
const (
	skewMax        = 300 * time.Second
	maxBody        = envelope.MaxEnvelopeJSON
	batchMax       = 100
	pairingLife    = 10 * time.Minute
	pairingGrace   = 15 * time.Minute
	pollInterval   = 5 * time.Millisecond
	defaultRetryMS = 10
)

// Recorded is one authenticated request the fake served.
type Recorded struct {
	Method     string
	RequestURI string
	Key        string
	TS         int64
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
	// Open stream counts per role, for presence.
	hostOpen, phoneOpen int
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
	// NumericCursors sends cursors as JSON numbers instead of strings.
	NumericCursors bool
	// MailboxFull answers every upload 429 mailbox_full with Retry-After: 1.
	MailboxFull bool
	// FailNext makes the next FailNext authenticated requests answer 503.
	FailNext int
	// KeepaliveMS sends a `: keepalive` comment on /events at that cadence; 0 sends none.
	KeepaliveMS int

	pairings  map[string]*pairingRec
	pairs     map[string]*pairRec
	rows      []row
	cursor    int64
	inflight  map[string]int
	maxFlight map[string]int
	requests  []Recorded
	lastIDs   []string
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

// Requests returns every authenticated request so far.
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
	key string
	ts  int64
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(mustJSON(v))
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
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	who, ok := f.authenticate(rec, r, body)
	f.mu.Lock()
	f.requests = append(f.requests, Recorded{Method: r.Method, RequestURI: r.URL.RequestURI(), Key: who.key, TS: who.ts, Status: rec.status})
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
	case len(body) > maxBody:
		writeJSON(rec, http.StatusRequestEntityTooLarge, map[string]string{"error": "too_large"})
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

// authenticate verifies the Clair-Ed25519 header, answering 401 itself.
func (f *Fake) authenticate(w http.ResponseWriter, r *http.Request, body []byte) (authed, bool) {
	f.mu.Lock()
	now := f.Now()
	noServerTime := f.NoServerTime
	f.mu.Unlock()
	refuse := func(reason string) bool {
		resp := map[string]any{"error": "unauthorized", "reason": reason}
		if !noServerTime {
			resp["serverTime"] = now.Unix()
		}
		w.Header().Set("WWW-Authenticate", `Clair-Ed25519 realm="clair-relay"`)
		writeJSON(w, http.StatusUnauthorized, resp)
		return false
	}
	header := r.Header.Get("Authorization")
	scheme, params, found := strings.Cut(header, " ")
	if !found || scheme != "Clair-Ed25519" {
		return authed{}, refuse("malformed")
	}
	fields := make(map[string]string)
	for part := range strings.SplitSeq(params, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return authed{}, refuse("malformed")
		}
		fields[k] = v
	}
	key, err := base64.RawURLEncoding.Strict().DecodeString(fields["key"])
	if err != nil || len(key) != ed25519.PublicKeySize {
		return authed{}, refuse("malformed")
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(fields["sig"])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return authed{}, refuse("malformed")
	}
	ts, err := strconv.ParseInt(fields["ts"], 10, 64)
	if err != nil {
		return authed{}, refuse("malformed")
	}
	if !ed25519.Verify(ed25519.PublicKey(key), relay.Canonical(r.Method, r.URL.RequestURI(), ts, body), sig) {
		return authed{}, refuse("signature")
	}
	if d := now.Unix() - ts; d > int64(skewMax/time.Second) || -d > int64(skewMax/time.Second) {
		return authed{}, refuse("skew")
	}
	return authed{key: fields["key"], ts: ts}, true
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
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
		return "", false
	}
	if revoked {
		writeJSON(w, http.StatusGone, map[string]string{"error": "revoked"})
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

func (f *Fake) completePairing(w http.ResponseWriter, who authed, id string, body []byte) {
	var req struct {
		PhonePub  string            `json:"phonePub"`
		PushToken string            `json:"pushToken"`
		Envelope  envelope.Envelope `json:"envelope"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.Envelope.Pair != id || req.Envelope.Dir != envelope.DirP2H {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.pairings[id]
	switch {
	case !ok:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
	case p.completed:
		writeJSON(w, http.StatusConflict, map[string]string{"error": "pairing_used"})
	case f.Now().After(p.expiresAt):
		writeJSON(w, http.StatusGone, map[string]string{"error": "pairing_expired"})
	default:
		p.completed, p.phone, p.phonePub, p.hello = true, who.key, req.PhonePub, req.Envelope
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

func (f *Fake) waitPairing(w http.ResponseWriter, r *http.Request, who authed, id string) {
	f.mu.Lock()
	f.lastIDs = append(f.lastIDs, r.Header.Get("Last-Event-ID"))
	p, ok := f.pairings[id]
	if ok && p.host != who.key {
		ok = false
	}
	expired := ok && f.Now().After(p.expiresAt.Add(pairingGrace))
	f.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	if expired {
		writeJSON(w, http.StatusGone, map[string]string{"error": "pairing_expired"})
		return
	}
	write := sse(w)
	for {
		f.mu.Lock()
		done := p.completed
		gone := f.Now().After(p.expiresAt.Add(pairingGrace))
		data := mustJSON(map[string]any{"pairId": id, "phonePub": p.phonePub, "envelope": p.hello})
		retry := f.RetryMS
		f.mu.Unlock()
		if done {
			write("id: 1\nevent: completed\ndata: " + string(data) + "\n\n")
			write(fmt.Sprintf("id: 1\nretry: %d\n: reconnect\n\n", retry))
			return
		}
		if gone {
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
	var envs []envelope.Envelope
	if strings.HasPrefix(strings.TrimSpace(string(body)), `{"envelopes"`) {
		var batch struct {
			Envelopes []envelope.Envelope `json:"envelopes"`
		}
		if err := json.Unmarshal(body, &batch); err != nil || len(batch.Envelopes) == 0 || len(batch.Envelopes) > batchMax {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
			return
		}
		envs = batch.Envelopes
	} else {
		var env envelope.Envelope
		if err := json.Unmarshal(body, &env); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
			return
		}
		envs = []envelope.Envelope{env}
	}
	for _, env := range envs {
		if env.Validate(pairID, dir) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
			return
		}
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
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "mailbox_full"})
		return
	}
	f.mu.Lock()
	numeric := f.NumericCursors
	accepted := make([]map[string]any, 0, len(envs))
	duplicates := []string{}
	for _, env := range envs {
		cursor, dup := f.appendRow(env)
		if dup {
			duplicates = append(duplicates, env.ID)
			continue
		}
		var c any = strconv.FormatInt(cursor, 10)
		if numeric {
			c = cursor
		}
		accepted = append(accepted, map[string]any{"id": env.ID, "cursor": c, "ttlSec": env.TTLSec})
	}
	f.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"accepted": accepted, "duplicates": duplicates})
}

func (f *Fake) ack(w http.ResponseWriter, who authed, pairID string, body []byte) {
	role, ok := f.member(w, who, pairID)
	if !ok {
		return
	}
	var req struct {
		Cursor relay.Cursor `json:"cursor"`
	}
	if json.Unmarshal(body, &req) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
		return
	}
	cursor, err := strconv.ParseInt(string(req.Cursor), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
		return
	}
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
	last, _ := strconv.ParseInt(r.Header.Get("Last-Event-ID"), 10, 64)
	inbound := outbound(role).Opposite()
	f.mu.Lock()
	f.lastIDs = append(f.lastIDs, r.Header.Get("Last-Event-ID"))
	p := f.pairs[pairID]
	if role == RoleHost {
		p.hostOpen++
	} else {
		p.phoneOpen++
	}
	silent := f.Silent
	keepaliveMS := f.KeepaliveMS
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		if role == RoleHost {
			p.hostOpen--
		} else {
			p.phoneOpen--
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
		peerOpen := p.phoneOpen
		peer := RolePhone
		if role == RolePhone {
			peerOpen, peer = p.hostOpen, RoleHost
		}
		var next *row
		for i := range f.rows {
			if f.rows[i].pair == pairID && f.rows[i].dir == inbound && f.rows[i].cursor > last {
				next = &f.rows[i]
				break
			}
		}
		f.mu.Unlock()
		if revoked {
			write(fmt.Sprintf("id: %d\nevent: revoked\ndata: {}\n\n", last))
			return
		}
		state := "idle"
		if peerOpen > 0 {
			state = "connected"
		}
		if state != peerState {
			peerState = state
			data := mustJSON(map[string]any{"peer": peer, "state": state, "at": f.Now().Unix()})
			if !write("event: presence\ndata: " + string(data) + "\n\n") {
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
