package relay_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"claircode.app/clair-agent/internal/envelope"
	"claircode.app/clair-agent/internal/identity"
	"claircode.app/clair-agent/internal/relay"
	"claircode.app/clair-agent/internal/relay/relaytest"
)

// specPath is the relay's OpenAPI 3.1 document, copied unchanged from
// clair-server commit a8393a7 (`openapi.json` at its root; the relay serves it
// at /openapi.json). A refresh replaces the file and this commit together. A
// check that then fails is drift between the relay and this client or the
// fake, never a reason to edit the copy.
const specPath = "testdata/openapi.json"

// TestContract drives the client and raw signed requests through the fake
// relay, records every exchange, and checks each one against the relay's
// published contract: the route and method exist, the status is declared,
// the error code is one the spec lists for that status, JSON bodies and SSE
// events match their schemas, and a 2xx request's body matches the request
// schema. Every pairing and pair operation must be exercised: answered 2xx,
// or for the WebSocket the agent never opens, refused as a plain GET.
func TestContract(t *testing.T) {
	t.Parallel()

	doc := loadSpec(t)
	fake := relaytest.New()
	t.Cleanup(fake.Close)
	rec := &recorder{next: fake.Server.Config.Handler}
	srv := httptest.NewServer(rec)
	var s sleeps
	opts := relay.Options{BaseURL: srv.URL, Sleep: s.sleep}
	hostKeys, phoneKeys := newIdentity(t), newIdentity(t)
	host := newClient(t, fake, hostKeys, opts)
	phone := newClient(t, fake, phoneKeys, opts)
	ctx := t.Context()
	raw := rawCaller{t: t, base: srv.URL}

	// Pairing: mint, complete, wait; the refusals the client can provoke.
	pairing, err := host.MintPairing(ctx)
	if err != nil {
		t.Fatalf("MintPairing: %v", err)
	}
	hello := mkEnv(t, pairing.ID, envelope.DirP2H, 1, 64)
	pair, err := phone.CompletePairing(ctx, pairing.ID, phoneKeys.AgreementPublic(), "fcm-token", hello)
	if err != nil {
		t.Fatalf("CompletePairing: %v", err)
	}
	if _, err = host.WaitPairing(ctx, pairing.ID); err != nil {
		t.Fatalf("WaitPairing: %v", err)
	}
	if _, err = phone.CompletePairing(ctx, pairing.ID, phoneKeys.AgreementPublic(), "fcm-token", hello); !errors.Is(err, relay.ErrPairingUsed) {
		t.Errorf("second CompletePairing: err = %v, want ErrPairingUsed", err)
	}
	unknown := "BBBBBBBBBBBBBBBBBBBBBB"
	if _, err = phone.CompletePairing(ctx, unknown, phoneKeys.AgreementPublic(), "", mkEnv(t, unknown, envelope.DirP2H, 2, 8)); !errors.Is(err, relay.ErrNotFound) {
		t.Errorf("CompletePairing of an unknown pairing: err = %v, want ErrNotFound", err)
	}

	// The tunnel: single and batch uploads, a duplicate, the refusals.
	if _, err = host.Upload(ctx, pair, []envelope.Envelope{mkEnv(t, pair, envelope.DirH2P, 3, 8)}); err != nil {
		t.Fatalf("Upload one: %v", err)
	}
	batch := []envelope.Envelope{mkEnv(t, pair, envelope.DirH2P, 4, 8), mkEnv(t, pair, envelope.DirH2P, 5, 8)}
	if _, err = host.Upload(ctx, pair, batch); err != nil {
		t.Fatalf("Upload batch: %v", err)
	}
	receipt, err := host.Upload(ctx, pair, batch[:1])
	if err != nil || len(receipt.Duplicates) != 1 {
		t.Errorf("Upload a duplicate: receipt %+v, err %v, want one duplicate", receipt, err)
	}
	if _, err = host.Upload(ctx, pair, []envelope.Envelope{mkEnv(t, pair, envelope.DirP2H, 6, 8)}); !errors.Is(err, relay.ErrBadRequest) {
		t.Errorf("Upload in the wrong direction: err = %v, want ErrBadRequest", err)
	}
	other := "CCCCCCCCCCCCCCCCCCCCCC"
	if _, err = host.Upload(ctx, other, []envelope.Envelope{mkEnv(t, other, envelope.DirH2P, 7, 8)}); !errors.Is(err, relay.ErrNotFound) {
		t.Errorf("Upload to an unknown pair: err = %v, want ErrNotFound", err)
	}
	fake.Set(func(f *relaytest.Fake) { f.MailboxFull = true })
	if _, err = host.Upload(ctx, pair, []envelope.Envelope{mkEnv(t, pair, envelope.DirH2P, 8, 8)}); !errors.Is(err, relay.ErrMailboxFull) {
		t.Errorf("Upload to a full mailbox: err = %v, want ErrMailboxFull", err)
	}
	fake.Set(func(f *relaytest.Fake) { f.MailboxFull = false })
	// The host lets go of a stream it closed (DELETE /events).
	if err = host.ReleaseStream(ctx, pair); err != nil {
		t.Errorf("ReleaseStream: %v", err)
	}
	if err = host.ReleaseStream(ctx, other); !errors.Is(err, relay.ErrPairNotFound) {
		t.Errorf("ReleaseStream of an unknown pair: err = %v, want ErrPairNotFound", err)
	}

	// Refusals only a raw request can provoke: the client never sends them.
	envelopes := "/v1/pairs/" + pair + "/envelopes"
	lone := func(e envelope.Envelope) []byte { return mustJSON(t, e) }
	bulky := func(i, ctLen int) envelope.Envelope {
		e := mkEnv(t, pair, envelope.DirH2P, i, 8)
		e.CT = strings.Repeat("A", ctLen)
		return e
	}
	misnamed := mkEnv(t, pair, envelope.DirH2P, 9, 8)
	misnamed.Pair = other
	many := make([]envelope.Envelope, relay.BatchMaxEnvelopes+1)
	for i := range many {
		many[i] = mkEnv(t, pair, envelope.DirH2P, 10+i, 8)
	}
	for _, c := range []struct {
		name, method, path, contentType string
		body                            []byte
		lastID                          string
		status                          int
		code                            string
	}{
		{"a body that is not JSON", http.MethodPost, envelopes, "text/plain", []byte("hi"), "", 415, "unsupported_media_type"},
		{"an empty batch", http.MethodPost, envelopes, "", []byte(`{"envelopes":[]}`), "", 400, "invalid_batch"},
		{"a batch over the count", http.MethodPost, envelopes, "", mustJSON(t, map[string]any{"envelopes": many}), "", 400, "too_many_envelopes"},
		{"an envelope missing fields", http.MethodPost, envelopes, "", []byte(`{"v":1}`), "", 400, "invalid_envelope"},
		{"an envelope for another pair", http.MethodPost, envelopes, "", lone(misnamed), "", 400, "pair_mismatch"},
		{"an envelope over 4 MiB", http.MethodPost, envelopes, "", lone(bulky(11, envelope.MaxEnvelopeJSON+1024)), "", 413, "envelope_too_large"},
		{"a batch over 4 MiB", http.MethodPost, envelopes, "", mustJSON(t, map[string]any{"envelopes": []envelope.Envelope{bulky(12, 2<<20+1024), bulky(13, 2<<20+1024)}}), "", 413, "batch_too_large"},
		{"a body over the parser limit", http.MethodPost, envelopes, "", lone(bulky(14, 5<<20)), "", 413, "payload_too_large"},
		{"an ack with a string cursor", http.MethodPost, "/v1/pairs/" + pair + "/ack", "", []byte(`{"cursor":"1"}`), "", 400, "invalid_body"},
		{"a Last-Event-ID that is not a cursor", http.MethodGet, "/v1/pairs/" + pair + "/events", "", nil, "x", 400, "invalid_last_event_id"},
		// The agent speaks SSE only (ADR 2026-09.khcq); the WebSocket route
		// answers a plain GET with what it should have asked for.
		{"a plain GET of the WebSocket", http.MethodGet, "/v1/pairs/" + pair + "/stream", "", nil, "", 426, "upgrade_required"},
	} {
		status, code := raw.do(hostKeys, c.method, c.path, c.contentType, c.body, c.lastID)
		if status != c.status || code != c.code {
			t.Errorf("%s: %d %s, want %d %s", c.name, status, code, c.status, c.code)
		}
	}

	// Signed-request refusals (relay ADR 2026-09.9vsq, as with
	// AUTH_NONCE=required): a nonce is good once, the host is signed, and a
	// header without a nonce is malformed. Then a host completing its own pairing.
	ack := "/v1/pairs/" + pair + "/ack"
	ackBody := []byte(`{"cursor":0}`)
	once := raw.sign(hostKeys, http.MethodPost, mustURL(t, srv.URL).Host, ack, ackBody)
	if status, code := raw.withHeader(http.MethodPost, ack, ackBody, once); status != http.StatusNoContent {
		t.Errorf("a freshly signed ack: %d %s, want 204", status, code)
	}
	ts := time.Now().Unix()
	sum := sha256.Sum256(ackBody)
	v1 := fmt.Sprintf("POST\n%s\n%d\n%x", ack, ts, sum)
	for _, c := range []struct {
		name, header string
		reason       string
	}{
		{"the same header again", once, "replay"},
		{"a request signed for another host", raw.sign(hostKeys, http.MethodPost, "relay.claircode.app", ack, ackBody), "signature"},
		{"a v1 header without a nonce", "Clair-Ed25519 key=" + relay.NewSigner(hostKeys.Auth()).Key() + ", ts=" + strconv.FormatInt(ts, 10) +
			", sig=" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(hostKeys.Auth(), []byte(v1))), "malformed"},
	} {
		status, code := raw.withHeader(http.MethodPost, ack, ackBody, c.header)
		if status != http.StatusUnauthorized || code != "unauthorized" {
			t.Errorf("%s: %d %s, want 401 unauthorized", c.name, status, code)
		}
		if got := lastReason(t, rec); got != c.reason {
			t.Errorf("%s: reason %q, want %q", c.name, got, c.reason)
		}
	}
	own, err := host.MintPairing(ctx)
	if err != nil {
		t.Fatalf("MintPairing: %v", err)
	}
	selfHello := mustJSON(t, map[string]any{"phonePub": base64.RawURLEncoding.EncodeToString(hostKeys.AgreementPublic()), "envelope": mkEnv(t, own.ID, envelope.DirP2H, 30, 8)})
	if status, code := raw.do(hostKeys, http.MethodPost, "/v1/pairings/"+own.ID+"/complete", "", selfHello, ""); status != 400 || code != "self_pairing" {
		t.Errorf("a host completing its own pairing: %d %s, want 400 self_pairing", status, code)
	}

	// The phone drains its stream, acking what it applied; the host revokes
	// after the second, and the relay keeps the third — what the host sent —
	// for the phone to drain and ack before `revoked` (RELAY.md r9 §6.6).
	var seen int
	err = phone.Stream(ctx, pair, "", func(ctx context.Context, ev relay.Event) error {
		if ev.Kind != relay.EventEnvelope {
			return nil
		}
		if ackErr := phone.Ack(ctx, pair, ev.Cursor); ackErr != nil {
			return ackErr
		}
		seen++
		if seen == 2 {
			return host.Revoke(ctx, pair)
		}
		return nil
	})
	if !errors.Is(err, relay.ErrRevoked) || seen != 3 {
		t.Errorf("Stream: err = %v after %d envelopes, want ErrRevoked after 3", err, seen)
	}
	if _, err = host.Upload(ctx, pair, []envelope.Envelope{mkEnv(t, pair, envelope.DirH2P, 200, 8)}); !errors.Is(err, relay.ErrRevoked) {
		t.Errorf("Upload to a revoked pair: err = %v, want ErrRevoked", err)
	}
	// With nothing left for it, the phone is refused like everyone else.
	if err = phone.Stream(ctx, pair, "", func(context.Context, relay.Event) error { return nil }); !errors.Is(err, relay.ErrRevoked) {
		t.Errorf("Stream of a drained revoked pair: err = %v, want ErrRevoked", err)
	}
	if err = phone.Ack(ctx, pair, "1"); !errors.Is(err, relay.ErrRevoked) {
		t.Errorf("Ack on a drained revoked pair: err = %v, want ErrRevoked", err)
	}
	if err = phone.ReleaseStream(ctx, pair); !errors.Is(err, relay.ErrRevoked) {
		t.Errorf("ReleaseStream on a revoked pair: err = %v, want ErrRevoked", err)
	}

	// A pairing that expires while the host waits: `expired`, then 410; the
	// relay's clock moving past the client's is corrected from a 401 on the way.
	stale, err := host.MintPairing(ctx)
	if err != nil {
		t.Fatalf("MintPairing: %v", err)
	}
	completion := func(e any) []byte {
		return mustJSON(t, map[string]any{"phonePub": base64.RawURLEncoding.EncodeToString(phoneKeys.AgreementPublic()), "envelope": e})
	}
	complete := "/v1/pairings/" + stale.ID + "/complete"
	for _, c := range []struct {
		name   string
		body   []byte
		status int
		code   string
	}{
		{"a completion without a key", []byte(`{"envelope":{}}`), 400, "invalid_body"},
		{"a hello in the host's direction", completion(mkEnv(t, stale.ID, envelope.DirH2P, 201, 8)), 400, "dir_mismatch"},
	} {
		status, code := raw.do(phoneKeys, http.MethodPost, complete, "", c.body, "")
		if status != c.status || code != c.code {
			t.Errorf("%s: %d %s, want %d %s", c.name, status, code, c.status, c.code)
		}
	}
	waited := make(chan error, 1)
	opened := len(fake.LastEventIDs())
	go func() {
		_, waitErr := host.WaitPairing(ctx, stale.ID)
		waited <- waitErr
	}()
	for deadline := time.Now().Add(5 * time.Second); len(fake.LastEventIDs()) == opened; {
		if time.Now().After(deadline) {
			t.Fatal("the host's wait never opened")
		}
		time.Sleep(time.Millisecond)
	}
	fake.Set(func(f *relaytest.Fake) { f.Now = func() time.Time { return time.Now().Add(11 * time.Minute) } })
	if err = <-waited; !errors.Is(err, relay.ErrPairingExpired) {
		t.Errorf("WaitPairing across expiry: err = %v, want ErrPairingExpired", err)
	}
	if _, err = phone.CompletePairing(ctx, stale.ID, phoneKeys.AgreementPublic(), "fcm-token", mkEnv(t, stale.ID, envelope.DirP2H, 202, 8)); !errors.Is(err, relay.ErrPairingExpired) {
		t.Errorf("CompletePairing after expiry: err = %v, want ErrPairingExpired", err)
	}

	srv.Close() // waits for every handler, so the log is complete
	// Only an upgrade answers /stream 2xx (101), and the agent never asks for
	// one: its refusal is what the client can meet, so it is what is covered.
	refusedOnly := map[string]int{"openStream": http.StatusUpgradeRequired}
	exercised := make(map[string]bool)
	for _, ex := range rec.exchanges() {
		op, errs := doc.check(ex)
		for _, e := range errs {
			t.Errorf("%s %s → %d: %s", ex.method, ex.path, ex.status, e)
		}
		if op != nil && (ex.status/100 == 2 || refusedOnly[op.OperationID] == ex.status) {
			exercised[op.OperationID] = true
		}
	}
	for _, id := range doc.operations("pairings", "pairs") {
		if !exercised[id] {
			t.Errorf("operation %s was never answered 2xx: the contract test does not cover it", id)
		}
	}
}

// rawCaller sends signed requests the client never would.
type rawCaller struct {
	t    *testing.T
	base string
}

// do sends one signed request and returns the status and the body's `error`.
func (r rawCaller) do(keys *identity.Keys, method, path, contentType string, body []byte, lastID string) (status int, code string) {
	r.t.Helper()
	req := r.build(method, path, contentType, body, lastID)
	req.Header.Set("Authorization", r.sign(keys, method, req.Host, path, body))
	return r.send(req)
}

// withHeader sends one JSON request carrying exactly authorization.
func (r rawCaller) withHeader(method, path string, body []byte, authorization string) (status int, code string) {
	r.t.Helper()
	req := r.build(method, path, "", body, "")
	req.Header.Set("Authorization", authorization)
	return r.send(req)
}

// sign is the v2 header for one request, with a fresh nonce.
func (r rawCaller) sign(keys *identity.Keys, method, host, path string, body []byte) string {
	r.t.Helper()
	nonce, err := relay.NewNonce(rand.Reader)
	if err != nil {
		r.t.Fatalf("nonce: %v", err)
	}
	return relay.NewSigner(keys.Auth()).Authorization(method, host, path, time.Now().Unix(), nonce, body)
}

func (r rawCaller) build(method, path, contentType string, body []byte, lastID string) *http.Request {
	r.t.Helper()
	req, err := http.NewRequestWithContext(r.t.Context(), method, r.base+path, bytes.NewReader(body))
	if err != nil {
		r.t.Fatalf("build %s %s: %v", method, path, err)
	}
	if contentType == "" && body != nil {
		contentType = "application/json"
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if lastID != "" {
		req.Header.Set("Last-Event-ID", lastID)
	}
	return req
}

func (r rawCaller) send(req *http.Request) (status int, code string) {
	r.t.Helper()
	method, path := req.Method, req.URL.Path
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var answer struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(mustRead(r.t, resp), &answer)
	return resp.StatusCode, answer.Error
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("encode %T: %v", v, err)
	}
	return data
}

// lastReason is the `reason` of the last exchange rec saw.
func lastReason(t *testing.T, rec *recorder) string {
	t.Helper()
	log := rec.exchanges()
	var body struct {
		Reason string `json:"reason"`
	}
	if len(log) > 0 {
		_ = json.Unmarshal(log[len(log)-1].body, &body)
	}
	return body.Reason
}

// exchange is one request the relay answered, as sent and as answered.
type exchange struct {
	method, path string
	lastID       []string
	reqBody      []byte
	status       int
	header       http.Header
	body         []byte
}

// recorder sits in front of the fake's handler and keeps every exchange.
type recorder struct {
	next http.Handler
	mu   sync.Mutex
	log  []exchange
}

func (rec *recorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))
	tw := &teeWriter{ResponseWriter: w, status: http.StatusOK}
	rec.next.ServeHTTP(tw, r)
	ex := exchange{
		method: r.Method, path: r.URL.EscapedPath(), lastID: r.Header.Values("Last-Event-ID"),
		reqBody: body, status: tw.status, header: w.Header().Clone(), body: tw.buf.Bytes(),
	}
	rec.mu.Lock()
	rec.log = append(rec.log, ex)
	rec.mu.Unlock()
}

func (rec *recorder) exchanges() []exchange {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return slices.Clone(rec.log)
}

// teeWriter copies the response body aside; Unwrap lets the fake flush SSE.
type teeWriter struct {
	http.ResponseWriter

	status int
	wrote  bool
	buf    bytes.Buffer
}

func (w *teeWriter) WriteHeader(code int) {
	if !w.wrote {
		w.status, w.wrote = code, true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *teeWriter) Write(p []byte) (int, error) {
	w.wrote = true
	w.buf.Write(p)
	return w.ResponseWriter.Write(p)
}

func (w *teeWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// The parts of an OpenAPI document this checker reads.
type (
	schema    = map[string]any
	mediaType struct {
		Schema schema `json:"schema"`
	}
	response struct {
		Description string               `json:"description"`
		Content     map[string]mediaType `json:"content"`
		Headers     map[string]mediaType `json:"headers"`
	}
	parameter struct {
		Name   string `json:"name"`
		In     string `json:"in"`
		Schema schema `json:"schema"`
	}
	operation struct {
		OperationID string      `json:"operationId"`
		Tags        []string    `json:"tags"`
		Description string      `json:"description"`
		Parameters  []parameter `json:"parameters"`
		RequestBody *struct {
			Content map[string]mediaType `json:"content"`
		} `json:"requestBody"`
		Responses map[string]response `json:"responses"`
	}
	openAPI struct {
		Paths      map[string]map[string]*operation `json:"paths"`
		Components struct {
			Schemas map[string]schema `json:"schemas"`
		} `json:"components"`
	}
)

func loadSpec(t *testing.T) *openAPI {
	t.Helper()
	data, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var doc openAPI
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("decode spec: %v", err)
	}
	return &doc
}

// operations lists the operation ids carrying any of tags, sorted.
func (doc *openAPI) operations(tags ...string) []string {
	var ids []string
	for _, methods := range doc.Paths {
		for _, op := range methods {
			if slices.ContainsFunc(op.Tags, func(tag string) bool { return slices.Contains(tags, tag) }) {
				ids = append(ids, op.OperationID)
			}
		}
	}
	slices.Sort(ids)
	return ids
}

// find matches a request to the operation whose path template fits it.
func (doc *openAPI) find(method, path string) *operation {
	got := strings.Split(path, "/")
	for _, tmpl := range slices.Sorted(maps.Keys(doc.Paths)) {
		want := strings.Split(tmpl, "/")
		if len(want) != len(got) {
			continue
		}
		fits := true
		for i := range want {
			if want[i] != got[i] && (!strings.HasPrefix(want[i], "{") || got[i] == "") {
				fits = false
				break
			}
		}
		if op := doc.Paths[tmpl][strings.ToLower(method)]; fits && op != nil {
			return op
		}
	}
	return nil
}

var (
	// A response description ends "— `error`: `a`, `b`" with the codes it may carry.
	errorCodesPattern = regexp.MustCompile("`error`: (.*)$")
	backticked        = regexp.MustCompile("`([a-z_]+)`")
	// An operation description names its SSE events as "`name` (`Schema`".
	eventPattern = regexp.MustCompile("`([a-z]+)` \\(`([A-Z][A-Za-z]+)`")
	// An event schema's description may pin its id: "`id: 0`".
	eventIDPattern = regexp.MustCompile("`id: (\\d+)`")
)

// check reports every way ex departs from the document.
func (doc *openAPI) check(ex exchange) (*operation, []string) {
	op := doc.find(ex.method, ex.path)
	if op == nil {
		return nil, []string{"no such operation in the spec"}
	}
	resp, ok := op.Responses[strconv.Itoa(ex.status)]
	if !ok {
		return op, []string{fmt.Sprintf("status %d is not declared for %s", ex.status, op.OperationID)}
	}
	var errs []string
	fail := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }
	if ex.status/100 == 2 {
		if op.RequestBody != nil {
			if err := doc.validateJSON(op.RequestBody.Content["application/json"].Schema, ex.reqBody, "request"); err != nil {
				fail("%v", err)
			}
		}
		for _, p := range op.Parameters {
			if p.In == "header" && p.Name == "Last-Event-ID" && len(ex.lastID) > 0 {
				if err := doc.validate(p.Schema, ex.lastID[0], "Last-Event-ID"); err != nil {
					fail("%v", err)
				}
			}
		}
	}
	for name, h := range resp.Headers {
		value := ex.header.Get(name)
		if value == "" {
			fail("header %s is missing", name)
			continue
		}
		if err := doc.validate(h.Schema, json.Number(value), name); err != nil {
			fail("%v", err)
		}
	}
	media, _, _ := mime.ParseMediaType(ex.header.Get("Content-Type"))
	if len(resp.Content) == 0 {
		if len(ex.body) > 0 {
			fail("a %d carries a body the spec does not declare", ex.status)
		}
		return op, errs
	}
	content, ok := resp.Content[media]
	if !ok {
		return op, append(errs, fmt.Sprintf("content type %q is not declared", media))
	}
	switch media {
	case "application/json":
		if err := doc.validateJSON(content.Schema, ex.body, "response"); err != nil {
			fail("%v", err)
		}
		var body struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(ex.body, &body)
		if m := errorCodesPattern.FindStringSubmatch(resp.Description); m != nil && ex.status >= 400 {
			var codes []string
			for _, c := range backticked.FindAllStringSubmatch(m[1], -1) {
				codes = append(codes, c[1])
			}
			if !slices.Contains(codes, body.Error) {
				fail("error %q is not one of %v", body.Error, codes)
			}
		}
	case "text/event-stream":
		events := make(map[string]string)
		for _, m := range eventPattern.FindAllStringSubmatch(op.Description, -1) {
			events[m[1]] = m[2]
		}
		for _, ev := range parseSSE(ex.body) {
			name, ok := events[ev.name]
			if !ok {
				fail("event %q is not one %s names", ev.name, op.OperationID)
				continue
			}
			if ev.id == "" {
				fail("event %q carries no id", ev.name)
			}
			ref := doc.Components.Schemas[name]
			if desc, ok := ref["description"].(string); ok && eventIDPattern.MatchString(desc) {
				if want := eventIDPattern.FindStringSubmatch(desc)[1]; ev.id != want {
					fail("event %q has id %q, want %s", ev.name, ev.id, want)
				}
			}
			if err := doc.validateJSON(schema{"$ref": "#/components/schemas/" + name}, []byte(ev.data), "event "+ev.name); err != nil {
				fail("%v", err)
			}
		}
	}
	return op, errs
}

// sseEvent is one dispatched event of a recorded stream.
type sseEvent struct{ name, id, data string }

// parseSSE splits a recorded stream into its events; comments and blocks
// without data (the closing `retry:`) are not events.
func parseSSE(body []byte) []sseEvent {
	var out []sseEvent
	for block := range strings.SplitSeq(string(body), "\n\n") {
		ev := sseEvent{name: "message"}
		var data []string
		for line := range strings.SplitSeq(block, "\n") {
			field, value, _ := strings.Cut(line, ":")
			value = strings.TrimPrefix(value, " ")
			switch field {
			case "event":
				ev.name = value
			case "id":
				ev.id = value
			case "data":
				data = append(data, value)
			}
		}
		if data != nil {
			ev.data = strings.Join(data, "\n")
			out = append(out, ev)
		}
	}
	return out
}

func (doc *openAPI) validateJSON(s schema, data []byte, at string) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return fmt.Errorf("%s: not JSON: %w", at, err)
	}
	return doc.validate(s, v, at)
}

// supported reports the JSON Schema keywords validate understands; a schema
// using another fails loudly rather than passing unchecked.
func supported(keyword string) bool {
	switch keyword {
	case "$ref", "oneOf", "const", "enum", "type", "description",
		"pattern", "minLength", "maxLength", "format",
		"minimum", "maximum", "exclusiveMinimum",
		"required", "properties", "additionalProperties",
		"items", "minItems", "maxItems":
		return true
	}
	return false
}

// validate checks v (decoded with UseNumber) against the subset of JSON
// Schema the relay's document uses.
func (doc *openAPI) validate(s schema, v any, at string) error {
	for k := range s {
		if !supported(k) {
			return fmt.Errorf("%s: schema keyword %q is not supported by this checker", at, k)
		}
	}
	if ref, ok := s["$ref"].(string); ok {
		name := strings.TrimPrefix(ref, "#/components/schemas/")
		target, ok := doc.Components.Schemas[name]
		if !ok {
			return fmt.Errorf("%s: unresolved $ref %s", at, ref)
		}
		return doc.validate(target, v, at)
	}
	if alts, ok := s["oneOf"].([]any); ok {
		matched := 0
		for _, alt := range alts {
			if alt, ok := alt.(schema); ok && doc.validate(alt, v, at) == nil {
				matched++
			}
		}
		if matched != 1 {
			return fmt.Errorf("%s: matches %d of oneOf's %d schemas, want 1", at, matched, len(alts))
		}
	}
	if c, ok := s["const"]; ok && !reflect.DeepEqual(c, v) {
		return fmt.Errorf("%s: %v, want const %v", at, v, c)
	}
	if enum, ok := s["enum"].([]any); ok && !slices.ContainsFunc(enum, func(e any) bool { return reflect.DeepEqual(e, v) }) {
		return fmt.Errorf("%s: %v is not one of %v", at, v, enum)
	}
	if typ, ok := s["type"]; ok {
		var types []any
		switch typ := typ.(type) {
		case string:
			types = []any{typ}
		case []any:
			types = typ
		}
		if !slices.ContainsFunc(types, func(name any) bool { n, ok := name.(string); return ok && hasType(v, n) }) {
			return fmt.Errorf("%s: %v (%T) is not of type %v", at, v, v, typ)
		}
	}
	switch v := v.(type) {
	case string:
		return validateString(s, v, at)
	case json.Number:
		return validateNumber(s, v, at)
	case map[string]any:
		return doc.validateObject(s, v, at)
	case []any:
		if n, ok := s["minItems"].(json.Number); ok && int64(len(v)) < mustInt(n) {
			return fmt.Errorf("%s: %d items, want at least %s", at, len(v), n)
		}
		if n, ok := s["maxItems"].(json.Number); ok && int64(len(v)) > mustInt(n) {
			return fmt.Errorf("%s: %d items, want at most %s", at, len(v), n)
		}
		if items, ok := s["items"].(schema); ok {
			for i, item := range v {
				if err := doc.validate(items, item, fmt.Sprintf("%s[%d]", at, i)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func hasType(v any, name string) bool {
	switch v := v.(type) {
	case nil:
		return name == "null"
	case bool:
		return name == "boolean"
	case string:
		return name == "string"
	case json.Number:
		_, err := v.Int64()
		return name == "number" || (name == "integer" && err == nil)
	case map[string]any:
		return name == "object"
	case []any:
		return name == "array"
	}
	return false
}

func validateString(s schema, v, at string) error {
	if p, ok := s["pattern"].(string); ok {
		re, err := regexp.Compile(p)
		if err != nil {
			return fmt.Errorf("%s: pattern %q: %w", at, p, err)
		}
		if !re.MatchString(v) {
			return fmt.Errorf("%s: %.40q does not match %s", at, v, p)
		}
	}
	if n, ok := s["minLength"].(json.Number); ok && int64(utf8.RuneCountInString(v)) < mustInt(n) {
		return fmt.Errorf("%s: shorter than %s", at, n)
	}
	if n, ok := s["maxLength"].(json.Number); ok && int64(utf8.RuneCountInString(v)) > mustInt(n) {
		return fmt.Errorf("%s: longer than %s", at, n)
	}
	if s["format"] == "date-time" {
		if _, err := time.Parse(time.RFC3339Nano, v); err != nil {
			return fmt.Errorf("%s: %q is not a date-time", at, v)
		}
	}
	return nil
}

func validateNumber(s schema, v json.Number, at string) error {
	f, err := v.Float64()
	if err != nil {
		return fmt.Errorf("%s: %s: %w", at, v, err)
	}
	bound := func(key string) (float64, bool) {
		n, ok := s[key].(json.Number)
		if !ok {
			return 0, false
		}
		b, _ := n.Float64()
		return b, true
	}
	if b, ok := bound("minimum"); ok && f < b {
		return fmt.Errorf("%s: %s < minimum %v", at, v, b)
	}
	if b, ok := bound("maximum"); ok && f > b {
		return fmt.Errorf("%s: %s > maximum %v", at, v, b)
	}
	if b, ok := bound("exclusiveMinimum"); ok && f <= b {
		return fmt.Errorf("%s: %s ≤ exclusiveMinimum %v", at, v, b)
	}
	return nil
}

func (doc *openAPI) validateObject(s schema, v map[string]any, at string) error {
	if required, ok := s["required"].([]any); ok {
		for _, name := range required {
			if n, ok := name.(string); !ok || !hasKey(v, n) {
				return fmt.Errorf("%s: missing required %v", at, name)
			}
		}
	}
	props := make(schema)
	if p, ok := s["properties"].(schema); ok {
		props = p
	}
	switch extra := s["additionalProperties"].(type) {
	case nil:
	case bool:
		if !extra {
			for name := range v {
				if !hasKey(props, name) {
					return fmt.Errorf("%s: unexpected property %q", at, name)
				}
			}
		}
	default:
		return fmt.Errorf("%s: additionalProperties as a schema is not supported by this checker", at)
	}
	for _, name := range slices.Sorted(maps.Keys(v)) {
		if sub, ok := props[name].(schema); ok {
			if err := doc.validate(sub, v[name], at+"."+name); err != nil {
				return err
			}
		}
	}
	return nil
}

func hasKey(m map[string]any, key string) bool {
	_, ok := m[key]
	return ok
}

// mustInt reads a schema's integer keyword; the document is trusted to be well formed.
func mustInt(n json.Number) int64 {
	i, _ := n.Int64()
	return i
}
