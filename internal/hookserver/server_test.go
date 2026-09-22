package hookserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"claircode.app/clair-agent/internal/ctl"
	"claircode.app/clair-agent/internal/envelope"
	"claircode.app/clair-agent/internal/record"
)

const (
	token = "hook-token-0123456789abcdefghijklmnopqrstu"
	admin = "admin-token-123456789abcdefghijklmnopqrstu"
)

type enqueued struct {
	rec  record.Record
	hook record.Hook
}

type held struct {
	rec     record.Record
	hook    record.Hook
	timeout time.Duration
}

// fakeSink records what the server hands it and answers holds as told.
type fakeSink struct {
	mu       sync.Mutex
	enqueued []enqueued
	holds    []held
	answer   func(ctx context.Context) (record.Record, bool, error)
}

func (f *fakeSink) Enqueue(rec record.Record, hook record.Hook) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enqueued = append(f.enqueued, enqueued{rec: rec, hook: hook})
	return nil
}

func (f *fakeSink) Hold(ctx context.Context, rec record.Record, hook record.Hook, timeout time.Duration) (record.Record, bool, error) {
	f.mu.Lock()
	f.holds = append(f.holds, held{rec: rec, hook: hook, timeout: timeout})
	answer := f.answer
	f.mu.Unlock()
	if answer == nil {
		return record.Record{}, false, nil
	}
	return answer(ctx)
}

type fakeControl struct {
	mu       sync.Mutex
	reloads  int
	released []string
}

func (*fakeControl) Status(context.Context) ctl.Status {
	return ctl.Status{Version: "test", Listen: ListenDefault, Paired: true, Pairs: []ctl.PairStatus{{PairID: "p1"}}}
}

func (f *fakeControl) Reload(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reloads++
	return nil
}

func (f *fakeControl) ReleasePair(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id != "p1" {
		return ctl.ErrNotFound
	}
	f.released = append(f.released, id)
	return nil
}

func newServer(t *testing.T, sink *fakeSink, control Controller) *Server {
	t.Helper()
	s, err := New(Options{Token: token, AdminToken: admin, Sink: sink, Control: control, Entropy: rand.Reader})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// do runs one request through the handler and returns the recorder.
func do(t *testing.T, s *Server, method, path, auth string, body io.Reader, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, body)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

const hookBody = `{"session_id":"s-1","hook_event_name":"PreToolUse","tool_input":{"command":"ls > out"}}`

func TestGuardOrder(t *testing.T) {
	t.Parallel()

	sink := &fakeSink{}
	s := newServer(t, sink, &fakeControl{})
	bearer := "Bearer " + token
	tests := []struct {
		name   string
		method string
		path   string
		auth   string
		want   int
	}{
		{name: "root is 404 before auth", method: "GET", path: "/", want: 404},
		{name: "foreign path is 404 even with a bearer", method: "POST", path: "/hook/event", auth: bearer, want: 404},
		{name: "hook path without auth", method: "POST", path: record.PathEvent, want: 401},
		{name: "wrong token", method: "POST", path: record.PathEvent, auth: "Bearer nope", want: 401},
		{name: "bare token is not accepted", method: "POST", path: record.PathEvent, auth: token, want: 401},
		{name: "trailing space is not trimmed", method: "POST", path: record.PathEvent, auth: bearer + " ", want: 401},
		{name: "lowercase scheme", method: "POST", path: record.PathEvent, auth: "bearer " + token, want: 401},
		{name: "admin token is not a hook bearer", method: "POST", path: record.PathEvent, auth: "Bearer " + admin, want: 401},
		{name: "unknown path under the prefix needs auth first", method: "GET", path: "/clair/v1/nope", want: 401},
		{name: "unknown path under the prefix", method: "GET", path: "/clair/v1/nope", auth: bearer, want: 404},
		{name: "prefix without a slash", method: "GET", path: "/clair/v1x", auth: bearer, want: 404},
		{name: "wrong method on a known path", method: "GET", path: record.PathEvent, auth: bearer, want: 405},
		{name: "control with the hook token", method: "GET", path: ctl.PathStatus, auth: bearer, want: 401},
		{name: "control without auth", method: "GET", path: ctl.PathStatus, want: 401},
		{name: "control with the admin token", method: "GET", path: ctl.PathStatus, auth: "Bearer " + admin, want: 200},
		{name: "unknown control path", method: "GET", path: ctl.Prefix + "nope", auth: "Bearer " + admin, want: 404},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := do(t, s, tt.method, tt.path, tt.auth, strings.NewReader(hookBody), nil)
			if rec.Code != tt.want {
				t.Fatalf("%s %s with auth %q = %d, want %d", tt.method, tt.path, tt.auth, rec.Code, tt.want)
			}
			if tt.want == 405 && rec.Header().Get("Allow") == "" {
				t.Error("405 without an Allow header")
			}
		})
	}
	if len(sink.enqueued) != 0 {
		t.Errorf("refused requests reached the sink: %+v", sink.enqueued)
	}
}

func TestEmptyTokenRefusesEverything(t *testing.T) {
	t.Parallel()

	s, err := New(Options{Token: "", AdminToken: "", Sink: &fakeSink{}, Entropy: rand.Reader})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if rec := do(t, s, "POST", record.PathEvent, "Bearer ", strings.NewReader(hookBody), nil); rec.Code != 401 {
		t.Errorf("empty configured token: %d, want 401", rec.Code)
	}
	if rec := do(t, s, "GET", ctl.PathStatus, "Bearer ", nil, nil); rec.Code != 401 {
		t.Errorf("empty admin token: %d, want 401", rec.Code)
	}
}

func TestBodyCap(t *testing.T) {
	t.Parallel()

	sink := &fakeSink{}
	s, err := New(Options{Token: token, Sink: sink, Entropy: rand.Reader, MaxBodyBytes: 64 << 10})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	big := `{"session_id":"s","hook_event_name":"Stop","pad":"` + strings.Repeat("x", 70<<10) + `"}`
	if rec := do(t, s, "POST", record.PathEvent, "Bearer "+token, strings.NewReader(big), nil); rec.Code != 413 {
		t.Errorf("Content-Length over the cap: %d, want 413", rec.Code)
	}
	// An io.Reader of unknown length arrives chunked, so the cap must bite while reading.
	chunked := io.MultiReader(strings.NewReader(big))
	if rec := do(t, s, "POST", record.PathEvent, "Bearer "+token, chunked, nil); rec.Code != 413 {
		t.Errorf("chunked body over the cap: %d, want 413", rec.Code)
	}
	if rec := do(t, s, "POST", record.PathStatusline, "Bearer "+token, strings.NewReader(big), nil); rec.Code != 413 {
		t.Errorf("statusline over the cap: %d, want 413", rec.Code)
	}
	if len(sink.enqueued) != 0 {
		t.Error("an oversize body reached the sink")
	}
}

func TestHookBodyValidation(t *testing.T) {
	t.Parallel()

	sink := &fakeSink{}
	s := newServer(t, sink, nil)
	tests := []struct {
		name string
		path string
		body string
		want int
	}{
		{name: "valid hook", path: record.PathEvent, body: hookBody, want: 204},
		{name: "not json", path: record.PathEvent, body: "not json", want: 400},
		{name: "array", path: record.PathEvent, body: `[{"session_id":"s","hook_event_name":"Stop"}]`, want: 400},
		{name: "missing session_id", path: record.PathEvent, body: `{"hook_event_name":"Stop"}`, want: 400},
		{name: "numeric session_id", path: record.PathEvent, body: `{"session_id":7,"hook_event_name":"Stop"}`, want: 400},
		{name: "empty event name", path: record.PathEvent, body: `{"session_id":"s","hook_event_name":""}`, want: 400},
		{name: "trailing garbage", path: record.PathEvent, body: hookBody + "x", want: 400},
		{name: "empty body", path: record.PathEvent, body: "", want: 400},
		{name: "decide with a plain hook", path: record.PathDecide, body: hookBody, want: 204},
		{name: "decide not json", path: record.PathDecide, body: "{", want: 400},
		{name: "statusline object", path: record.PathStatusline, body: `{"session_id":"s-1","rate_limits":{}}`, want: 204},
		{name: "statusline empty object", path: record.PathStatusline, body: ` {} `, want: 204},
		{name: "statusline null", path: record.PathStatusline, body: `null`, want: 400},
		{name: "statusline array", path: record.PathStatusline, body: `[]`, want: 400},
		{name: "statusline not json", path: record.PathStatusline, body: `{`, want: 400},
		{name: "ping object", path: record.PathPing, body: `{"hostname":"walter","mode":"install"}`, want: 204},
		{name: "ping garbage", path: record.PathPing, body: `garbage`, want: 204},
		{name: "ping empty", path: record.PathPing, body: ``, want: 204},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := do(t, s, "POST", tt.path, "Bearer "+token, strings.NewReader(tt.body), nil)
			if rec.Code != tt.want {
				t.Fatalf("POST %s %q = %d, want %d", tt.path, tt.body, rec.Code, tt.want)
			}
			if rec.Body.Len() != 0 {
				t.Errorf("body = %q, want empty", rec.Body.String())
			}
		})
	}
}

func TestRequestRecordShape(t *testing.T) {
	t.Parallel()

	sink := &fakeSink{}
	s := newServer(t, sink, nil)
	headers := map[string]string{record.HostHeader: "  walter-laptop ", "Content-Type": "application/json", "X-Other": "nope"}
	body := "{ \"session_id\": \"s-1\",\n \"hook_event_name\": \"PreToolUse\" }"
	rec := do(t, s, "POST", record.PathEvent+"?a=1&a=2&b=x", "Bearer "+token, strings.NewReader(body), headers)
	if rec.Code != 204 {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if len(sink.enqueued) != 1 {
		t.Fatalf("enqueued %d records, want 1", len(sink.enqueued))
	}
	got := sink.enqueued[0]
	if got.hook != (record.Hook{Event: "PreToolUse"}) {
		t.Errorf("hook = %+v, want PreToolUse with no mode", got.hook)
	}
	if got.rec.Kind != record.KindRequest || got.rec.Path != record.PathEvent || !envelope.ValidID(got.rec.ReqID) {
		t.Errorf("record = %+v, want a request for %s with a ULID reqId", got.rec, record.PathEvent)
	}
	if !bytes.Equal(got.rec.Body, []byte(body)) {
		t.Errorf("body = %q, want it verbatim %q", got.rec.Body, body)
	}
	if len(got.rec.Query) != 2 || got.rec.Query["a"] != "1" || got.rec.Query["b"] != "x" {
		t.Errorf("query = %v, want first values a=1 b=x", got.rec.Query)
	}
	if len(got.rec.Headers) != 1 || got.rec.Headers[record.HostHeader] != "walter-laptop" {
		t.Errorf("headers = %v, want only %s trimmed", got.rec.Headers, record.HostHeader)
	}
	if err := got.rec.Validate(); !errors.Is(err, record.ErrInvalid) {
		t.Errorf("record without n validates as %v; the tunnel assigns n", err)
	}

	do(t, s, "POST", record.PathEvent, "Bearer "+token, strings.NewReader(hookBody), map[string]string{record.HostHeader: "   "})
	if last := sink.enqueued[len(sink.enqueued)-1]; last.rec.Headers != nil || last.rec.Query != nil {
		t.Errorf("blank host header or empty query still forwarded: %+v", last.rec)
	}
}

func TestDecideTimeoutClamp(t *testing.T) {
	t.Parallel()

	sink := &fakeSink{}
	s := newServer(t, sink, nil)
	tests := []struct {
		query string
		want  time.Duration
	}{
		{query: "", want: 86400 * time.Second},
		{query: "?timeout=abc", want: 86400 * time.Second},
		{query: "?timeout=1", want: 5 * time.Second},
		{query: "?timeout=5", want: 5 * time.Second},
		{query: "?timeout=600", want: 600 * time.Second},
		{query: "?timeout=86400", want: 86400 * time.Second},
		{query: "?timeout=99999999", want: 86400 * time.Second},
	}
	for _, tt := range tests {
		do(t, s, "POST", record.PathDecide+tt.query, "Bearer "+token, strings.NewReader(hookBody), nil)
		last := sink.holds[len(sink.holds)-1]
		if last.timeout != tt.want {
			t.Errorf("decide%s held with timeout %v, want %v", tt.query, last.timeout, tt.want)
		}
		if tt.query != "" && last.rec.Query["timeout"] != strings.TrimPrefix(tt.query, "?timeout=") {
			t.Errorf("decide%s record query = %v, want the raw value", tt.query, last.rec.Query)
		}
	}
}

// wroteRecorder tells whether the handler wrote anything at all.
type wroteRecorder struct {
	*httptest.ResponseRecorder

	wrote bool
}

func (w *wroteRecorder) WriteHeader(code int) {
	w.wrote = true
	w.ResponseRecorder.WriteHeader(code)
}

func (w *wroteRecorder) Write(b []byte) (int, error) {
	w.wrote = true
	return w.ResponseRecorder.Write(b)
}

func TestDecideAnswers(t *testing.T) {
	t.Parallel()

	output := `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}`
	tests := []struct {
		name      string
		answer    func(context.Context) (record.Record, bool, error)
		wantCode  int
		wantBody  string
		wantType  string
		wantWrote bool
	}{
		{
			name: "decision with body",
			answer: func(context.Context) (record.Record, bool, error) {
				return record.Record{Status: 200, Body: []byte(output)}, true, nil
			},
			wantCode: 200, wantBody: output, wantType: "application/json", wantWrote: true,
		},
		{
			name:     "bare 204 from the phone",
			answer:   func(context.Context) (record.Record, bool, error) { return record.Record{Status: 204}, true, nil },
			wantCode: 204, wantWrote: true,
		},
		{
			name:     "200 without a body is no decision",
			answer:   func(context.Context) (record.Record, bool, error) { return record.Record{Status: 200}, true, nil },
			wantCode: 204, wantWrote: true,
		},
		{
			name:     "deadline or nothing to wait for",
			answer:   func(context.Context) (record.Record, bool, error) { return record.Record{}, false, nil },
			wantCode: 204, wantWrote: true,
		},
		{
			name:      "client gone writes nothing",
			answer:    func(context.Context) (record.Record, bool, error) { return record.Record{}, false, context.Canceled },
			wantWrote: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sink := &fakeSink{answer: tt.answer}
			s := newServer(t, sink, nil)
			req := httptest.NewRequestWithContext(t.Context(), "POST", record.PathDecide+"?timeout=300", strings.NewReader(`{"session_id":"s","hook_event_name":"PermissionRequest","permission_mode":"bubble"}`))
			req.Header.Set("Authorization", "Bearer "+token)
			rec := &wroteRecorder{ResponseRecorder: httptest.NewRecorder()}
			s.ServeHTTP(rec, req)
			if rec.wrote != tt.wantWrote {
				t.Fatalf("wrote = %v, want %v", rec.wrote, tt.wantWrote)
			}
			if !tt.wantWrote {
				return
			}
			if rec.Code != tt.wantCode || rec.Body.String() != tt.wantBody {
				t.Errorf("answer = %d %q, want %d %q", rec.Code, rec.Body.String(), tt.wantCode, tt.wantBody)
			}
			if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, tt.wantType) {
				t.Errorf("Content-Type = %q, want prefix %q", got, tt.wantType)
			}
			if h := sink.holds[0]; h.hook != (record.Hook{Event: "PermissionRequest", Mode: "bubble"}) || h.timeout != 300*time.Second {
				t.Errorf("held %+v, want a bubbled PermissionRequest for 300s", h)
			}
		})
	}
}

func TestStatusAndControl(t *testing.T) {
	t.Parallel()

	control := &fakeControl{}
	s := newServer(t, &fakeSink{}, control)
	for _, path := range []string{record.PathStatus, ctl.PathStatus} {
		auth := "Bearer " + token
		if path == ctl.PathStatus {
			auth = "Bearer " + admin
		}
		rec := do(t, s, "GET", path, auth, nil, nil)
		if rec.Code != 200 {
			t.Fatalf("GET %s = %d, want 200", path, rec.Code)
		}
		var st ctl.Status
		if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil || !st.Paired || len(st.Pairs) != 1 {
			t.Errorf("GET %s body = %s (%v), want the controller's status", path, rec.Body.String(), err)
		}
	}
	if rec := do(t, s, "POST", ctl.PathReload, "Bearer "+admin, nil, nil); rec.Code != 204 || control.reloads != 1 {
		t.Errorf("reload = %d with %d reloads, want 204 and 1", rec.Code, control.reloads)
	}
	if rec := do(t, s, "GET", ctl.PathReload, "Bearer "+admin, nil, nil); rec.Code != 405 {
		t.Errorf("GET reload = %d, want 405", rec.Code)
	}
	if rec := do(t, s, "DELETE", ctl.PathPairs+"p1", "Bearer "+admin, nil, nil); rec.Code != 204 || len(control.released) != 1 {
		t.Errorf("release p1 = %d with %v released, want 204 and [p1]", rec.Code, control.released)
	}
	if rec := do(t, s, "DELETE", ctl.PathPairs+"p2", "Bearer "+admin, nil, nil); rec.Code != 404 {
		t.Errorf("release unknown = %d, want 404", rec.Code)
	}
	if rec := do(t, s, "POST", ctl.PathPairs+"p1", "Bearer "+admin, nil, nil); rec.Code != 405 {
		t.Errorf("POST pairs = %d, want 405", rec.Code)
	}
}

func TestServeStopsOnContext(t *testing.T) {
	t.Parallel()

	s := newServer(t, &fakeSink{}, nil)
	ln, err := Listen(t.Context(), "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+ln.Addr().String()+"/", http.NoBody)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET / = %d, want 404", resp.StatusCode)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after the context ended")
	}
}

func TestIsLoopback(t *testing.T) {
	t.Parallel()

	for addr, want := range map[string]bool{
		"127.0.0.1:7317": true, "[::1]:7317": true, "localhost:7317": true,
		"0.0.0.0:7317": false, ":7317": false, "10.0.0.2:7317": false, "nope": false,
	} {
		if got := IsLoopback(addr); got != want {
			t.Errorf("IsLoopback(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestNewRequiresSinkAndEntropy(t *testing.T) {
	t.Parallel()

	if _, err := New(Options{Entropy: rand.Reader}); err == nil {
		t.Error("New without a Sink: want an error")
	}
	if _, err := New(Options{Sink: &fakeSink{}}); err == nil {
		t.Error("New without entropy: want an error")
	}
}
