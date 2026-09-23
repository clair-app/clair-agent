package relay

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// signingVectorPath is the relay's canonical v2 vector (RFC 8032 §7.1 TEST 1
// key, a fixed nonce and host), copied unchanged from clair-server commit
// d74f7a7 (`src/auth/testdata/signing-vector-v2.json`, relay ADR
// 2026-09.9vsq). A refresh updates both; a mismatch is a bug on one side.
const signingVectorPath = "testdata/signing-vector-v2.json"

func TestSigningVectorV2(t *testing.T) {
	t.Parallel()

	var v struct {
		SeedHex       string `json:"seedHex"`
		PublicKeyHex  string `json:"publicKeyHex"`
		Method        string `json:"method"`
		Host          string `json:"host"`
		RequestURI    string `json:"requestURI"`
		TS            int64  `json:"ts"`
		Nonce         string `json:"nonce"`
		BodyHex       string `json:"bodyHex"`
		Canonical     string `json:"canonical"`
		SignatureB64  string `json:"signatureB64"`
		Authorization string `json:"authorization"`
	}
	data, err := os.ReadFile(signingVectorPath)
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	if err = json.Unmarshal(data, &v); err != nil {
		t.Fatalf("decode vector: %v", err)
	}
	seed, _ := hex.DecodeString(v.SeedHex)
	priv := ed25519.NewKeyFromSeed(seed)
	if got := hex.EncodeToString(priv.Public().(ed25519.PublicKey)); got != v.PublicKeyHex {
		t.Fatalf("public key = %s, want %s (RFC 8032 TEST 1)", got, v.PublicKeyHex)
	}
	body, _ := hex.DecodeString(v.BodyHex)
	if got := Canonical(v.Method, v.Host, v.RequestURI, v.TS, v.Nonce, body); string(got) != v.Canonical {
		t.Errorf("Canonical = %q, want %q", got, v.Canonical)
	}
	s := NewSigner(priv)
	got := s.Authorization(v.Method, v.Host, v.RequestURI, v.TS, v.Nonce, body)
	if got != v.Authorization {
		t.Errorf("Authorization = %q, want %q", got, v.Authorization)
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(v.SignatureB64)
	if err != nil {
		t.Fatalf("signature base64: %v", err)
	}
	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), []byte(v.Canonical), sig) {
		t.Error("pinned signature does not verify under the pinned key")
	}
	if want := base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)); s.Key() != want {
		t.Errorf("Key = %q, want %q", s.Key(), want)
	}
}

func TestCanonicalHashesTheBodyAndLowersTheHost(t *testing.T) {
	t.Parallel()

	const nonce = "AAECAwQFBgcICQoLDA0ODw"
	empty := Canonical("POST", "Relay.Example:8443", "/v1/pairings", 1, nonce, nil)
	if !bytes.HasSuffix(empty, []byte("\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")) {
		t.Errorf("empty body canonical = %q, want the SHA-256 of nothing", empty)
	}
	if !bytes.HasPrefix(empty, []byte("clair-v2\nPOST\nrelay.example:8443\n/v1/pairings\n1\n"+nonce+"\n")) {
		t.Errorf("canonical = %q, want the v2 label, the method and the lower-cased host with its port", empty)
	}
	withBody := Canonical("POST", "relay.example:8443", "/v1/pairings", 1, nonce, []byte("{}"))
	if bytes.Equal(withBody, empty) {
		t.Error("a body did not change the canonical string")
	}
	if strings.Count(string(withBody), "\n") != 6 {
		t.Errorf("canonical = %q, want exactly six newlines", withBody)
	}
}

func TestNewNonce(t *testing.T) {
	t.Parallel()

	src := bytes.NewReader(bytes.Repeat([]byte{0xfb}, 2*NonceSize))
	a, err := NewNonce(src)
	if err != nil {
		t.Fatalf("NewNonce: %v", err)
	}
	if src.Len() != NonceSize {
		t.Errorf("NewNonce read %d bytes, want %d", 2*NonceSize-src.Len(), NonceSize)
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(a)
	if err != nil || len(a) != 22 || len(raw) != NonceSize {
		t.Errorf("nonce = %q (%d chars, %v), want 22 chars of unpadded base64url", a, len(a), err)
	}
	if strings.ContainsAny(a, "+/=") {
		t.Errorf("nonce = %q, want the URL alphabet without padding", a)
	}
	if _, err := NewNonce(bytes.NewReader(make([]byte, NonceSize-1))); err == nil {
		t.Error("NewNonce on a short reader: err = nil, want an error")
	}
}

func TestCursorAcceptsStringsAndNumbers(t *testing.T) {
	t.Parallel()

	var got struct {
		A Cursor `json:"A"`
		B Cursor `json:"B"`
		C Cursor `json:"C"`
	}
	if err := json.Unmarshal([]byte(`{"A":"12","B":34,"C":null}`), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.A != "12" || got.B != "34" || got.C != "" {
		t.Fatalf("cursors = %+v, want 12, 34, empty", got)
	}
	out, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(out) != `{"A":"12","B":"34","C":""}` {
		t.Fatalf("Marshal = %s, want strings", out)
	}
	if err := json.Unmarshal([]byte(`{"A":true}`), &got); err == nil {
		t.Error("Unmarshal of a boolean cursor: want an error")
	}
}

func TestBatch(t *testing.T) {
	t.Parallel()

	small := func(n int) [][]byte {
		out := make([][]byte, n)
		for i := range out {
			out[i] = []byte(`{"i":` + strings.Repeat("1", 1+i%3) + `}`)
		}
		return out
	}
	n, body := batch(small(1))
	if n != 1 || string(body) != `{"i":1}` {
		t.Errorf("batch(1) = %d, %s; want the envelope bare", n, body)
	}
	n, body = batch(small(3))
	if n != 3 || string(body) != `{"envelopes":[{"i":1},{"i":11},{"i":111}]}` {
		t.Errorf("batch(3) = %d, %s", n, body)
	}
	if n, _ = batch(small(250)); n != BatchMaxEnvelopes {
		t.Errorf("batch(250) took %d, want %d", n, BatchMaxEnvelopes)
	}
	big := bytes.Repeat([]byte("x"), BatchMaxBytes/2)
	n, _ = batch([][]byte{big, big, big})
	if n != 1 {
		t.Errorf("batch of three half-cap envelopes took %d, want 1 (two would exceed the cap with the wrapper)", n)
	}
	n, body = batch([][]byte{big, big[:len(big)-100], big})
	if n != 2 || len(body) > BatchMaxBytes {
		t.Errorf("batch stopped at %d envelopes with %d bytes, want 2 under the cap", n, len(body))
	}
}

func TestParseRetryAfter(t *testing.T) {
	t.Parallel()

	date := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		value string
		want  time.Duration
	}{
		{value: "", want: 0},
		{value: "7", want: 7 * time.Second},
		{value: "-3", want: 0},
		{value: "99999", want: RetryAfterMax},
		{value: date.Add(90 * time.Second).Format(http.TimeFormat), want: 90 * time.Second},
		{value: "soon", want: 0},
	}
	for _, tt := range tests {
		if got := parseRetryAfter(tt.value, date.Format(http.TimeFormat)); got != tt.want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", tt.value, got, tt.want)
		}
	}
}

func TestParseUnix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw  string
		want int64
		ok   bool
	}{
		{raw: `1700000000`, want: 1700000000, ok: true},
		{raw: `"1700000000"`, want: 1700000000, ok: true},
		{raw: `1700000000123`, want: 1700000000, ok: true},
		{raw: `"2023-11-14T22:13:20Z"`, want: 1700000000, ok: true},
		{raw: `null`, ok: false},
		{raw: ``, ok: false},
		{raw: `"later"`, ok: false},
	}
	for _, tt := range tests {
		got, ok := parseUnix(json.RawMessage(tt.raw))
		if got != tt.want || ok != tt.ok {
			t.Errorf("parseUnix(%s) = %d, %v; want %d, %v", tt.raw, got, ok, tt.want, tt.ok)
		}
	}
}

func TestBackoff(t *testing.T) {
	t.Parallel()

	for attempt := range 10 {
		lo, hi := backoff(attempt, 0), backoff(attempt, 1)
		if lo > hi || hi > BackoffMax || lo < BackoffInitial/2 {
			t.Errorf("backoff(%d) spans %v..%v, want within [%v, %v]", attempt, lo, hi, BackoffInitial/2, BackoffMax)
		}
		if attempt > 0 && backoff(attempt, 0) < backoff(attempt-1, 0) {
			t.Errorf("backoff(%d) fixed part fell below backoff(%d)", attempt, attempt-1)
		}
	}
	if got := backoff(0, 0); got != BackoffInitial/2 {
		t.Errorf("backoff(0, 0) = %v, want %v", got, BackoffInitial/2)
	}
	if got := backoff(20, 1); got != BackoffMax {
		t.Errorf("backoff(20, 1) = %v, want the cap %v", got, BackoffMax)
	}
}

func TestSSEReader(t *testing.T) {
	t.Parallel()

	type ev = sseEvent
	tests := []struct {
		name   string
		stream string
		want   []ev
		lastID string
		retry  time.Duration
		err    error
	}{
		{name: "single", stream: "event: envelope\nid: 5\ndata: {\"a\":1}\n\n", want: []ev{{name: "envelope", id: "5", data: `{"a":1}`}}, lastID: "5"},
		{name: "multi-line data joins with newline", stream: "data: a\ndata: b\n\n", want: []ev{{data: "a\nb"}}},
		{name: "crlf", stream: "event: x\r\ndata: y\r\n\r\n", want: []ev{{name: "x", data: "y"}}},
		{name: "no space after colon", stream: "data:y\n\n", want: []ev{{data: "y"}}},
		{name: "only one leading space stripped", stream: "data:  y\n\n", want: []ev{{data: " y"}}},
		{name: "comment-only block is skipped", stream: ": keepalive\n\nevent: e\ndata: d\n\n", want: []ev{{name: "e", data: "d"}}},
		{name: "id on a data-less block updates the reader", stream: "id: 9\nretry: 1500\n: reconnect\n\n", want: nil, lastID: "9", retry: 1500 * time.Millisecond},
		{name: "id persists across events", stream: "id: 1\ndata: a\n\ndata: b\n\n", want: []ev{{id: "1", data: "a"}, {id: "1", data: "b"}}, lastID: "1"},
		{name: "field without colon is a field with empty value", stream: "data\n\n", want: []ev{{data: ""}}},
		{name: "unknown field ignored", stream: "foo: bar\ndata: d\n\n", want: []ev{{data: "d"}}},
		{name: "final line without newline", stream: "data: d\n\nid: 3", want: []ev{{data: "d"}}, lastID: "3"},
		{name: "block cut by eof is discarded", stream: "data: partial", want: nil},
		{name: "retry not a number ignored", stream: "retry: soon\n\n", want: nil},
		{name: "oversize line", stream: "data: " + strings.Repeat("x", MaxSSELineBytes+1) + "\n\n", err: ErrProtocol},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			lines := 0
			rd := newSSEReader(strings.NewReader(tt.stream), func() { lines++ })
			var got []ev
			var err error
			for {
				var e ev
				e, err = rd.next()
				if err != nil {
					break
				}
				got = append(got, e)
			}
			if tt.err != nil {
				if !errors.Is(err, tt.err) {
					t.Fatalf("next: err = %v, want %v", err, tt.err)
				}
				return
			}
			if !errors.Is(err, io.EOF) {
				t.Fatalf("next: err = %v, want io.EOF", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("events = %+v, want %+v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("event %d = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
			if rd.lastID != tt.lastID {
				t.Errorf("lastID = %q, want %q", rd.lastID, tt.lastID)
			}
			if rd.retry != tt.retry {
				t.Errorf("retry = %v, want %v", rd.retry, tt.retry)
			}
			if lines == 0 && tt.stream != "" {
				t.Error("onLine was never called")
			}
		})
	}
}
