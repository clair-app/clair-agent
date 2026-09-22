// Package relay is the agent's client for the relay (RELAY.md §7, as pinned
// by the relay's own plan): Ed25519-signed requests, SSE down and POST up,
// bounded streams resumed by cursor, and typed answers. It carries envelopes
// and never looks inside them.
package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"claircode.app/clair-agent/internal/envelope"
)

// Timing and size knobs. Those marked draft are starting points.
const (
	// DefaultBaseURL is the developer's relay; `--relay` overrides it.
	DefaultBaseURL = "https://relay.claircode.app"
	// SkewMax is the clock skew the relay tolerates (RELAY.md §7.3).
	SkewMax = 300 * time.Second
	// UnaryTimeout bounds one non-streaming call (draft).
	UnaryTimeout = 30 * time.Second
	// ResponseHeaderTimeout bounds the wait for any response's headers; a
	// stream flushes its headers on open, so it applies there too (draft).
	ResponseHeaderTimeout = 30 * time.Second
	// StreamIdleTimeout ends a stream that stayed silent for three of the
	// relay's 30 s keepalives (§7.2; draft).
	StreamIdleTimeout = 90 * time.Second
	// DefaultRetry is the reconnect delay after a clean stream end when the
	// relay sent no `retry:`; RetryMin and RetryMax clamp the one it sends.
	DefaultRetry = time.Second
	RetryMin     = 250 * time.Millisecond
	RetryMax     = 30 * time.Second
	// BackoffInitial and BackoffMax bound the jittered exponential backoff
	// after a failed connection (§13; draft).
	BackoffInitial = time.Second
	BackoffMax     = 60 * time.Second
	// RetryAfterMax clamps a 429's Retry-After (draft).
	RetryAfterMax = 5 * time.Minute
	// BatchMaxEnvelopes and BatchMaxBytes are the relay's batch upload limits.
	BatchMaxEnvelopes = 100
	BatchMaxBytes     = envelope.MaxEnvelopeJSON
	// MaxSSELineBytes caps one SSE line: a `data:` line carries a whole envelope.
	MaxSSELineBytes = envelope.MaxEnvelopeJSON + 64
	// A non-streaming answer is read up to maxResponseBody (receipts are
	// small); an error answer up to maxErrorBody, enough for its `error`.
	maxResponseBody = 1 << 20
	maxErrorBody    = 4096
)

// Options configure a Client. The zero value is production: the developer's
// relay, the system trust store, the proxy environment, real time and sleep.
type Options struct {
	// BaseURL is the relay's origin, e.g. https://relay.claircode.app or
	// http://localhost:3000 for a local relay.
	BaseURL string
	// RootCAs replaces the system roots when set (`--relay-ca`, RELAY.md §12:
	// self-hosters pin explicitly; everyone else trusts the system store so
	// TLS-inspecting proxies keep working).
	RootCAs *x509.CertPool
	// Proxy selects a proxy per request; nil means http.ProxyFromEnvironment
	// (HTTPS_PROXY / NO_PROXY, §12). It is a parameter because
	// ProxyFromEnvironment reads the environment once per process and never
	// proxies loopback targets, so a test cannot steer it.
	Proxy func(*http.Request) (*url.URL, error)
	// UserAgent identifies this agent build to the relay.
	UserAgent string
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Sleep waits for a duration or the context; nil means a timer. Tests
	// record the durations instead of waiting.
	Sleep func(context.Context, time.Duration) error
	// Jitter returns a value in [0, 1) for the backoff; nil means math/rand.
	Jitter func() float64
	// Logger receives static messages with sizes, paths and ids — never bodies
	// or headers. Nil discards.
	Logger *slog.Logger
	// StreamIdleTimeout overrides StreamIdleTimeout; tests shorten it.
	StreamIdleTimeout time.Duration
}

// Client talks to one relay as one Ed25519 identity. It is safe for
// concurrent use and keeps no state beyond the skew it learnt and the
// one-in-flight upload slot per (pair, direction).
type Client struct {
	base   *url.URL
	http   *http.Client
	signer *Signer
	// skew is the seconds to add to the local clock so the relay accepts the
	// timestamp; learnt from a 401 (RELAY.md §7.3, §13).
	skew   atomic.Int64
	slots  slots
	now    func() time.Time
	sleep  func(context.Context, time.Duration) error
	jitter func() float64
	idle   time.Duration
	ua     string
	log    *slog.Logger
}

// New builds a client for the relay in opts, signing as auth.
func New(auth ed25519.PrivateKey, opts Options) (*Client, error) {
	raw := opts.BaseURL
	if raw == "" {
		raw = DefaultBaseURL
	}
	base, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("relay: base url %q: %w", raw, err)
	}
	if (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return nil, fmt.Errorf("relay: base url %q: want http(s)://host", raw)
	}
	base.Path = strings.TrimSuffix(base.Path, "/")
	base.RawQuery, base.Fragment = "", ""

	proxy := opts.Proxy
	if proxy == nil {
		proxy = http.ProxyFromEnvironment
	}
	transport := &http.Transport{
		Proxy:                 proxy,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: ResponseHeaderTimeout,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: opts.RootCAs},
	}
	c := &Client{
		base:   base,
		signer: NewSigner(auth),
		now:    opts.Now,
		sleep:  opts.Sleep,
		jitter: opts.Jitter,
		idle:   opts.StreamIdleTimeout,
		ua:     opts.UserAgent,
		log:    opts.Logger,
	}
	c.http = &http.Client{
		Transport: transport,
		// A redirect would change the signed request target; never follow one.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.sleep == nil {
		c.sleep = sleep
	}
	if c.jitter == nil {
		c.jitter = rand.Float64
	}
	if c.idle <= 0 {
		c.idle = StreamIdleTimeout
	}
	if c.ua == "" {
		c.ua = "clair-agent"
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	return c, nil
}

// Key is the public key the client signs as, as the relay knows it.
func (c *Client) Key() string { return c.signer.Key() }

// Skew is the clock correction learnt from the relay, for `clair status`.
func (c *Client) Skew() time.Duration { return time.Duration(c.skew.Load()) * time.Second }

// sleep waits for d or the context.
func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// reply is a non-streaming answer with its body read.
type reply struct {
	status int
	header http.Header
	body   []byte
}

// newRequest builds a signed request for path (which may carry a query)
// with an optional JSON body.
func (c *Client) newRequest(ctx context.Context, method, path string, body []byte) (*http.Request, error) {
	u := *c.base
	p, query, _ := strings.Cut(path, "?")
	u.Path, u.RawQuery = c.base.Path+p, query
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return nil, fmt.Errorf("relay: build %s %s: %w", method, path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.ua)
	ts := c.now().Unix() + c.skew.Load()
	req.Header.Set("Authorization", c.signer.Authorization(method, req.URL.RequestURI(), ts, body))
	return req, nil
}

// do performs one non-streaming call, correcting the clock and retrying once
// when the relay reports skew. A 2xx returns the reply; anything else is a
// *StatusError.
func (c *Client) do(ctx context.Context, method, path string, body []byte) (*reply, error) {
	ctx, cancel := context.WithTimeout(ctx, UnaryTimeout)
	defer cancel()
	for attempt := range 2 {
		r, serr, err := c.once(ctx, method, path, body)
		if err != nil {
			return nil, err
		}
		if serr == nil {
			return r, nil
		}
		if serr.Status == http.StatusUnauthorized && attempt == 0 && c.correctSkew(serr, r.header, r.body) {
			c.log.Info("relay clock skew corrected", "path", path, "skew_s", c.skew.Load())
			continue
		}
		c.log.Warn("relay request refused", "method", method, "path", path, "status", serr.Status, "code", serr.Code)
		return nil, serr
	}
	return nil, fmt.Errorf("%w: %s %s still refused after correcting skew", ErrUnauthorized, method, path)
}

// once performs one call. A non-2xx answer comes back as a *StatusError with
// the reply still attached (for the skew correction to read).
func (c *Client) once(ctx context.Context, method, path string, body []byte) (*reply, *StatusError, error) {
	req, err := c.newRequest(ctx, method, path, body)
	if err != nil {
		return nil, nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("relay: %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := readBody(resp.Body, maxResponseBody)
	if err != nil {
		return nil, nil, fmt.Errorf("relay: %s %s: read: %w", method, path, err)
	}
	r := &reply{status: resp.StatusCode, header: resp.Header, body: data}
	if resp.StatusCode/100 == 2 {
		return r, nil, nil
	}
	return r, c.statusError(path, resp, data), nil
}

// readBody reads at most limit bytes; the caller closes the body.
func readBody(body io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: body over %d bytes", ErrProtocol, limit)
	}
	return data, nil
}

// errorBody is what the relay puts in an error answer.
type errorBody struct {
	Error      string          `json:"error"`
	Reason     string          `json:"reason"`
	ServerTime json.RawMessage `json:"serverTime"`
}

// statusError classifies a non-2xx answer.
func (*Client) statusError(path string, resp *http.Response, data []byte) *StatusError {
	e := &StatusError{Status: resp.StatusCode, Path: path}
	var body errorBody
	if json.Unmarshal(data[:min(len(data), maxErrorBody)], &body) == nil {
		e.Code, e.Reason = body.Error, body.Reason
	}
	switch resp.StatusCode {
	case http.StatusBadRequest:
		e.sentinel = ErrBadRequest
	case http.StatusUnauthorized:
		e.sentinel = ErrUnauthorized
	case http.StatusNotFound:
		e.sentinel = ErrNotFound
	case http.StatusConflict:
		e.sentinel = ErrPairingUsed
	case http.StatusGone:
		if e.Code == "pairing_expired" {
			e.sentinel = ErrPairingExpired
		} else {
			e.sentinel = ErrRevoked
		}
	case http.StatusRequestEntityTooLarge:
		e.sentinel = ErrTooLarge
	case http.StatusTooManyRequests:
		e.RetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), resp.Header.Get("Date"))
		if e.Code == "mailbox_full" {
			e.sentinel = ErrMailboxFull
		} else {
			e.sentinel = ErrRateLimited
		}
	default:
		if resp.StatusCode >= 500 {
			e.sentinel = ErrUnavailable
		} else {
			e.sentinel = ErrProtocol
		}
	}
	return e
}

// correctSkew adopts the relay's clock after a 401 that blames skew (or gives
// no reason): `serverTime` from the body first, the Date header as the
// fallback (RELAY.md §7.3, §13). It reports whether anything was adopted.
func (c *Client) correctSkew(serr *StatusError, header http.Header, data []byte) bool {
	if serr.Reason != "" && serr.Reason != "skew" {
		return false
	}
	var body errorBody
	_ = json.Unmarshal(data[:min(len(data), maxErrorBody)], &body)
	if server, ok := parseUnix(body.ServerTime); ok {
		c.skew.Store(server - c.now().Unix())
		return true
	}
	if date, err := http.ParseTime(header.Get("Date")); err == nil {
		c.skew.Store(date.Unix() - c.now().Unix())
		return true
	}
	return false
}

// parseUnix reads a unix time that the relay may send as seconds or
// milliseconds, as a number or a string.
func parseUnix(raw json.RawMessage) (int64, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, false
	}
	s := strings.Trim(string(raw), `"`)
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t.Unix(), true
		}
		return 0, false
	}
	if n > 1e11 { // milliseconds
		n /= 1000
	}
	return n, true
}

// parseRetryAfter reads Retry-After as seconds or an HTTP date, clamped.
func parseRetryAfter(value, date string) time.Duration {
	if value == "" {
		return 0
	}
	var d time.Duration
	if secs, err := strconv.Atoi(value); err == nil {
		d = time.Duration(secs) * time.Second
	} else if at, err := http.ParseTime(value); err == nil {
		base := time.Now()
		if now, err := http.ParseTime(date); err == nil {
			base = now
		}
		d = at.Sub(base)
	}
	return min(max(d, 0), RetryAfterMax)
}

// slots serialises uploads per (pair, direction): one in flight, as the
// relay's cursor semantics require.
type slots struct {
	mu sync.Mutex
	m  map[string]chan struct{}
}

// acquire takes the slot for key, waiting for the holder or the context.
func (s *slots) acquire(ctx context.Context, key string) (release func(), err error) {
	s.mu.Lock()
	if s.m == nil {
		s.m = make(map[string]chan struct{})
	}
	ch, ok := s.m[key]
	if !ok {
		ch = make(chan struct{}, 1)
		s.m[key] = ch
	}
	s.mu.Unlock()
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Cursor is the relay's mailbox position: opaque to the agent, a string on
// the wire. It tolerates a JSON number on input, since the relay's cursor is
// a database integer, and always marshals as a string.
type Cursor string

// UnmarshalJSON accepts a string, a number or null.
func (c *Cursor) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*c = ""
		return nil
	}
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return fmt.Errorf("cursor: %w", err)
		}
		*c = Cursor(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("cursor: %w", err)
	}
	*c = Cursor(n.String())
	return nil
}

// Pairing is a pending pairing the host minted (RELAY.md §6, §7.2).
type Pairing struct {
	ID        string
	ExpiresAt time.Time
}

// Completed is what the relay hands the waiting host once a phone completed
// the pairing: the pair id (equal to the pairing id), the phone's X25519
// public key and its `hello` envelope.
type Completed struct {
	PairID   string
	PhonePub []byte
	Envelope envelope.Envelope
}

// Accepted is one envelope the relay stored.
type Accepted struct {
	ID     string `json:"id"`
	Cursor Cursor `json:"cursor"`
	TTLSec int    `json:"ttlSec"`
}

// Receipt is the relay's answer to an upload. On an error mid-batch it names
// what the relay had already accepted, so the sender drops only those.
type Receipt struct {
	Accepted   []Accepted `json:"accepted"`
	Duplicates []string   `json:"duplicates"`
}

// MintPairing asks the relay for a pending pairing (POST /v1/pairings).
func (c *Client) MintPairing(ctx context.Context) (Pairing, error) {
	r, err := c.do(ctx, http.MethodPost, "/v1/pairings", nil)
	if err != nil {
		return Pairing{}, err
	}
	var body struct {
		PairingID string          `json:"pairingId"`
		ExpiresAt json.RawMessage `json:"expiresAt"`
	}
	if err := json.Unmarshal(r.body, &body); err != nil || body.PairingID == "" {
		return Pairing{}, fmt.Errorf("%w: mint pairing: bad answer", ErrProtocol)
	}
	p := Pairing{ID: body.PairingID}
	if unix, ok := parseUnix(body.ExpiresAt); ok {
		p.ExpiresAt = time.Unix(unix, 0)
	}
	return p, nil
}

// CompletePairing is the phone's side of §6 (POST /v1/pairings/{id}/complete):
// its X25519 public key, its push token and the sealed `hello`. The agent
// never calls it; tools/phonesim and tests do.
func (c *Client) CompletePairing(ctx context.Context, pairingID string, phonePub []byte, pushToken string, hello envelope.Envelope) (string, error) {
	body, err := json.Marshal(struct {
		PhonePub  string            `json:"phonePub"`
		PushToken string            `json:"pushToken"`
		Envelope  envelope.Envelope `json:"envelope"`
	}{base64.RawURLEncoding.EncodeToString(phonePub), pushToken, hello})
	if err != nil {
		return "", fmt.Errorf("relay: encode complete: %w", err)
	}
	r, err := c.do(ctx, http.MethodPost, "/v1/pairings/"+url.PathEscape(pairingID)+"/complete", body)
	if err != nil {
		return "", err
	}
	var answer struct {
		PairID string `json:"pairId"`
	}
	if err := json.Unmarshal(r.body, &answer); err != nil || answer.PairID == "" {
		return "", fmt.Errorf("%w: complete pairing: bad answer", ErrProtocol)
	}
	return answer.PairID, nil
}

// Upload sends envelopes for one pair (POST /v1/pairs/{pair}/envelopes). It
// chunks them to the relay's batch limits, posts a lone envelope bare so the
// batch wrapper can never push a full-size one over the cap, and holds the
// pair's one-in-flight slot for the direction until every chunk is answered.
// The receipt covers what the relay accepted, even when a later chunk failed.
func (c *Client) Upload(ctx context.Context, pair string, envs []envelope.Envelope) (Receipt, error) {
	var receipt Receipt
	if len(envs) == 0 {
		return receipt, nil
	}
	dir := envs[0].Dir
	encoded := make([][]byte, len(envs))
	for i, e := range envs {
		if e.Pair != pair || e.Dir != dir {
			return receipt, fmt.Errorf("relay: upload: envelope %d is for %s/%s, batch is %s/%s", i, e.Pair, e.Dir, pair, dir)
		}
		data, err := json.Marshal(e)
		if err != nil {
			return receipt, fmt.Errorf("relay: encode envelope: %w", err)
		}
		if len(data) > BatchMaxBytes {
			return receipt, fmt.Errorf("%w: envelope %s is %d bytes", ErrTooLarge, e.ID, len(data))
		}
		encoded[i] = data
	}
	release, err := c.slots.acquire(ctx, pair+"/"+string(dir))
	if err != nil {
		return receipt, err
	}
	defer release()

	path := "/v1/pairs/" + url.PathEscape(pair) + "/envelopes"
	for start := 0; start < len(encoded); {
		end, body := batch(encoded[start:])
		r, err := c.do(ctx, http.MethodPost, path, body)
		if err != nil {
			return receipt, err
		}
		var part Receipt
		if err := json.Unmarshal(r.body, &part); err != nil {
			return receipt, fmt.Errorf("%w: upload receipt: %w", ErrProtocol, err)
		}
		receipt.Accepted = append(receipt.Accepted, part.Accepted...)
		receipt.Duplicates = append(receipt.Duplicates, part.Duplicates...)
		c.log.Debug("envelopes uploaded", "pair", pair, "count", end, "accepted", len(part.Accepted), "duplicates", len(part.Duplicates))
		start += end
	}
	return receipt, nil
}

// batch takes as many leading envelopes as fit one upload and builds its
// body: the envelope itself when it stands alone, else the batch wrapper.
func batch(encoded [][]byte) (n int, body []byte) {
	const wrapper = len(`{"envelopes":[]}`)
	size := wrapper
	for n < len(encoded) && n < BatchMaxEnvelopes {
		next := size + len(encoded[n])
		if n > 0 {
			next++ // the comma
		}
		if n > 0 && next > BatchMaxBytes {
			break
		}
		size = next
		n++
	}
	if n == 1 {
		return 1, encoded[0]
	}
	body = make([]byte, 0, size)
	body = append(body, `{"envelopes":[`...)
	for i := range n {
		if i > 0 {
			body = append(body, ',')
		}
		body = append(body, encoded[i]...)
	}
	return n, append(body, "]}"...)
}

// Ack tells the relay every inbound row up to and including cursor was applied
// (POST /v1/pairs/{pair}/ack). The relay takes the cursor back as the JSON
// integer it is, not the string Cursor marshals as.
func (c *Client) Ack(ctx context.Context, pair string, cursor Cursor) error {
	n, err := strconv.ParseUint(string(cursor), 10, 63)
	if err != nil {
		return fmt.Errorf("relay: ack cursor %q is not a non-negative integer", string(cursor))
	}
	body, err := json.Marshal(struct {
		Cursor uint64 `json:"cursor"`
	}{n})
	if err != nil {
		return fmt.Errorf("relay: encode ack: %w", err)
	}
	_, err = c.do(ctx, http.MethodPost, "/v1/pairs/"+url.PathEscape(pair)+"/ack", body)
	return err
}

// Revoke ends the pair from this side (DELETE /v1/pairs/{pair}, RELAY.md §6.6).
func (c *Client) Revoke(ctx context.Context, pair string) error {
	_, err := c.do(ctx, http.MethodDelete, "/v1/pairs/"+url.PathEscape(pair), nil)
	return err
}
