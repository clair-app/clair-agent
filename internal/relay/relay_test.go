package relay_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"claircode.app/clair-agent/internal/envelope"
	"claircode.app/clair-agent/internal/identity"
	"claircode.app/clair-agent/internal/relay"
	"claircode.app/clair-agent/internal/relay/relaytest"
)

const pairID = "AAAAAAAAAAAAAAAAAAAAAA"

// sleeps records every wait a client asked for instead of waiting, and can
// cancel a context after a number of them.
type sleeps struct {
	mu     sync.Mutex
	waits  []time.Duration
	cancel func()
	after  int
}

func (s *sleeps) sleep(_ context.Context, d time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.waits = append(s.waits, d)
	if s.cancel != nil && len(s.waits) >= s.after {
		s.cancel()
	}
	return nil
}

func (s *sleeps) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.waits)
}

func newIdentity(t *testing.T) *identity.Keys {
	t.Helper()
	keys, err := identity.Generate(rand.Reader)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return keys
}

func newClient(t *testing.T, fake *relaytest.Fake, keys *identity.Keys, opts relay.Options) *relay.Client {
	t.Helper()
	if opts.BaseURL == "" {
		opts.BaseURL = fake.URL
	}
	c, err := relay.New(keys.Auth(), opts)
	if err != nil {
		t.Fatalf("relay.New: %v", err)
	}
	return c
}

// mkEnv builds a well-formed envelope with a unique id; ct is filler of the
// given plaintext size (the fake never decrypts).
func mkEnv(t *testing.T, pair string, dir envelope.Dir, i, size int) envelope.Envelope {
	t.Helper()
	entropy := bytes.Repeat([]byte{byte(i)}, 10)
	id, err := envelope.NewID(time.UnixMilli(int64(i)+1), bytes.NewReader(entropy))
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	return envelope.Envelope{
		V: envelope.Version, Pair: pair, ID: id, Dir: dir, Wake: envelope.WakeNo, TTLSec: 3600,
		CT: base64.RawURLEncoding.EncodeToString(make([]byte, envelope.NonceSize+envelope.TagSize+size)),
	}
}

func TestSkewIsCorrectedFromTheRelay(t *testing.T) {
	t.Parallel()

	for _, viaDate := range []bool{false, true} {
		t.Run(fmt.Sprintf("date_fallback=%v", viaDate), func(t *testing.T) {
			t.Parallel()
			fake := relaytest.New()
			t.Cleanup(fake.Close)
			fake.Set(func(f *relaytest.Fake) { f.NoServerTime = viaDate })
			keys := newIdentity(t)
			slow := time.Now().Add(-1000 * time.Second)
			client := newClient(t, fake, keys, relay.Options{Now: func() time.Time { return slow }})

			pairing, err := client.MintPairing(t.Context())
			if err != nil {
				t.Fatalf("MintPairing: %v", err)
			}
			if pairing.ID == "" || pairing.ExpiresAt.IsZero() {
				t.Errorf("MintPairing = %+v, want an id and an expiry", pairing)
			}
			reqs := fake.Requests()
			if len(reqs) != 2 || reqs[0].Status != http.StatusUnauthorized || reqs[1].Status != http.StatusCreated {
				t.Fatalf("requests = %+v, want a 401 then a 201", reqs)
			}
			if d := time.Since(time.Unix(reqs[1].TS, 0)); d < -relay.SkewMax || d > relay.SkewMax {
				t.Errorf("second request signed with ts %d, %v from now; want within ±%v", reqs[1].TS, d, relay.SkewMax)
			}
			if skew := client.Skew(); skew < 990*time.Second || skew > 1010*time.Second {
				t.Errorf("Skew = %v, want ≈ 1000s", skew)
			}
		})
	}
}

func TestSignatureRefusalIsNotRetried(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized","reason":"signature","serverTime":1}`))
	}))
	t.Cleanup(srv.Close)
	client, err := relay.New(newIdentity(t).Auth(), relay.Options{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("relay.New: %v", err)
	}
	_, err = client.MintPairing(t.Context())
	if !errors.Is(err, relay.ErrUnauthorized) {
		t.Fatalf("MintPairing: err = %v, want ErrUnauthorized", err)
	}
	if calls.Load() != 1 {
		t.Errorf("server saw %d requests, want 1: a signature refusal is not a clock problem", calls.Load())
	}
	var serr *relay.StatusError
	if !errors.As(err, &serr) || serr.Reason != "signature" {
		t.Errorf("err = %#v, want a *StatusError with reason signature", err)
	}
}

func TestUploadBatchesAndReportsDuplicates(t *testing.T) {
	t.Parallel()

	fake := relaytest.New()
	t.Cleanup(fake.Close)
	host := newIdentity(t)
	client := newClient(t, fake, host, relay.Options{})
	fake.AddPair(pairID, client.Key(), "phone")

	envs := make([]envelope.Envelope, 250)
	for i := range envs {
		envs[i] = mkEnv(t, pairID, envelope.DirH2P, i, 8)
	}
	receipt, err := client.Upload(t.Context(), pairID, envs)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if len(receipt.Accepted) != 250 || len(receipt.Duplicates) != 0 {
		t.Fatalf("receipt: %d accepted, %d duplicates; want 250, 0", len(receipt.Accepted), len(receipt.Duplicates))
	}
	if reqs := fake.Requests(); len(reqs) != 3 {
		t.Errorf("250 envelopes took %d requests, want 3 (100/100/50)", len(reqs))
	}
	if receipt.Accepted[0].Cursor == "" || receipt.Accepted[0].ID != envs[0].ID {
		t.Errorf("first accepted = %+v, want %s with a cursor", receipt.Accepted[0], envs[0].ID)
	}

	again, err := client.Upload(t.Context(), pairID, envs[:3])
	if err != nil {
		t.Fatalf("Upload again: %v", err)
	}
	if len(again.Accepted) != 0 || len(again.Duplicates) != 3 {
		t.Errorf("re-upload receipt: %d accepted, %d duplicates; want 0, 3", len(again.Accepted), len(again.Duplicates))
	}
	if rows := fake.Rows(pairID, envelope.DirH2P); len(rows) != 250 {
		t.Errorf("mailbox holds %d rows, want 250", len(rows))
	}

	big := []envelope.Envelope{
		mkEnv(t, pairID, envelope.DirH2P, 300, 1500<<10),
		mkEnv(t, pairID, envelope.DirH2P, 301, 1500<<10),
		mkEnv(t, pairID, envelope.DirH2P, 302, 1500<<10),
	}
	before := len(fake.Requests())
	if _, err := client.Upload(t.Context(), pairID, big); err != nil {
		t.Fatalf("Upload big: %v", err)
	}
	if got := len(fake.Requests()) - before; got != 2 {
		t.Errorf("three 1.5 MiB envelopes took %d requests, want 2", got)
	}
}

func TestUploadSerialisesPerPairAndDirection(t *testing.T) {
	t.Parallel()

	fake := relaytest.New()
	t.Cleanup(fake.Close)
	client := newClient(t, fake, newIdentity(t), relay.Options{})
	fake.AddPair(pairID, client.Key(), "phone")
	var wg sync.WaitGroup
	for g := range 4 {
		wg.Go(func() {
			envs := make([]envelope.Envelope, 5)
			for i := range envs {
				envs[i] = mkEnv(t, pairID, envelope.DirH2P, g*10+i, 8)
			}
			if _, err := client.Upload(t.Context(), pairID, envs); err != nil {
				t.Errorf("Upload: %v", err)
			}
		})
	}
	wg.Wait()
	if got := fake.MaxInFlight(pairID, envelope.DirH2P); got != 1 {
		t.Fatalf("max concurrent uploads = %d, want 1", got)
	}
}

func TestUploadRefusals(t *testing.T) {
	t.Parallel()

	fake := relaytest.New()
	t.Cleanup(fake.Close)
	client := newClient(t, fake, newIdentity(t), relay.Options{})
	fake.AddPair(pairID, client.Key(), "phone")
	ctx := t.Context()

	if _, err := client.Upload(ctx, "BBBBBBBBBBBBBBBBBBBBBB", []envelope.Envelope{mkEnv(t, "BBBBBBBBBBBBBBBBBBBBBB", envelope.DirH2P, 1, 8)}); !errors.Is(err, relay.ErrNotFound) {
		t.Errorf("Upload to an unknown pair: err = %v, want ErrNotFound", err)
	}
	if _, err := client.Upload(ctx, pairID, []envelope.Envelope{mkEnv(t, pairID, envelope.DirP2H, 1, 8)}); !errors.Is(err, relay.ErrBadRequest) {
		t.Errorf("Upload in the wrong direction: err = %v, want ErrBadRequest", err)
	}
	before := len(fake.Requests())
	if _, err := client.Upload(ctx, pairID, []envelope.Envelope{mkEnv(t, pairID, envelope.DirH2P, 2, envelope.MaxEnvelopeJSON)}); !errors.Is(err, relay.ErrTooLarge) {
		t.Errorf("Upload over the cap: err = %v, want ErrTooLarge", err)
	}
	if len(fake.Requests()) != before {
		t.Error("an oversize envelope reached the relay; want it refused locally")
	}
	fake.Set(func(f *relaytest.Fake) { f.MailboxFull = true })
	_, err := client.Upload(ctx, pairID, []envelope.Envelope{mkEnv(t, pairID, envelope.DirH2P, 3, 8)})
	if !errors.Is(err, relay.ErrMailboxFull) {
		t.Fatalf("Upload to a full mailbox: err = %v, want ErrMailboxFull", err)
	}
	var serr *relay.StatusError
	if !errors.As(err, &serr) || serr.RetryAfter != time.Second {
		t.Errorf("err = %#v, want RetryAfter 1s", err)
	}
	fake.Set(func(f *relaytest.Fake) { f.MailboxFull = false })
	fake.Revoke(pairID)
	if _, err := client.Upload(ctx, pairID, []envelope.Envelope{mkEnv(t, pairID, envelope.DirH2P, 4, 8)}); !errors.Is(err, relay.ErrRevoked) {
		t.Errorf("Upload to a revoked pair: err = %v, want ErrRevoked", err)
	}
}

func TestStreamResumesAcrossBoundedEndsAndStopsOnRevoke(t *testing.T) {
	t.Parallel()

	fake := relaytest.New()
	t.Cleanup(fake.Close)
	fake.Set(func(f *relaytest.Fake) { f.StreamLimit = 2 })
	client := newClient(t, fake, newIdentity(t), relay.Options{})
	fake.AddPair(pairID, client.Key(), "phone")
	for i := range 3 {
		fake.Inject(mkEnv(t, pairID, envelope.DirP2H, i, 8))
	}

	var got []relay.Event
	err := client.Stream(t.Context(), pairID, "", func(ctx context.Context, ev relay.Event) error {
		got = append(got, ev)
		switch {
		case ev.Kind == relay.EventEnvelope && ev.Cursor == "2":
			if err := client.Ack(ctx, pairID, ev.Cursor); err != nil {
				return err
			}
		case ev.Kind == relay.EventEnvelope && ev.Cursor == "3":
			fake.Revoke(pairID)
		}
		return nil
	})
	if !errors.Is(err, relay.ErrRevoked) {
		t.Fatalf("Stream: err = %v, want ErrRevoked", err)
	}
	var cursors []relay.Cursor
	kinds := make(map[relay.EventKind]int)
	for _, ev := range got {
		kinds[ev.Kind]++
		if ev.Kind == relay.EventEnvelope {
			cursors = append(cursors, ev.Cursor)
			if ev.Envelope == nil || ev.Envelope.Pair != pairID {
				t.Errorf("envelope event %v carries %+v", ev.Cursor, ev.Envelope)
			}
		}
	}
	if len(cursors) != 3 || cursors[0] != "1" || cursors[1] != "2" || cursors[2] != "3" {
		t.Errorf("envelope cursors = %v, want [1 2 3]", cursors)
	}
	if kinds[relay.EventRevoked] != 1 {
		t.Errorf("revoked events = %d, want 1", kinds[relay.EventRevoked])
	}
	if ids := fake.LastEventIDs(); len(ids) != 2 || ids[0] != "" || ids[1] != "2" {
		t.Errorf("Last-Event-ID per connection = %q, want [\"\" \"2\"]", ids)
	}
	if rows := fake.Rows(pairID, envelope.DirP2H); len(rows) != 1 {
		t.Errorf("mailbox holds %d rows after acking 2, want 1", len(rows))
	}
}

func TestStreamDeliversPresence(t *testing.T) {
	t.Parallel()

	fake := relaytest.New()
	t.Cleanup(fake.Close)
	host := newClient(t, fake, newIdentity(t), relay.Options{})
	phone := newClient(t, fake, newIdentity(t), relay.Options{})
	fake.AddPair(pairID, host.Key(), phone.Key())

	phoneCtx, stopPhone := context.WithCancel(t.Context())
	t.Cleanup(stopPhone)
	seen := make(chan relay.Presence, 8)
	hostCtx, stopHost := context.WithCancel(t.Context())
	t.Cleanup(stopHost)
	var wg sync.WaitGroup
	wg.Go(func() {
		_ = host.Stream(hostCtx, pairID, "", func(_ context.Context, ev relay.Event) error {
			if ev.Kind == relay.EventPresence {
				seen <- *ev.Presence
			}
			return nil
		})
	})
	wg.Go(func() {
		_ = phone.Stream(phoneCtx, pairID, "", func(context.Context, relay.Event) error { return nil })
	})
	// Whether the host sees an initial "idle" depends on which stream the
	// fake opened first; what must arrive is connected, then idle once the
	// phone leaves.
	next := func(state string) {
		t.Helper()
		for {
			select {
			case p := <-seen:
				if p.Peer != "phone" || p.At.IsZero() {
					t.Fatalf("presence = %+v, want peer phone with a time", p)
				}
				if p.State == state {
					return
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("presence %q never arrived", state)
			}
		}
	}
	next("connected")
	stopPhone()
	next("idle")
	stopHost()
	wg.Wait()
}

func TestStreamStopsOnHandlerError(t *testing.T) {
	t.Parallel()

	fake := relaytest.New()
	t.Cleanup(fake.Close)
	client := newClient(t, fake, newIdentity(t), relay.Options{})
	fake.AddPair(pairID, client.Key(), "phone")
	fake.Inject(mkEnv(t, pairID, envelope.DirP2H, 1, 8))
	boom := errors.New("apply failed")
	err := client.Stream(t.Context(), pairID, "", func(context.Context, relay.Event) error { return boom })
	if !errors.Is(err, boom) {
		t.Fatalf("Stream: err = %v, want the handler's error", err)
	}
	if reqs := fake.Requests(); len(reqs) != 1 {
		t.Errorf("stream reconnected %d times after a handler error, want none", len(reqs)-1)
	}
}

func TestStreamIdleWatchdogReconnects(t *testing.T) {
	t.Parallel()

	fake := relaytest.New()
	t.Cleanup(fake.Close)
	fake.Set(func(f *relaytest.Fake) { f.Silent = true })
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	rec := &sleeps{cancel: cancel, after: 2}
	client := newClient(t, fake, newIdentity(t), relay.Options{StreamIdleTimeout: 30 * time.Millisecond, Sleep: rec.sleep})
	fake.AddPair(pairID, client.Key(), "phone")
	err := client.Stream(ctx, pairID, "", func(context.Context, relay.Event) error { return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Stream: err = %v, want context.Canceled", err)
	}
	if reqs := fake.Requests(); len(reqs) < 2 {
		t.Errorf("silent stream was opened %d times, want ≥ 2 (the watchdog reconnects)", len(reqs))
	}
	if rec.count() < 2 {
		t.Errorf("backoff sleeps = %d, want ≥ 2", rec.count())
	}
}

func TestStreamRetriesAfterAnOutage(t *testing.T) {
	t.Parallel()

	fake := relaytest.New()
	t.Cleanup(fake.Close)
	fake.Set(func(f *relaytest.Fake) { f.FailNext = 2 })
	rec := &sleeps{}
	client := newClient(t, fake, newIdentity(t), relay.Options{Sleep: rec.sleep, Jitter: func() float64 { return 0 }})
	fake.AddPair(pairID, client.Key(), "phone")
	fake.Inject(mkEnv(t, pairID, envelope.DirP2H, 1, 8))
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	err := client.Stream(ctx, pairID, "", func(context.Context, relay.Event) error {
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Stream: err = %v, want context.Canceled after the event", err)
	}
	if got := rec.waits; len(got) != 2 || got[0] != relay.BackoffInitial/2 || got[1] != relay.BackoffInitial {
		t.Errorf("waits after two 503s = %v, want [%v %v]", got, relay.BackoffInitial/2, relay.BackoffInitial)
	}
}

func TestStreamRefusals(t *testing.T) {
	t.Parallel()

	fake := relaytest.New()
	t.Cleanup(fake.Close)
	client := newClient(t, fake, newIdentity(t), relay.Options{})
	fake.AddPair(pairID, client.Key(), "phone")
	fake.Revoke(pairID)
	nop := func(context.Context, relay.Event) error { return nil }
	if err := client.Stream(t.Context(), pairID, "", nop); !errors.Is(err, relay.ErrRevoked) {
		t.Errorf("Stream on a revoked pair: err = %v, want ErrRevoked", err)
	}
	if err := client.Stream(t.Context(), "BBBBBBBBBBBBBBBBBBBBBB", "", nop); !errors.Is(err, relay.ErrNotFound) {
		t.Errorf("Stream on an unknown pair: err = %v, want ErrNotFound", err)
	}
}

func TestPairingFlow(t *testing.T) {
	t.Parallel()

	fake := relaytest.New()
	t.Cleanup(fake.Close)
	host := newClient(t, fake, newIdentity(t), relay.Options{})
	phoneKeys := newIdentity(t)
	phone := newClient(t, fake, phoneKeys, relay.Options{})
	ctx := t.Context()

	pairing, err := host.MintPairing(ctx)
	if err != nil {
		t.Fatalf("MintPairing: %v", err)
	}
	if got := time.Until(pairing.ExpiresAt); got < 9*time.Minute || got > 11*time.Minute {
		t.Errorf("pairing expires in %v, want ≈ 10 min", got)
	}
	hello := mkEnv(t, pairing.ID, envelope.DirP2H, 1, 64)
	pairID, err := phone.CompletePairing(ctx, pairing.ID, phoneKeys.AgreementPublic(), "fcm-token", hello)
	if err != nil {
		t.Fatalf("CompletePairing: %v", err)
	}
	if pairID != pairing.ID {
		t.Errorf("pairId = %q, want the pairingId %q", pairID, pairing.ID)
	}
	completed, err := host.WaitPairing(ctx, pairing.ID)
	if err != nil {
		t.Fatalf("WaitPairing: %v", err)
	}
	if completed.PairID != pairing.ID || !bytes.Equal(completed.PhonePub, phoneKeys.AgreementPublic()) || completed.Envelope != hello {
		t.Errorf("WaitPairing = %+v, want the phone's completion", completed)
	}
	if _, again := phone.CompletePairing(ctx, pairing.ID, phoneKeys.AgreementPublic(), "fcm-token", hello); !errors.Is(again, relay.ErrPairingUsed) {
		t.Errorf("second CompletePairing: err = %v, want ErrPairingUsed", again)
	}
	other := newClient(t, fake, newIdentity(t), relay.Options{})
	if _, foreign := other.WaitPairing(ctx, pairing.ID); !errors.Is(foreign, relay.ErrNotFound) {
		t.Errorf("WaitPairing by another host: err = %v, want ErrNotFound", foreign)
	}

	stale, err := host.MintPairing(ctx)
	if err != nil {
		t.Fatalf("MintPairing: %v", err)
	}
	fake.Set(func(f *relaytest.Fake) { f.Now = func() time.Time { return time.Now().Add(30 * time.Minute) } })
	// The client's clock must move with the relay's, or every call is a skew 401.
	late := newClient(t, fake, newIdentity(t), relay.Options{Now: func() time.Time { return time.Now().Add(30 * time.Minute) }})
	if _, err := late.CompletePairing(ctx, stale.ID, phoneKeys.AgreementPublic(), "t", mkEnv(t, stale.ID, envelope.DirP2H, 2, 8)); !errors.Is(err, relay.ErrPairingExpired) {
		t.Errorf("CompletePairing after expiry: err = %v, want ErrPairingExpired", err)
	}
}

func TestProxyIsUsed(t *testing.T) {
	t.Parallel()

	fake := relaytest.New()
	t.Cleanup(fake.Close)
	var proxied atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !r.URL.IsAbs() {
			http.Error(w, "not a proxy request", http.StatusBadRequest)
			return
		}
		proxied.Add(1)
		out := r.Clone(r.Context())
		out.RequestURI = ""
		resp, err := http.DefaultTransport.RoundTrip(out)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		maps.Copy(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(mustRead(t, resp))
	}))
	t.Cleanup(proxy.Close)
	proxyURL := mustURL(t, proxy.URL)
	client := newClient(t, fake, newIdentity(t), relay.Options{Proxy: http.ProxyURL(proxyURL)})
	if _, err := client.MintPairing(t.Context()); err != nil {
		t.Fatalf("MintPairing through the proxy: %v", err)
	}
	if proxied.Load() != 1 {
		t.Errorf("proxy saw %d requests, want 1", proxied.Load())
	}
}

func TestRootCAsPinTheRelay(t *testing.T) {
	t.Parallel()

	fake := relaytest.NewTLS()
	t.Cleanup(fake.Close)
	pool := x509.NewCertPool()
	pool.AddCert(fake.Server.Certificate())
	pinned := newClient(t, fake, newIdentity(t), relay.Options{RootCAs: pool})
	if _, err := pinned.MintPairing(t.Context()); err != nil {
		t.Fatalf("MintPairing with the pinned root: %v", err)
	}
	system := newClient(t, fake, newIdentity(t), relay.Options{})
	if _, err := system.MintPairing(t.Context()); err == nil {
		t.Fatal("MintPairing with the system roots against a self-signed relay: want a TLS error")
	}
}

func TestNewRejectsBadBaseURLs(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"relay.claircode.app", "ftp://relay", "https://", "://x"} {
		if _, err := relay.New(newIdentity(t).Auth(), relay.Options{BaseURL: raw}); err == nil {
			t.Errorf("New(%q): want an error", raw)
		}
	}
	if _, err := relay.New(newIdentity(t).Auth(), relay.Options{}); err != nil {
		t.Errorf("New with defaults: %v", err)
	}
}
