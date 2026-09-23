package relay_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"claircode.app/clair-agent/internal/envelope"
	"claircode.app/clair-agent/internal/relay"
	"claircode.app/clair-agent/internal/relay/relaytest"
)

// The signed-request rules of ADR 2026-09.n68c, against a fake that enforces
// canonical v2 as the relay does with AUTH_NONCE=required.

func TestEveryRequestCarriesAFreshNonceAndTheHost(t *testing.T) {
	t.Parallel()

	fake := relaytest.New()
	t.Cleanup(fake.Close)
	hostKeys, phoneKeys := newIdentity(t), newIdentity(t)
	host := newClient(t, fake, hostKeys, relay.Options{})
	phone := newClient(t, fake, phoneKeys, relay.Options{})
	ctx := t.Context()

	pairing, err := host.MintPairing(ctx)
	if err != nil {
		t.Fatalf("MintPairing: %v", err)
	}
	pair, err := phone.CompletePairing(ctx, pairing.ID, phoneKeys.AgreementPublic(), "fcm-token", mkEnv(t, pairing.ID, envelope.DirP2H, 1, 8))
	if err != nil {
		t.Fatalf("CompletePairing: %v", err)
	}
	if _, err = host.WaitPairing(ctx, pairing.ID); err != nil {
		t.Fatalf("WaitPairing: %v", err)
	}
	if _, err = host.Upload(ctx, pair, []envelope.Envelope{mkEnv(t, pair, envelope.DirH2P, 2, 8)}); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	err = phone.Stream(ctx, pair, "", func(ctx context.Context, ev relay.Event) error {
		if ev.Kind != relay.EventEnvelope {
			return nil
		}
		if ackErr := phone.Ack(ctx, pair, ev.Cursor); ackErr != nil {
			return ackErr
		}
		return host.Revoke(ctx, pair)
	})
	if !errors.Is(err, relay.ErrRevoked) {
		t.Fatalf("Stream: err = %v, want ErrRevoked", err)
	}

	wantHost := mustURL(t, fake.URL).Host
	seen := make(map[string]bool)
	for _, r := range fake.Requests() {
		if r.Status/100 != 2 {
			t.Errorf("%s %s answered %d, want every request verified", r.Method, r.RequestURI, r.Status)
		}
		if r.Nonce == "" || seen[r.Nonce] {
			t.Errorf("%s %s: nonce %q, want a fresh one on every request", r.Method, r.RequestURI, r.Nonce)
		}
		seen[r.Nonce] = true
		if r.Host != wantHost {
			t.Errorf("%s %s: Host %q, want %q", r.Method, r.RequestURI, r.Host, wantHost)
		}
	}
	if len(seen) < 7 {
		t.Errorf("%d requests seen, want mint, complete, wait, upload, events, ack and revoke", len(seen))
	}
}

func TestReplayIsResignedAndRetriedOnce(t *testing.T) {
	t.Parallel()

	calls := []struct {
		name string
		// setup prepares the relay; call is the one operation under test.
		setup func(t *testing.T, fake *relaytest.Fake, host, phone *relay.Client) string
		call  func(ctx context.Context, host *relay.Client, id string) error
	}{
		{
			name:  "mint",
			setup: func(*testing.T, *relaytest.Fake, *relay.Client, *relay.Client) string { return "" },
			call: func(ctx context.Context, host *relay.Client, _ string) error {
				_, err := host.MintPairing(ctx)
				return err
			},
		},
		{
			name: "ack",
			setup: func(_ *testing.T, fake *relaytest.Fake, host, phone *relay.Client) string {
				fake.AddPair(pairID, host.Key(), phone.Key())
				return pairID
			},
			call: func(ctx context.Context, host *relay.Client, id string) error { return host.Ack(ctx, id, "0") },
		},
		{
			name: "stream open",
			setup: func(t *testing.T, fake *relaytest.Fake, host, phone *relay.Client) string {
				t.Helper()
				fake.AddPair(pairID, host.Key(), phone.Key())
				fake.Inject(mkEnv(t, pairID, envelope.DirP2H, 1, 8))
				return pairID
			},
			call: func(ctx context.Context, host *relay.Client, id string) error {
				ctx, cancel := context.WithCancel(ctx)
				defer cancel()
				err := host.Stream(ctx, id, "", func(_ context.Context, ev relay.Event) error {
					if ev.Kind == relay.EventEnvelope {
						cancel()
					}
					return nil
				})
				if errors.Is(err, context.Canceled) {
					return nil
				}
				return err
			},
		},
		{
			name: "pairing wait",
			setup: func(t *testing.T, _ *relaytest.Fake, host, phone *relay.Client) string {
				t.Helper()
				p, err := host.MintPairing(t.Context())
				if err != nil {
					t.Fatalf("MintPairing: %v", err)
				}
				if _, err = phone.CompletePairing(t.Context(), p.ID, make([]byte, envelope.KeySize), "fcm-token", mkEnv(t, p.ID, envelope.DirP2H, 1, 8)); err != nil {
					t.Fatalf("CompletePairing: %v", err)
				}
				return p.ID
			},
			call: func(ctx context.Context, host *relay.Client, id string) error {
				_, err := host.WaitPairing(ctx, id)
				return err
			},
		},
	}
	for _, c := range calls {
		for _, replays := range []int{1, 2} {
			name := c.name + "/once"
			if replays == 2 {
				name = c.name + "/twice"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				fake := relaytest.New()
				t.Cleanup(fake.Close)
				var s sleeps
				host := newClient(t, fake, newIdentity(t), relay.Options{Sleep: s.sleep})
				phone := newClient(t, fake, newIdentity(t), relay.Options{Sleep: s.sleep})
				id := c.setup(t, fake, host, phone)
				before := len(fake.Requests())
				fake.Set(func(f *relaytest.Fake) { f.ReplayNext = replays })

				err := c.call(t.Context(), host, id)
				reqs := fake.Requests()[before:]
				if len(reqs) != 2 {
					t.Fatalf("requests = %+v, want exactly 2: the refused one and one re-signed retry", reqs)
				}
				if reqs[0].Status != http.StatusUnauthorized || reqs[0].Nonce == "" || reqs[1].Nonce == reqs[0].Nonce {
					t.Errorf("requests = %+v, want a 401 then a retry with a fresh nonce", reqs)
				}
				if replays == 1 {
					if err != nil || reqs[1].Status/100 != 2 {
						t.Errorf("after one replay: err = %v, retry answered %d; want success", err, reqs[1].Status)
					}
					return
				}
				serr, ok := errors.AsType[*relay.StatusError](err)
				if !errors.Is(err, relay.ErrUnauthorized) || !ok || serr.Reason != "replay" {
					t.Errorf("after two replays: err = %v, want ErrUnauthorized with reason replay, surfaced not retried", err)
				}
			})
		}
	}
}

func TestSupersededStreamReconnectsWithLastEventID(t *testing.T) {
	t.Parallel()

	fake := relaytest.New()
	t.Cleanup(fake.Close)
	keys := newIdentity(t)
	var s sleeps
	client := newClient(t, fake, keys, relay.Options{Sleep: s.sleep})
	fake.AddPair(pairID, client.Key(), "phone")
	fake.Inject(mkEnv(t, pairID, envelope.DirP2H, 1, 8))
	second := mkEnv(t, pairID, envelope.DirP2H, 2, 8)
	raw := rawCaller{t: t, base: fake.URL}
	path := "/v1/pairs/" + pairID + "/events"

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	// A second stream for the host's side, as a racing reconnect or a
	// second agent would open: it takes the side over and ends ours.
	otherEnded := make(chan error, 1)
	openOther := func() {
		req := raw.build(http.MethodGet, path, "", nil, "")
		req.Header.Set("Authorization", raw.sign(keys, http.MethodGet, req.Host, path, nil))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			otherEnded <- err
			return
		}
		_, err = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		otherEnded <- err
	}
	var cursors []relay.Cursor
	err := client.Stream(ctx, pairID, "", func(_ context.Context, ev relay.Event) error {
		if ev.Kind != relay.EventEnvelope {
			return nil
		}
		cursors = append(cursors, ev.Cursor)
		switch ev.Cursor {
		case "1":
			go openOther()
			go func() {
				// Once our stream is back, the next envelope must reach it.
				for len(fake.LastEventIDs()) < 3 && ctx.Err() == nil {
					time.Sleep(time.Millisecond)
				}
				fake.Inject(second)
			}()
		case "2":
			cancel()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Stream: err = %v, want context.Canceled after the second envelope", err)
	}
	if len(cursors) != 2 || cursors[0] != "1" || cursors[1] != "2" {
		t.Errorf("cursors = %v, want [1 2]", cursors)
	}
	if ids := fake.LastEventIDs(); len(ids) != 3 || ids[0] != "" || ids[1] != "" || ids[2] != "1" {
		t.Errorf("Last-Event-ID per connection = %q, want ours, the other one, then ours resuming from 1", ids)
	}
	if len(s.waits) == 0 || s.waits[0] != relay.DefaultRetry {
		t.Errorf("waits = %v, want the clean end's %v first, not a backoff", s.waits, relay.DefaultRetry)
	}
	// Our reconnect took the side back, so the other stream ended too: the
	// relay never lets two live streams share one side.
	select {
	case err := <-otherEnded:
		if err != nil {
			t.Errorf("the other stream: %v, want a quiet end", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("the other stream is still open after ours reconnected")
	}
}

func TestEdgeRateLimitIsBackedOff(t *testing.T) {
	t.Parallel()

	t.Run("unary", func(t *testing.T) {
		t.Parallel()
		fake := relaytest.New()
		t.Cleanup(fake.Close)
		client := newClient(t, fake, newIdentity(t), relay.Options{})
		fake.Set(func(f *relaytest.Fake) { f.EdgeLimitNext = 1 })
		_, err := client.MintPairing(t.Context())
		serr, ok := errors.AsType[*relay.StatusError](err)
		if !errors.Is(err, relay.ErrRateLimited) || !ok || serr.Code != "" || serr.RetryAfter != 0 {
			t.Errorf("MintPairing: err = %#v, want ErrRateLimited with no code and no Retry-After", err)
		}
		if n := len(fake.Requests()); n != 1 {
			t.Errorf("requests = %d, want 1: a 429 is the caller's to back off, not retried here", n)
		}
	})
	t.Run("stream", func(t *testing.T) {
		t.Parallel()
		fake := relaytest.New()
		t.Cleanup(fake.Close)
		var s sleeps
		client := newClient(t, fake, newIdentity(t), relay.Options{Sleep: s.sleep, Jitter: func() float64 { return 0 }})
		fake.AddPair(pairID, client.Key(), "phone")
		fake.Inject(mkEnv(t, pairID, envelope.DirP2H, 1, 8))
		fake.Set(func(f *relaytest.Fake) { f.EdgeLimitNext = 1 })
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)
		err := client.Stream(ctx, pairID, "", func(_ context.Context, ev relay.Event) error {
			if ev.Kind == relay.EventEnvelope {
				cancel()
			}
			return nil
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Stream: err = %v, want context.Canceled after the envelope", err)
		}
		if len(s.waits) != 1 || s.waits[0] != relay.BackoffInitial/2 {
			t.Errorf("waits = %v, want one backoff of %v", s.waits, relay.BackoffInitial/2)
		}
	})
}
