package tunnel

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"claircode.app/clair-agent/internal/envelope"
	"claircode.app/clair-agent/internal/record"
	"claircode.app/clair-agent/internal/relay"
)

const pairID = "AAAAAAAAAAAAAAAAAAAAAA"

// fakeRelay is an in-memory relay: uploads are recorded, the stream delivers
// whatever the test pushes. No network, so it may live inside a synctest bubble.
type fakeRelay struct {
	mu          sync.Mutex
	uploads     [][]envelope.Envelope
	uploadErr   error
	errOnce     bool
	inflight    int
	maxInflight int
	acks        []relay.Cursor
	cursor      int
	events      chan relay.Event
	streamErr   chan error
	streams     int
}

func newFakeRelay() *fakeRelay {
	return &fakeRelay{events: make(chan relay.Event, 64), streamErr: make(chan error, 1)}
}

func (f *fakeRelay) Upload(_ context.Context, pair string, envs []envelope.Envelope) (relay.Receipt, error) {
	f.mu.Lock()
	f.inflight++
	f.maxInflight = max(f.maxInflight, f.inflight)
	err := f.uploadErr
	if f.errOnce {
		f.uploadErr, f.errOnce = nil, false
	}
	f.mu.Unlock()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inflight--
	if err != nil {
		return relay.Receipt{}, err
	}
	var receipt relay.Receipt
	for _, e := range envs {
		if e.Pair != pair {
			return receipt, errors.New("fake relay: wrong pair")
		}
		f.cursor++
		receipt.Accepted = append(receipt.Accepted, relay.Accepted{ID: e.ID, Cursor: relay.Cursor(strconv.Itoa(f.cursor)), TTLSec: e.TTLSec})
	}
	f.uploads = append(f.uploads, envs)
	return receipt, nil
}

func (f *fakeRelay) Ack(_ context.Context, _ string, c relay.Cursor) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acks = append(f.acks, c)
	return nil
}

func (f *fakeRelay) Stream(ctx context.Context, _ string, _ relay.Cursor, h relay.Handler) error {
	f.mu.Lock()
	f.streams++
	f.mu.Unlock()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev := <-f.events:
			if err := h(ctx, ev); err != nil {
				return err
			}
		case err := <-f.streamErr:
			return err
		}
	}
}

func (*fakeRelay) Skew() time.Duration { return 0 }

// uploaded flattens every upload so far.
func (f *fakeRelay) uploaded() []envelope.Envelope {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []envelope.Envelope
	for _, batch := range f.uploads {
		out = append(out, batch...)
	}
	return out
}

func (f *fakeRelay) setUploadErr(err error, once bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.uploadErr, f.errOnce = err, once
}

type fakeCounters struct {
	mu       sync.Mutex
	reserved map[string][]uint64
	p2h      map[string]uint64
	cleared  []string
}

func newFakeCounters() *fakeCounters {
	return &fakeCounters{reserved: make(map[string][]uint64), p2h: make(map[string]uint64)}
}

func (c *fakeCounters) ReserveH2P(id string, limit uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reserved[id] = append(c.reserved[id], limit)
	return nil
}

func (c *fakeCounters) SaveP2HLast(id string, n uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.p2h[id] = max(c.p2h[id], n)
	return nil
}

func (c *fakeCounters) ClearPendingHelloAck(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleared = append(c.cleared, id)
	return nil
}

// phone is the far end: it opens h2p envelopes and seals p2h ones.
type phone struct {
	t    *testing.T
	keys *envelope.Keys
	n    uint64
}

func newPhone(t *testing.T) *phone {
	t.Helper()
	host, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ph, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := envelope.Derive(ph, host.PublicKey().Bytes(), bytes.Repeat([]byte{3}, 16))
	if err != nil {
		t.Fatal(err)
	}
	return &phone{t: t, keys: keys}
}

func (p *phone) open(env envelope.Envelope) *record.Record {
	p.t.Helper()
	if err := env.Validate(pairID, envelope.DirH2P); err != nil {
		p.t.Fatalf("phone: envelope invalid: %v", err)
	}
	plain, err := envelope.Open(p.keys.Key(envelope.DirH2P), env)
	if err != nil {
		p.t.Fatalf("phone: open: %v", err)
	}
	rec, err := record.Unmarshal(plain)
	if err != nil {
		p.t.Fatalf("phone: record: %v", err)
	}
	return rec
}

func (p *phone) seal(rec record.Record) envelope.Envelope {
	p.t.Helper()
	p.n++
	rec.N = p.n
	plain, err := record.Marshal(&rec)
	if err != nil {
		p.t.Fatal(err)
	}
	id, err := envelope.NewID(time.Now(), bytes.NewReader(bytes.Repeat([]byte{byte(p.n)}, 10)))
	if err != nil {
		p.t.Fatal(err)
	}
	env, err := envelope.Seal(p.keys.Key(envelope.DirP2H), envelope.Header{Pair: pairID, ID: id, Dir: envelope.DirP2H, Wake: envelope.WakeSoon, TTLSec: 60}, plain, bytes.NewReader(bytes.Repeat([]byte{byte(p.n)}, 24)))
	if err != nil {
		p.t.Fatal(err)
	}
	return env
}

// harness runs one tunnel with one pair inside a synctest bubble.
type harness struct {
	tun      *Tunnel
	relay    *fakeRelay
	counters *fakeCounters
	phone    *phone
	cancel   context.CancelFunc
	done     chan error
	mu       sync.Mutex
	revoked  []string
	snippets [][]byte
	presence []bool
	policies []record.Presence
}

func newHarness(t *testing.T, mod func(*PairConfig)) *harness {
	t.Helper()
	return newHarnessWith(t, nil, mod)
}

// newHarnessWith is newHarness with the tunnel's options adjusted first.
func newHarnessWith(t *testing.T, opts func(*Options), mod func(*PairConfig)) *harness {
	t.Helper()
	h := &harness{relay: newFakeRelay(), counters: newFakeCounters(), phone: newPhone(t), done: make(chan error, 1)}
	options := Options{
		Counters: h.counters,
		Entropy:  &counting{},
		Hooks: Hooks{
			OnRevoked: func(id, reason string) {
				h.mu.Lock()
				defer h.mu.Unlock()
				h.revoked = append(h.revoked, id+": "+reason)
			},
			OnSnippet: func(_ string, s json.RawMessage) {
				h.mu.Lock()
				defer h.mu.Unlock()
				h.snippets = append(h.snippets, s)
			},
			OnPresence: func(_ string, connected bool, _ time.Time) {
				h.mu.Lock()
				defer h.mu.Unlock()
				h.presence = append(h.presence, connected)
			},
			OnPolicy: func(_ string, policy record.Presence) {
				h.mu.Lock()
				defer h.mu.Unlock()
				h.policies = append(h.policies, policy)
			},
		},
	}
	if opts != nil {
		opts(&options)
	}
	h.tun = New(options)
	ctx, cancel := context.WithCancel(t.Context())
	h.cancel = cancel
	go func() { h.done <- h.tun.Run(ctx) }()
	cfg := PairConfig{ID: pairID, Keys: h.phone.keys, Relay: h.relay, PhoneName: "Pixel", Hostname: "walter-laptop", AgentVersion: "v0"}
	if mod != nil {
		mod(&cfg)
	}
	synctest.Wait()
	h.tun.SetPairs([]PairConfig{cfg})
	synctest.Wait()
	return h
}

func (h *harness) stop(t *testing.T) {
	t.Helper()
	h.cancel()
	if err := <-h.done; err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// counting is deterministic entropy.
type counting struct {
	mu sync.Mutex
	n  byte
}

func (c *counting) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range p {
		p[i] = c.n
		c.n++
	}
	return len(p), nil
}

func hook(event string) record.Record {
	return record.Record{Kind: record.KindRequest, ReqID: "01ARYZ6S41TSV4RRFFQ69G5F" + fmt.Sprintf("%02d", len(event)%100), Path: record.PathEvent, Body: json.RawMessage(`{"session_id":"s","hook_event_name":"` + event + `"}`)}
}

// event is the loopback's reading of a hook with the given name.
func event(name string) record.Hook { return record.Hook{Event: name} }

func decide(reqID string) record.Record {
	return record.Record{Kind: record.KindRequest, ReqID: reqID, Path: record.PathDecide, Query: map[string]string{"timeout": "300"}, Body: json.RawMessage(`{"session_id":"s","hook_event_name":"PermissionRequest"}`)}
}

func TestStartSendsResetAfterAPendingHelloAck(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, func(c *PairConfig) { c.PendingHelloAck = true })
		defer h.stop(t)
		envs := h.relay.uploaded()
		if len(envs) != 2 {
			t.Fatalf("uploaded %d envelopes at start, want hello-ack and reset", len(envs))
		}
		first, second := h.phone.open(envs[0]), h.phone.open(envs[1])
		if first.Control != record.ControlHelloAck || first.Hostname != "walter-laptop" || first.AgentVersion != "v0" || first.N != 1 {
			t.Errorf("first record = %+v, want hello-ack n=1 from walter-laptop", first)
		}
		if second.Control != record.ControlReset || second.N != 2 {
			t.Errorf("second record = %+v, want reset n=2", second)
		}
		if envs[0].Wake != envelope.WakeSoon || envs[1].Wake != envelope.WakeSoon {
			t.Errorf("control wakes = %s, %s; want soon", envs[0].Wake, envs[1].Wake)
		}
		if len(h.counters.cleared) != 1 {
			t.Errorf("hello-ack cleared %d times, want once", len(h.counters.cleared))
		}
		if got := h.counters.reserved[pairID]; len(got) != 1 || got[0] != 1+envelope.CounterBlock {
			t.Errorf("reserved limits = %v, want [%d]", got, 1+envelope.CounterBlock)
		}
	})
}

func TestFIFOOrderWakesAndCounters(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, nil)
		defer h.stop(t)
		for _, ev := range []string{"SessionStart", "PreToolUse", "PostToolUse", "Stop"} {
			if err := h.tun.Enqueue(hook(ev), event(ev)); err != nil {
				t.Fatalf("Enqueue(%s): %v", ev, err)
			}
		}
		synctest.Wait()
		envs := h.relay.uploaded()
		if len(envs) != 5 { // reset + four hooks
			t.Fatalf("uploaded %d envelopes, want 5", len(envs))
		}
		wantWake := []envelope.Wake{envelope.WakeSoon, envelope.WakeSoon, envelope.WakeNo, envelope.WakeNo, envelope.WakeSoon}
		var lastN uint64
		for i, env := range envs {
			if env.Wake != wantWake[i] {
				t.Errorf("envelope %d wake = %s, want %s", i, env.Wake, wantWake[i])
			}
			if env.TTLSec != record.TTL(env.Wake, 0) {
				t.Errorf("envelope %d ttl = %d, want %d", i, env.TTLSec, record.TTL(env.Wake, 0))
			}
			rec := h.phone.open(env)
			if rec.N <= lastN {
				t.Errorf("envelope %d n = %d, not above %d", i, rec.N, lastN)
			}
			lastN = rec.N
			if i > 0 && !bytes.Equal(rec.Body, hook("x").Body[:0]) && rec.Kind != record.KindRequest {
				t.Errorf("envelope %d is not a request", i)
			}
		}
		if h.relay.maxInflight != 1 {
			t.Errorf("max uploads in flight = %d, want 1", h.relay.maxInflight)
		}
		if st := h.tun.Snapshot(); len(st) != 1 || st[0].QueueRecords != 0 || st[0].Uploader.State != "idle" {
			t.Errorf("status = %+v, want an empty queue and an idle uploader", st)
		}
	})
}

func TestSheddingOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, nil)
		defer h.stop(t)
		// The relay is down from here on, so the queue only grows.
		h.relay.setUploadErr(errors.New("relay down"), false)
		h.tun.opts.MaxRecords = 3
		p := h.tun.livePairs()[0]
		hold := newHold(false)
		wakes := func() []envelope.Wake {
			p.mu.Lock()
			defer p.mu.Unlock()
			out := make([]envelope.Wake, len(p.queue))
			for i, it := range p.queue {
				out[i] = it.wake
			}
			return out
		}
		want := func(step string, expect ...envelope.Wake) {
			t.Helper()
			got := wakes()
			if len(got) != len(expect) {
				t.Fatalf("%s: queue wakes = %v, want %v", step, got, expect)
			}
			for i := range got {
				if got[i] != expect[i] {
					t.Fatalf("%s: queue wakes = %v, want %v", step, got, expect)
				}
			}
		}
		newDecide := func(id string) {
			p.register(id, hold)
			_ = p.enqueue(decide(id), envelope.WakeNow, record.TTL(envelope.WakeNow, time.Second))
		}
		_ = h.tun.Enqueue(hook("PreToolUse"), event("PreToolUse"))
		_ = h.tun.Enqueue(hook("UserPromptSubmit"), event("UserPromptSubmit"))
		newDecide("01ARYZ6S41TSV4RRFFQ69G5FA1")
		want("three fit", envelope.WakeNo, envelope.WakeSoon, envelope.WakeNow)
		_ = h.tun.Enqueue(hook("Stop"), event("Stop"))
		want("a soon sheds the oldest no", envelope.WakeSoon, envelope.WakeNow, envelope.WakeSoon)
		newDecide("01ARYZ6S41TSV4RRFFQ69G5FA2")
		want("a now sheds the oldest soon", envelope.WakeNow, envelope.WakeSoon, envelope.WakeNow)
		newDecide("01ARYZ6S41TSV4RRFFQ69G5FA3")
		want("another now sheds the last soon", envelope.WakeNow, envelope.WakeNow, envelope.WakeNow)
		_ = h.tun.Enqueue(hook("PreToolUse"), event("PreToolUse"))
		want("a no with only nows queued is dropped", envelope.WakeNow, envelope.WakeNow, envelope.WakeNow)
		newDecide("01ARYZ6S41TSV4RRFFQ69G5FA4")
		want("a now is never dropped", envelope.WakeNow, envelope.WakeNow, envelope.WakeNow, envelope.WakeNow)
		p.abortHolds()
	})
}

func TestPostToolUseIsSoonWhileADecideIsHeld(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, nil)
		defer h.stop(t)
		var wg sync.WaitGroup
		holdCtx, cancelHold := context.WithCancel(t.Context())
		wg.Go(func() {
			_, _, _ = h.tun.Hold(holdCtx, decide("01ARYZ6S41TSV4RRFFQ69G5FAV"), event("PermissionRequest"), time.Hour)
		})
		synctest.Wait()
		_ = h.tun.Enqueue(hook("PostToolUse"), event("PostToolUse"))
		synctest.Wait()
		cancelHold()
		wg.Wait()
		synctest.Wait()
		_ = h.tun.Enqueue(hook("PostToolUse"), event("PostToolUse"))
		synctest.Wait()
		envs := h.relay.uploaded()
		// reset, decide, PostToolUse (held → soon), cancel, PostToolUse (no).
		if len(envs) != 5 {
			t.Fatalf("uploaded %d envelopes, want 5", len(envs))
		}
		if envs[1].Wake != envelope.WakeNow || envs[1].TTLSec != 3600 {
			t.Errorf("decide envelope = wake %s ttl %d, want now/3600", envs[1].Wake, envs[1].TTLSec)
		}
		if envs[2].Wake != envelope.WakeSoon {
			t.Errorf("PostToolUse while held: wake %s, want soon", envs[2].Wake)
		}
		if rec := h.phone.open(envs[3]); rec.Control != record.ControlCancel || rec.ReqID != "01ARYZ6S41TSV4RRFFQ69G5FAV" {
			t.Errorf("after the client left: %+v, want a cancel for the decide", rec)
		}
		if envs[4].Wake != envelope.WakeNo {
			t.Errorf("PostToolUse after release: wake %s, want no", envs[4].Wake)
		}
	})
}

func TestHoldIsResolvedByTheResponse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, nil)
		defer h.stop(t)
		type result struct {
			resp record.Record
			ok   bool
			err  error
		}
		got := make(chan result, 1)
		go func() {
			resp, ok, err := h.tun.Hold(t.Context(), decide("01ARYZ6S41TSV4RRFFQ69G5FAV"), event("PermissionRequest"), time.Hour)
			got <- result{resp, ok, err}
		}()
		synctest.Wait()
		envs := h.relay.uploaded()
		if len(envs) != 2 {
			t.Fatalf("uploaded %d envelopes, want reset and the decide", len(envs))
		}
		req := h.phone.open(envs[1])
		if req.Path != record.PathDecide || req.Query["timeout"] != "300" {
			t.Fatalf("decide record = %+v", req)
		}
		output := json.RawMessage(`{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}`)
		env := h.phone.seal(record.Record{Kind: record.KindResponse, ReqID: req.ReqID, Status: 200, Body: output})
		h.relay.events <- relay.Event{Kind: relay.EventEnvelope, Cursor: "7", Envelope: &env}
		synctest.Wait()
		select {
		case r := <-got:
			if r.err != nil || !r.ok || r.resp.Status != 200 || !bytes.Equal(r.resp.Body, output) {
				t.Fatalf("Hold = %+v", r)
			}
		default:
			t.Fatal("Hold did not return after the response")
		}
		// The same response again is a replay (n repeats) and a late response
		// (the hold is gone); both are dropped quietly.
		h.relay.events <- relay.Event{Kind: relay.EventEnvelope, Cursor: "8", Envelope: &env}
		late := h.phone.seal(record.Record{Kind: record.KindResponse, ReqID: req.ReqID, Status: 204})
		h.relay.events <- relay.Event{Kind: relay.EventEnvelope, Cursor: "9", Envelope: &late}
		time.Sleep(ackInterval + time.Millisecond)
		synctest.Wait()
		h.relay.mu.Lock()
		acks := h.relay.acks
		h.relay.mu.Unlock()
		if len(acks) == 0 || acks[len(acks)-1] != "9" {
			t.Errorf("acks = %v, want the highest applied cursor 9 last", acks)
		}
		if st := h.tun.Snapshot(); st[0].Held != 0 {
			t.Errorf("held = %d after the response, want 0", st[0].Held)
		}
	})
}

func TestHoldExpiresAtTheDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, nil)
		defer h.stop(t)
		start := time.Now()
		_, ok, err := h.tun.Hold(t.Context(), decide("01ARYZ6S41TSV4RRFFQ69G5FAV"), event("PermissionRequest"), 5*time.Second)
		if err != nil || ok {
			t.Fatalf("Hold = ok %v, err %v; want no decision", ok, err)
		}
		if elapsed := time.Since(start); elapsed != 5*time.Second {
			t.Errorf("Hold returned after %v, want the 5s deadline", elapsed)
		}
	})
}

func TestOversizeRecordIsDroppedAndDecideAnswersAtOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, nil)
		defer h.stop(t)
		big := decide("01ARYZ6S41TSV4RRFFQ69G5FAV")
		big.Body = json.RawMessage(`{"session_id":"s","hook_event_name":"PermissionRequest","pad":"` + string(bytes.Repeat([]byte("x"), envelope.MaxRecordBytes)) + `"}`)
		start := time.Now()
		_, ok, err := h.tun.Hold(t.Context(), big, event("PermissionRequest"), time.Hour)
		if err != nil || ok || time.Since(start) != 0 {
			t.Fatalf("Hold of an oversize decide = ok %v, err %v after %v; want no decision at once", ok, err, time.Since(start))
		}
		if err := h.tun.Enqueue(big, event("PreToolUse")); err != nil {
			t.Fatalf("Enqueue of an oversize event: %v, want it dropped quietly", err)
		}
		synctest.Wait()
		if envs := h.relay.uploaded(); len(envs) != 1 {
			t.Errorf("uploaded %d envelopes, want only the reset", len(envs))
		}
	})
}

func TestNoPair(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tun := New(Options{Counters: newFakeCounters(), Entropy: &counting{}})
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- tun.Run(ctx) }()
		synctest.Wait()
		if err := tun.Enqueue(hook("Stop"), event("Stop")); !errors.Is(err, ErrNoPair) {
			t.Errorf("Enqueue with no pair: err = %v, want ErrNoPair", err)
		}
		if _, ok, err := tun.Hold(t.Context(), decide("01ARYZ6S41TSV4RRFFQ69G5FAV"), event("PermissionRequest"), time.Hour); ok || err != nil {
			t.Errorf("Hold with no pair = ok %v, err %v; want no decision at once", ok, err)
		}
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
}

func TestReplayIsDroppedAndHighWaterPersisted(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, func(c *PairConfig) { c.P2HLast = 5 })
		defer h.stop(t)
		h.phone.n = 5
		snippet := h.phone.seal(record.Record{Kind: record.KindControl, Control: record.ControlSnippet, Snippet: json.RawMessage(`{"hooks":{}}`)}) // n = 6
		replay := snippet
		h.relay.events <- relay.Event{Kind: relay.EventEnvelope, Cursor: "1", Envelope: &snippet}
		h.relay.events <- relay.Event{Kind: relay.EventEnvelope, Cursor: "2", Envelope: &replay}
		stale := h.phone
		stale.n = 2
		old := stale.seal(record.Record{Kind: record.KindControl, Control: record.ControlSnippet, Snippet: json.RawMessage(`{"hooks":{"x":1}}`)}) // n = 3 ≤ 6
		h.relay.events <- relay.Event{Kind: relay.EventEnvelope, Cursor: "3", Envelope: &old}
		synctest.Wait()
		h.mu.Lock()
		snippets := len(h.snippets)
		h.mu.Unlock()
		if snippets != 1 {
			t.Fatalf("OnSnippet fired %d times, want once (replays dropped)", snippets)
		}
		time.Sleep(counterFlushInterval + time.Second)
		h.phone.n = 6
		fresh := h.phone.seal(record.Record{Kind: record.KindControl, Control: record.ControlReset}) // n = 7, ignored but accepted
		h.relay.events <- relay.Event{Kind: relay.EventEnvelope, Cursor: "4", Envelope: &fresh}
		synctest.Wait()
		h.counters.mu.Lock()
		persisted := h.counters.p2h[pairID]
		h.counters.mu.Unlock()
		if persisted != 7 {
			t.Errorf("persisted p2hLast = %d, want 7", persisted)
		}
	})
}

func TestUploadRetriesAfterAFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, nil)
		defer h.stop(t)
		h.relay.setUploadErr(errors.New("relay down"), true)
		_ = h.tun.Enqueue(hook("Stop"), event("Stop"))
		synctest.Wait()
		if st := h.tun.Snapshot(); st[0].Uploader.State != "backoff" || st[0].QueueRecords == 0 {
			t.Fatalf("status after a failed upload = %+v, want backoff with a queue", st[0])
		}
		time.Sleep(backoffInitial)
		synctest.Wait()
		if envs := h.relay.uploaded(); len(envs) == 0 {
			t.Fatal("nothing uploaded after the backoff")
		}
		if st := h.tun.Snapshot(); st[0].QueueRecords != 0 || st[0].Uploader.State != "idle" {
			t.Errorf("status after the retry = %+v, want empty and idle", st[0])
		}
	})
}

func TestRelayTooLargeDropsALoneEnvelope(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, nil)
		defer h.stop(t)
		h.relay.setUploadErr(fmt.Errorf("fake: %w", relay.ErrTooLarge), false)
		_ = h.tun.Enqueue(hook("Stop"), event("Stop"))
		synctest.Wait()
		// A 413 is not retried: the queue empties by dropping.
		if st := h.tun.Snapshot(); st[0].QueueRecords != 0 {
			t.Errorf("queue after 413s = %d records, want 0", st[0].QueueRecords)
		}
	})
}

func TestRevokeReleasesHoldsAndNotifiesOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, nil)
		defer h.stop(t)
		got := make(chan bool, 1)
		go func() {
			_, ok, _ := h.tun.Hold(t.Context(), decide("01ARYZ6S41TSV4RRFFQ69G5FAV"), event("PermissionRequest"), time.Hour)
			got <- ok
		}()
		synctest.Wait()
		h.relay.events <- relay.Event{Kind: relay.EventRevoked}
		synctest.Wait()
		select {
		case ok := <-got:
			if ok {
				t.Error("a held decide answered ok after a revoke, want no decision")
			}
		default:
			t.Fatal("the held decide was not released by the revoke")
		}
		h.mu.Lock()
		revoked := h.revoked
		h.mu.Unlock()
		if len(revoked) != 1 || revoked[0] != pairID+": revoked by the phone" {
			t.Errorf("OnRevoked = %v, want once with the reason", revoked)
		}
		if st := h.tun.Snapshot(); len(st) != 0 || h.tun.Unpaired() == "" {
			t.Errorf("after the revoke: %d pairs, unpaired %q", len(st), h.tun.Unpaired())
		}
		if err := h.tun.Enqueue(hook("Stop"), event("Stop")); !errors.Is(err, ErrNoPair) {
			t.Errorf("Enqueue after the revoke: %v, want ErrNoPair", err)
		}
	})
}

func TestRelayRefusalRevokes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, nil)
		defer h.stop(t)
		h.relay.streamErr <- relay.ErrRevoked
		synctest.Wait()
		h.mu.Lock()
		revoked := len(h.revoked)
		h.mu.Unlock()
		if revoked != 1 {
			t.Fatalf("OnRevoked fired %d times after a 410 stream, want once", revoked)
		}
	})
}

func TestSetPairsStartsAndStops(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, nil)
		defer h.stop(t)
		other := newFakeRelay()
		h.tun.SetPairs([]PairConfig{
			{ID: pairID, Keys: h.phone.keys, Relay: h.relay},
			{ID: "BBBBBBBBBBBBBBBBBBBBBB", Keys: h.phone.keys, Relay: other},
		})
		synctest.Wait()
		if st := h.tun.Snapshot(); len(st) != 2 {
			t.Fatalf("pairs = %d, want 2", len(st))
		}
		got := make(chan bool, 1)
		go func() {
			_, ok, _ := h.tun.Hold(t.Context(), decide("01ARYZ6S41TSV4RRFFQ69G5FAV"), event("PermissionRequest"), time.Hour)
			got <- ok
		}()
		synctest.Wait()
		if len(other.uploaded()) != 2 || len(h.relay.uploaded()) != 2 {
			t.Errorf("fan-out: pair A got %d, pair B got %d; want reset + decide each", len(h.relay.uploaded()), len(other.uploaded()))
		}
		h.tun.SetPairs([]PairConfig{{ID: "BBBBBBBBBBBBBBBBBBBBBB", Keys: h.phone.keys, Relay: other}})
		synctest.Wait()
		if st := h.tun.Snapshot(); len(st) != 1 || st[0].PairID != "BBBBBBBBBBBBBBBBBBBBBB" {
			t.Fatalf("pairs after removal = %+v, want only B", st)
		}
		select {
		case <-got:
			t.Fatal("the hold resolved although pair B still holds it")
		default:
		}
		h.tun.SetPairs(nil)
		synctest.Wait()
		select {
		case ok := <-got:
			if ok {
				t.Error("hold answered ok after every pair stopped")
			}
		default:
			t.Fatal("removing the last pair did not release the hold")
		}
	})
}

func TestDrainReleasesHoldsAndFlushesQueues(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, nil)
		defer h.stop(t)
		got := make(chan bool, 1)
		go func() {
			_, ok, _ := h.tun.Hold(t.Context(), decide("01ARYZ6S41TSV4RRFFQ69G5FAV"), event("PermissionRequest"), time.Hour)
			got <- ok
		}()
		synctest.Wait()
		drainCtx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		h.tun.Drain(drainCtx)
		select {
		case ok := <-got:
			if ok {
				t.Error("Drain answered a hold ok, want no decision")
			}
		default:
			t.Fatal("Drain did not release the hold")
		}
		envs := h.relay.uploaded()
		if len(envs) != 3 {
			t.Fatalf("uploaded %d envelopes after Drain, want reset, decide and cancel", len(envs))
		}
		if rec := h.phone.open(envs[2]); rec.Control != record.ControlCancel {
			t.Errorf("last record = %+v, want the cancel", rec)
		}
	})
}

func TestPresenceIsReported(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, nil)
		defer h.stop(t)
		h.relay.events <- relay.Event{Kind: relay.EventPresence, Presence: &relay.Presence{Peer: "phone", State: "connected", At: time.Now()}}
		h.relay.events <- relay.Event{Kind: relay.EventPresence, Presence: &relay.Presence{Peer: "host", State: "idle", At: time.Now()}}
		h.relay.events <- relay.Event{Kind: relay.EventPresence, Presence: &relay.Presence{Peer: "phone", State: "idle", At: time.Now()}}
		synctest.Wait()
		h.mu.Lock()
		presence := h.presence
		h.mu.Unlock()
		if len(presence) != 2 || !presence[0] || presence[1] {
			t.Errorf("OnPresence = %v, want [true false] (host presence ignored)", presence)
		}
		if st := h.tun.Snapshot(); st[0].Phone != "idle" || st[0].PhoneSeenAt.IsZero() {
			t.Errorf("status phone = %q at %v, want idle with a time", st[0].Phone, st[0].PhoneSeenAt)
		}
	})
}

func TestBackoff(t *testing.T) {
	t.Parallel()

	if backoff(0) != backoffInitial || backoff(1) != 2*backoffInitial || backoff(10) != backoffMax {
		t.Errorf("backoff = %v %v %v", backoff(0), backoff(1), backoff(10))
	}
}
