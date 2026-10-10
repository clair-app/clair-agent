package tunnel

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
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
	ackErr      error
	cursor      int
	events      chan relay.Event
	streamErr   chan error
	streams     int
	starts      []time.Time
	// calls names every ack, release and revoke in order: "ack 7",
	// "release", "revoke".
	calls     []string
	revokeErr error
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
	f.calls = append(f.calls, "ack "+string(c))
	return f.ackErr
}

func (f *fakeRelay) ReleaseStream(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "release")
	return nil
}

func (f *fakeRelay) Revoke(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "revoke")
	return f.revokeErr
}

// called returns the acks, releases and revokes so far, in order.
func (f *fakeRelay) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// ackCount is how many acks were attempted.
func (f *fakeRelay) ackCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.acks)
}

func (f *fakeRelay) Stream(ctx context.Context, _ string, _ relay.Cursor, h relay.Handler) error {
	f.mu.Lock()
	f.streams++
	f.starts = append(f.starts, time.Now())
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
	dormant  []time.Time
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
			OnDormant: func(_ string, since time.Time) {
				h.mu.Lock()
				defer h.mu.Unlock()
				h.dormant = append(h.dormant, since)
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

// A PostToolBatch closes a prompt the terminal refused with feedback, which
// no PostToolUse follows; it goes out only while a decide is held, since it
// repeats every call's response (ADR 2026-10.ukr9).
func TestPostToolBatchIsQueuedOnlyWhileADecideIsHeld(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, nil)
		defer h.stop(t)
		_ = h.tun.Enqueue(hook("PostToolBatch"), event("PostToolBatch"))
		synctest.Wait()
		var wg sync.WaitGroup
		holdCtx, cancelHold := context.WithCancel(t.Context())
		wg.Go(func() {
			_, _, _ = h.tun.Hold(holdCtx, decide("01ARYZ6S41TSV4RRFFQ69G5FAW"), event("PermissionRequest"), time.Hour)
		})
		synctest.Wait()
		_ = h.tun.Enqueue(hook("PostToolBatch"), event("PostToolBatch"))
		synctest.Wait()
		cancelHold()
		wg.Wait()
		synctest.Wait()
		_ = h.tun.Enqueue(hook("PostToolBatch"), event("PostToolBatch"))
		synctest.Wait()
		envs := h.relay.uploaded()
		// reset, decide, PostToolBatch (held → soon), cancel; neither batch
		// without a hold.
		if len(envs) != 4 {
			t.Fatalf("uploaded %d envelopes, want 4", len(envs))
		}
		if envs[1].Wake != envelope.WakeNow {
			t.Errorf("decide envelope: wake %s, want now", envs[1].Wake)
		}
		if rec := h.phone.open(envs[2]); envs[2].Wake != envelope.WakeSoon || rec.Path != record.PathEvent {
			t.Errorf("PostToolBatch while held: wake %s, record %+v; want a soon event", envs[2].Wake, rec)
		}
		if rec := h.phone.open(envs[3]); rec.Control != record.ControlCancel {
			t.Errorf("after the client left: %+v, want a cancel for the decide", rec)
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
		if elapsed := time.Since(start); elapsed != 5*time.Second-holdMargin {
			t.Errorf("Hold returned after %v, want the 5s timeout less the margin", elapsed)
		}
		// The phone is told the decide expired, not that the terminal took it.
		synctest.Wait()
		recs, _ := records(t, h)
		if c := recs[len(recs)-1]; c.Control != record.ControlCancel || c.ReqID != "01ARYZ6S41TSV4RRFFQ69G5FAV" || c.Reason != record.CancelTimeout {
			t.Errorf("last record = %+v, want cancel (timeout) for the decide", c)
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

// A decide whose envelope the relay refuses never reaches the phone; its
// hook is answered at once instead of at its timeout (AG-17).
func TestRelayRefusedDecideAnswersAtOnce(t *testing.T) {
	t.Parallel()
	for _, refusal := range []error{relay.ErrTooLarge, relay.ErrBadRequest} {
		t.Run(refusal.Error(), func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				h := newHarness(t, nil)
				defer h.stop(t)
				h.relay.setUploadErr(fmt.Errorf("fake: %w", refusal), false)
				got := make(chan bool, 1)
				go func() {
					_, ok, _ := h.tun.Hold(t.Context(), decide("01ARYZ6S41TSV4RRFFQ69G5FAV"), event("PermissionRequest"), time.Hour)
					got <- ok
				}()
				synctest.Wait()
				select {
				case ok := <-got:
					if ok {
						t.Error("a refused decide answered ok, want no decision")
					}
				default:
					t.Fatal("the refused decide is still held, want it answered at once")
				}
				if st := h.tun.Snapshot(); st[0].Held != 0 || st[0].QueueRecords != 0 {
					t.Errorf("after the refusal: %d held, %d queued; want 0, 0", st[0].Held, st[0].QueueRecords)
				}
			})
		})
	}
}

// An ack cursor the relay refuses is dropped rather than resent every
// second for good (AG-18).
func TestRefusedAckIsNotRetried(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, nil)
		defer h.stop(t)
		h.relay.mu.Lock()
		h.relay.ackErr = fmt.Errorf("fake: %w", relay.ErrBadRequest)
		h.relay.mu.Unlock()
		h.relay.events <- relay.Event{Kind: relay.EventPresence, Cursor: "5", Presence: &relay.Presence{Peer: "phone", State: "connected"}}
		h.relay.events <- relay.Event{Kind: relay.EventEnvelope, Cursor: "6", Envelope: new(h.phone.seal(record.Record{Kind: record.KindControl, Control: record.ControlPolicy}))}
		synctest.Wait()
		time.Sleep(10 * ackInterval)
		synctest.Wait()
		h.relay.mu.Lock()
		acks := h.relay.acks
		h.relay.mu.Unlock()
		if len(acks) != 1 || acks[0] != "6" {
			t.Errorf("acks = %v, want [6] once", acks)
		}
	})
}

// The receiver's backoff starts over after a stream that held up, so an
// occasional failure does not creep toward the cap (AG-18).
func TestReceiverBackoffResetsAfterAHealthyStream(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, nil)
		defer h.stop(t)
		fail := func() {
			h.relay.streamErr <- errors.New("relay down")
			synctest.Wait()
		}
		// Each of the first three streams fails the moment it opens.
		for i := range 3 {
			fail()
			time.Sleep(backoff(i))
			synctest.Wait()
		}
		time.Sleep(2 * streamHealthy)
		fail()
		time.Sleep(backoffMax)
		synctest.Wait()
		h.relay.mu.Lock()
		starts := h.relay.starts
		h.relay.mu.Unlock()
		if len(starts) != 5 {
			t.Fatalf("%d stream opens, want 5", len(starts))
		}
		// Opens 1-3 failed at once, so each waited longer than the one before.
		for i, want := range []time.Duration{backoff(0), backoff(1), backoff(2)} {
			if got := starts[i+1].Sub(starts[i]); got != want {
				t.Errorf("wait before open %d = %v, want %v", i+2, got, want)
			}
		}
		// Open 4 held for two minutes; the wait after it is the first again.
		if got := starts[4].Sub(starts[3]) - 2*streamHealthy; got != backoff(0) {
			t.Errorf("wait after a healthy stream = %v, want %v", got, backoff(0))
		}
	})
}

// The phone's own sealed revoke record ends the pair at once.
func TestPhoneRevokeReleasesHoldsAndNotifiesOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, nil)
		defer h.stop(t)
		got := make(chan bool, 1)
		go func() {
			_, ok, _ := h.tun.Hold(t.Context(), decide("01ARYZ6S41TSV4RRFFQ69G5FAV"), event("PermissionRequest"), time.Hour)
			got <- ok
		}()
		synctest.Wait()
		revoke := h.phone.seal(record.Record{Kind: record.KindControl, Control: record.ControlRevoke})
		h.relay.events <- relay.Event{Kind: relay.EventEnvelope, Cursor: "1", Envelope: &revoke}
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
		// The record is acked, then the pair deleted at the relay too; an
		// ended pair has no stream to release.
		if got := h.relay.called(); !slices.Equal(got, []string{"ack 1", "revoke"}) {
			t.Errorf("relay calls after the revoke = %q, want the ack, then the DELETE", got)
		}
	})
}

// Whatever the relay says about a pair being gone is unauthenticated: the
// pair is parked — its holds answered, its hooks skipped — but nothing is
// deleted, and the start is recorded for the grace period (AG-3).
func TestRelayReportedRevokeParksThePair(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name   string
		report func(h *harness)
		reason string
	}{
		{"event revoked", func(h *harness) { h.relay.events <- relay.Event{Kind: relay.EventRevoked} }, "the relay reports the pair revoked"},
		{"stream 410", func(h *harness) { h.relay.streamErr <- relay.ErrRevoked }, "the relay reports the pair revoked"},
		{"stream 404 pair_not_found", func(h *harness) { h.relay.streamErr <- relay.ErrPairNotFound }, "the relay does not know the pair"},
		{"upload 410", func(h *harness) {
			h.relay.setUploadErr(relay.ErrRevoked, false)
			_ = h.tun.Enqueue(hook("Stop"), event("Stop"))
		}, "the relay reports the pair revoked"},
		{"upload 404 pair_not_found", func(h *harness) {
			h.relay.setUploadErr(relay.ErrPairNotFound, false)
			_ = h.tun.Enqueue(hook("Stop"), event("Stop"))
		}, "the relay does not know the pair"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				h := newHarness(t, nil)
				defer h.stop(t)
				got := make(chan bool, 1)
				go func() {
					_, ok, _ := h.tun.Hold(t.Context(), decide("01ARYZ6S41TSV4RRFFQ69G5FAV"), event("PermissionRequest"), time.Hour)
					got <- ok
				}()
				synctest.Wait()
				start := time.Now()
				tt.report(h)
				synctest.Wait()
				select {
				case ok := <-got:
					if ok {
						t.Error("a held decide answered ok, want no decision")
					}
				default:
					t.Fatal("the held decide is still held after the relay reported the pair gone")
				}
				h.mu.Lock()
				revoked, dormant := h.revoked, h.dormant
				h.mu.Unlock()
				if len(revoked) != 0 {
					t.Errorf("OnRevoked = %v, want nothing deleted on the relay's word", revoked)
				}
				if len(dormant) != 1 || !dormant[0].Equal(start) {
					t.Errorf("OnDormant = %v, want once with %v", dormant, start)
				}
				st := h.tun.Snapshot()
				if len(st) != 1 || st[0].Dormant == nil || st[0].Dormant.Reason != tt.reason || !st[0].Dormant.DeleteAfter.Equal(start.Add(dormantGrace)) {
					t.Fatalf("Snapshot = %+v, want the pair dormant: %s", st, tt.reason)
				}
				if err := h.tun.Enqueue(hook("Stop"), event("Stop")); !errors.Is(err, ErrNoPair) {
					t.Errorf("Enqueue while dormant: %v, want ErrNoPair", err)
				}
				if _, ok, _ := h.tun.Hold(t.Context(), decide("01ARYZ6S41TSV4RRFFQ69G5FAW"), event("PermissionRequest"), time.Hour); ok {
					t.Error("a decide while dormant answered ok, want no decision at once")
				}
			})
		})
	}
}

// A 404 the relay did not answer itself — an edge's, a proxy's, Vercel's
// DEPLOYMENT_NOT_FOUND mid-deploy — says nothing about the pair: it is a
// failure like any other, retried with backoff, and parks nothing.
func TestAnEdgeNotFoundParksNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, nil)
		defer h.stop(t)
		h.relay.streamErr <- relay.ErrNotFound
		h.relay.setUploadErr(relay.ErrNotFound, true)
		_ = h.tun.Enqueue(hook("Stop"), event("Stop"))
		synctest.Wait()
		st := h.tun.Snapshot()
		if len(st) != 1 || st[0].Dormant != nil || st[0].Stream.State != "backoff" || st[0].Uploader.State != "backoff" {
			t.Fatalf("Snapshot = %+v, want the pair live with both links backing off", st)
		}
		time.Sleep(backoffInitial)
		synctest.Wait()
		h.mu.Lock()
		dormant := h.dormant
		h.mu.Unlock()
		if len(dormant) != 0 {
			t.Errorf("OnDormant = %v, want nothing persisted", dormant)
		}
		if st := h.tun.Snapshot(); st[0].QueueRecords != 0 || h.relay.streams != 2 {
			t.Errorf("after the backoff: %d queued, %d stream opens; want the retry delivered and the stream reopened", st[0].QueueRecords, h.relay.streams)
		}
	})
}

// parkByRelay has the relay report the pair revoked, and keep refusing its
// uploads, as the relay does for a revoked pair.
func (h *harness) parkByRelay() {
	h.relay.setUploadErr(relay.ErrRevoked, false)
	h.relay.streamErr <- relay.ErrRevoked
	synctest.Wait()
}

// A parked pair the relay serves again is not resumed by the stream alone:
// its presence queues a reset, and only once the relay takes it do hooks
// reach the pair again and the recorded start go.
func TestParkedPairResumesOnceTheRelayTakesItsReset(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, nil)
		defer h.stop(t)
		h.parkByRelay()
		before := len(h.relay.uploaded())
		h.relay.setUploadErr(nil, false)
		time.Sleep(dormantRecheckMin)
		synctest.Wait()
		h.relay.events <- relay.Event{Kind: relay.EventPresence, Presence: &relay.Presence{Peer: "phone", State: "connected"}}
		synctest.Wait()
		if st := h.tun.Snapshot(); st[0].Dormant != nil || st[0].Stream.State != "connected" {
			t.Fatalf("after the relay took the reset: dormant %+v, stream %q; want resumed and connected", st[0].Dormant, st[0].Stream.State)
		}
		h.mu.Lock()
		dormant := h.dormant
		h.mu.Unlock()
		if len(dormant) != 2 || !dormant[1].IsZero() {
			t.Errorf("OnDormant = %v, want a start then a clear", dormant)
		}
		envs := h.relay.uploaded()[before:]
		if len(envs) != 1 || h.phone.open(envs[0]).Control != record.ControlReset {
			t.Errorf("after resuming uploaded %d envelopes, want one reset", len(envs))
		}
		// A second presence on the live pair queues nothing.
		h.relay.events <- relay.Event{Kind: relay.EventPresence, Presence: &relay.Presence{Peer: "phone", State: "idle"}}
		synctest.Wait()
		if err := h.tun.Enqueue(hook("Stop"), event("Stop")); err != nil {
			t.Errorf("Enqueue after resuming: %v", err)
		}
		synctest.Wait()
		if envs := h.relay.uploaded()[before:]; len(envs) != 2 || h.phone.open(envs[1]).Kind != record.KindRequest {
			t.Errorf("after the hook uploaded %d envelopes, want the reset and the hook", len(envs))
		}
	})
}

// The phone unpairs: the relay drains the phone's sealed revoke to the
// parked host — presence, the record, then `revoked` — and still refuses
// the host's uploads. The pair ends on the record without resuming in
// between: no reset reaches the phone, the parked start is not reset, and
// the trailing `revoked` changes nothing. The relay is told too (RELAY.md
// r9 §6.6).
func TestDrainedRevokeEndsAParkedPairCleanly(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, nil)
		defer h.stop(t)
		h.parkByRelay()
		before := len(h.relay.uploaded())
		time.Sleep(dormantRecheckMin)
		synctest.Wait()
		h.relay.events <- relay.Event{Kind: relay.EventPresence, Presence: &relay.Presence{Peer: "phone", State: "idle"}}
		synctest.Wait()
		if st := h.tun.Snapshot(); len(st) != 1 || st[0].Dormant == nil {
			t.Fatalf("Snapshot = %+v, want the pair still parked while the relay refuses its reset", st)
		}
		policy := h.phone.seal(record.Record{Kind: record.KindControl, Control: record.ControlPolicy})
		h.relay.events <- relay.Event{Kind: relay.EventEnvelope, Cursor: "4", Envelope: &policy}
		revoke := h.phone.seal(record.Record{Kind: record.KindControl, Control: record.ControlRevoke})
		h.relay.events <- relay.Event{Kind: relay.EventEnvelope, Cursor: "5", Envelope: &revoke}
		h.relay.events <- relay.Event{Kind: relay.EventRevoked, Cursor: "5"}
		synctest.Wait()
		h.mu.Lock()
		revoked, dormant := h.revoked, h.dormant
		h.mu.Unlock()
		if len(revoked) != 1 || revoked[0] != pairID+": revoked by the phone" {
			t.Errorf("OnRevoked = %v, want once, by the phone", revoked)
		}
		if len(dormant) != 1 {
			t.Errorf("OnDormant = %v, want only the first report's start", dormant)
		}
		if got := h.relay.uploaded()[before:]; len(got) != 0 {
			t.Errorf("the relay took %d envelopes from the parked pair, want none", len(got))
		}
		calls := h.relay.called()
		if len(calls) == 0 || calls[len(calls)-1] != "revoke" || slices.Contains(calls, "release") || !slices.Contains(calls, "ack 5") {
			t.Errorf("relay calls = %q, want the drained rows acked, then the DELETE, and no release", calls)
		}
		if st := h.tun.Snapshot(); len(st) != 0 {
			t.Errorf("Snapshot = %+v, want the pair gone", st)
		}
	})
}

// An ack the relay fails is retried with backoff, not every second; one it
// will never take — a pair it reports gone — is dropped; and parking drops
// whatever was pending (a failed ack once went on every second for a week).
func TestAckBacksOffAndDropsWhatTheRelayWillNotTake(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name  string
		err   error
		park  bool
		acks  int
		after time.Duration
	}{
		{"a failure is retried with backoff", errors.New("relay down"), false, 4, 10 * time.Second},
		{"a revoked pair's is dropped", relay.ErrRevoked, false, 1, 10 * time.Second},
		{"an unknown pair's is dropped", relay.ErrPairNotFound, false, 1, 10 * time.Second},
		{"an edge 404 is retried with backoff", relay.ErrNotFound, false, 4, 10 * time.Second},
		{"parking drops it", errors.New("relay down"), true, 1, 10 * time.Second},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				h := newHarness(t, nil)
				defer h.stop(t)
				h.relay.mu.Lock()
				h.relay.ackErr = tt.err
				h.relay.mu.Unlock()
				env := h.phone.seal(record.Record{Kind: record.KindControl, Control: record.ControlPolicy})
				h.relay.events <- relay.Event{Kind: relay.EventEnvelope, Cursor: "6", Envelope: &env}
				synctest.Wait()
				if tt.park {
					h.relay.streamErr <- relay.ErrRevoked
					synctest.Wait()
				}
				time.Sleep(tt.after)
				synctest.Wait()
				// At 0 s, then after 1, 2 and 4 s of backoff: 4 in 10 s.
				if got := h.relay.ackCount(); got != tt.acks {
					t.Errorf("%d acks in %v, want %d", got, tt.after, tt.acks)
				}
			})
		})
	}
}

// The grace counts from the start the pair file recorded, across restarts:
// a report that has held for longer ends the pair; a younger one parks it
// without resetting its start; an upload the relay takes forgets it.
func TestDormantGraceCountsFromThePersistedStart(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		age     time.Duration
		served  bool
		revoked bool
	}{
		{"past the grace", dormantGrace + time.Hour, false, true},
		{"within the grace", dormantGrace - time.Hour, false, false},
		{"contradicted by an accepted upload", dormantGrace + time.Hour, true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				since := time.Now().Add(-tt.age)
				h := newHarness(t, func(c *PairConfig) {
					c.RelayRevokedAt = since
					if !tt.served {
						// The relay still refuses it: the start's reset is not taken.
						c.Relay.(*fakeRelay).setUploadErr(relay.ErrRevoked, false)
					}
				})
				defer h.stop(t)
				h.mu.Lock()
				revoked, dormant := h.revoked, h.dormant
				h.mu.Unlock()
				if got := len(revoked) == 1; got != tt.revoked {
					t.Errorf("OnRevoked = %v, want revoked: %t", revoked, tt.revoked)
				}
				st := h.tun.Snapshot()
				switch {
				case tt.served:
					if len(dormant) != 1 || !dormant[0].IsZero() || len(st) != 1 || st[0].Dormant != nil {
						t.Errorf("OnDormant = %v, Snapshot = %+v; want the start cleared and the pair live", dormant, st)
					}
				case tt.revoked:
					if len(dormant) != 0 || len(st) != 0 {
						t.Errorf("OnDormant = %v, Snapshot = %+v; want the start left alone and the pair gone", dormant, st)
					}
				default:
					if len(dormant) != 0 || len(st) != 1 || st[0].Dormant == nil || !st[0].Dormant.Since.Equal(since) {
						t.Errorf("OnDormant = %v, Snapshot = %+v; want the pair dormant since %v", dormant, st, since)
					}
				}
			})
		})
	}
}

// A pair that stops — the daemon stopping, or letting it go — releases its
// stream at the relay, so the phone sees the host leave at once; a parked
// pair has none to release.
func TestStoppingReleasesTheStream(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t, nil)
		other, parked := newFakeRelay(), newFakeRelay()
		parked.streamErr <- relay.ErrRevoked
		const otherID, parkedID = "BBBBBBBBBBBBBBBBBBBBBB", "CCCCCCCCCCCCCCCCCCCCCC"
		h.tun.SetPairs([]PairConfig{
			{ID: pairID, Keys: h.phone.keys, Relay: h.relay},
			{ID: otherID, Keys: h.phone.keys, Relay: other},
			{ID: parkedID, Keys: h.phone.keys, Relay: parked},
		})
		synctest.Wait()
		h.tun.SetPairs([]PairConfig{{ID: pairID}, {ID: parkedID}})
		if got := other.called(); !slices.Equal(got, []string{"release"}) {
			t.Errorf("the pair let go: relay calls = %q by the time SetPairs returned, want the release", got)
		}
		h.stop(t)
		if got := h.relay.called(); !slices.Equal(got, []string{"release"}) {
			t.Errorf("on stop: relay calls = %q, want the release", got)
		}
		if got := parked.called(); len(got) != 0 {
			t.Errorf("the parked pair on stop: relay calls = %q, want none", got)
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
		// Drain releases the hold; the goroutine holding it still has to run to
		// report that.
		synctest.Wait()
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
