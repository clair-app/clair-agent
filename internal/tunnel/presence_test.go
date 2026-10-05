package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"claircode.app/clair-agent/internal/envelope"
	"claircode.app/clair-agent/internal/presence"
	"claircode.app/clair-agent/internal/record"
	"claircode.app/clair-agent/internal/relay"
)

// fakePresence is a sampler the test moves by hand.
type fakePresence struct {
	mu     sync.Mutex
	sample presence.Sample
	reads  int
}

func (f *fakePresence) Sample() presence.Sample {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	return f.sample
}

func (f *fakePresence) set(idle time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sample = presence.Sample{Idle: idle, Known: true, Source: "fake"}
}

func (f *fakePresence) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reads
}

// presenceHarness runs a tunnel with a fake sampler and a phone threshold.
func presenceHarness(t *testing.T, idle, threshold time.Duration) (*harness, *fakePresence) {
	t.Helper()
	sampler := &fakePresence{}
	sampler.set(idle)
	h := newHarnessWith(t, func(o *Options) { o.Presence = sampler }, func(c *PairConfig) { c.IdleThreshold = threshold })
	return h, sampler
}

// bubbled is a background subagent's decide as the loopback reads it.
func bubbled() record.Hook { return record.Hook{Event: "PermissionRequest", Mode: record.ModeBubble} }

type holdResult struct {
	resp record.Record
	ok   bool
	err  error
}

// startHold runs an hour-long Hold on its own goroutine and returns its
// result channel.
func startHold(ctx context.Context, h *harness, req record.Record, hook record.Hook) chan holdResult {
	got := make(chan holdResult, 1)
	go func() {
		resp, ok, err := h.tun.Hold(ctx, req, hook, time.Hour)
		got <- holdResult{resp, ok, err}
	}()
	return got
}

// records opens every uploaded envelope after the reset, in order.
func records(t *testing.T, h *harness) ([]*record.Record, []envelope.Envelope) {
	t.Helper()
	envs := h.relay.uploaded()
	if len(envs) == 0 {
		t.Fatal("nothing uploaded")
	}
	out := make([]*record.Record, 0, len(envs)-1)
	for _, env := range envs[1:] {
		out = append(out, h.phone.open(env))
	}
	return out, envs[1:]
}

func TestBubbledDecideIsReleasedAtOnceWhileSomeoneIsAtTheTerminal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h, _ := presenceHarness(t, 5*time.Second, presence.DefaultThreshold)
		defer h.stop(t)
		got := startHold(t.Context(), h, decide("01ARYZ6S41TSV4RRFFQ69G5FAV"), bubbled())
		synctest.Wait()
		select {
		case r := <-got:
			if r.err != nil || r.ok {
				t.Fatalf("Hold = %+v, want no decision at once", r)
			}
		default:
			t.Fatal("Hold blocked on a bubbled decide with someone at the terminal")
		}
		recs, envs := records(t, h)
		if len(recs) != 2 {
			t.Fatalf("uploaded %d records after reset, want the request and its cancel", len(recs))
		}
		if req := recs[0]; req.Path != record.PathDecide || req.Headers[record.IdleHeader] != "5000" || envs[0].Wake != envelope.WakeSoon {
			t.Errorf("request = %+v (wake %s), want the decide with X-Clair-Idle-Ms 5000 as soon", req, envs[0].Wake)
		}
		if c := recs[1]; c.Control != record.ControlCancel || c.ReqID != "01ARYZ6S41TSV4RRFFQ69G5FAV" || c.Reason != record.CancelTerminal {
			t.Errorf("cancel = %+v, want reason terminal", c)
		}
		if st := h.tun.Snapshot(); st[0].Held != 0 || st[0].IdleThresholdSec != 120 {
			t.Errorf("status = %+v, want nothing held and the default threshold", st[0])
		}
	})
}

func TestBubbledDecideHeldWhileAwayIsReleasedWhenTheyReturn(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h, sampler := presenceHarness(t, 10*time.Minute, presence.DefaultThreshold)
		defer h.stop(t)
		got := startHold(t.Context(), h, decide("01ARYZ6S41TSV4RRFFQ69G5FAV"), bubbled())
		synctest.Wait()
		select {
		case r := <-got:
			t.Fatalf("Hold returned %+v with nobody at the terminal, want it held", r)
		default:
		}
		recs, envs := records(t, h)
		if len(recs) != 1 || envs[0].Wake != envelope.WakeNow {
			t.Fatalf("uploaded %v, want the held decide as now", recs)
		}
		// Still away after a few polls: nothing changes, nothing is sent.
		time.Sleep(3 * presencePoll)
		synctest.Wait()
		if again, _ := records(t, h); len(again) != 1 {
			t.Fatalf("uploaded %d records while still away, want 1", len(again))
		}
		// Someone comes back to a terminal: the next poll hands the prompt over.
		sampler.set(2 * time.Second)
		time.Sleep(presencePoll)
		synctest.Wait()
		select {
		case r := <-got:
			if r.err != nil || r.ok {
				t.Fatalf("Hold = %+v, want no decision", r)
			}
		default:
			t.Fatal("Hold still blocked after someone returned")
		}
		recs, envs = records(t, h)
		if len(recs) != 3 {
			t.Fatalf("uploaded %d records, want request, presence, cancel: %+v", len(recs), recs)
		}
		if pr := recs[1]; pr.Path != record.PathPresence || string(pr.Body) != `{"idleMs":2000}` || pr.Headers[record.IdleHeader] != "2000" || envs[1].Wake != envelope.WakeNow {
			t.Errorf("presence = %+v (wake %s), want /hook/presence idleMs 2000 as now", pr, envs[1].Wake)
		}
		if c := recs[2]; c.Control != record.ControlCancel || c.Reason != record.CancelTerminal {
			t.Errorf("cancel = %+v, want reason terminal", c)
		}
		if st := h.tun.Snapshot(); st[0].Held != 0 {
			t.Errorf("held = %d after the release, want 0", st[0].Held)
		}
	})
}

// A subagent's decide is bubbled whatever the session's mode, in an
// interactive session or one whose hooks block predates the entrypoint header
// (ADR 2026-10.gw8w): released at once while someone is there, held while
// nobody is and released when they return.
func TestSubagentDecideIsReleasedWhateverItsMode(t *testing.T) {
	for _, hook := range []record.Hook{
		{Event: "PermissionRequest", Mode: "auto", Subagent: true},
		{Event: "PermissionRequest", Mode: "auto", Subagent: true, Entrypoint: record.EntrypointCLI},
		{Event: "PermissionRequest", Mode: "acceptEdits", Subagent: true, Entrypoint: record.EntrypointCLI},
	} {
		t.Run(hook.Mode+"/"+hook.Entrypoint, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h, sampler := presenceHarness(t, 5*time.Second, presence.DefaultThreshold)
				defer h.stop(t)
				got := startHold(t.Context(), h, decide("01ARYZ6S41TSV4RRFFQ69G5FAV"), hook)
				synctest.Wait()
				select {
				case r := <-got:
					if r.err != nil || r.ok {
						t.Fatalf("Hold = %+v, want no decision at once", r)
					}
				default:
					t.Fatal("Hold blocked on a subagent's decide with someone at the terminal")
				}
				recs, envs := records(t, h)
				if len(recs) != 2 || envs[0].Wake != envelope.WakeSoon || recs[1].Control != record.ControlCancel || recs[1].Reason != record.CancelTerminal {
					t.Fatalf("uploaded %+v, want the decide as soon and a cancel (terminal)", recs)
				}

				// Nobody there: held, then released when someone returns.
				sampler.set(10 * time.Minute)
				got = startHold(t.Context(), h, decide("01ARYZ6S41TSV4RRFFQ69G5FAW"), hook)
				synctest.Wait()
				select {
				case r := <-got:
					t.Fatalf("Hold returned %+v with nobody at the terminal, want it held", r)
				default:
				}
				sampler.set(2 * time.Second)
				time.Sleep(presencePoll)
				synctest.Wait()
				select {
				case r := <-got:
					if r.err != nil || r.ok {
						t.Fatalf("Hold = %+v, want no decision", r)
					}
				default:
					t.Fatal("Hold still blocked after someone returned")
				}
				if recs, _ := records(t, h); recs[len(recs)-1].Control != record.ControlCancel || recs[len(recs)-1].Reason != record.CancelTerminal {
					t.Errorf("last record = %+v, want a cancel (terminal)", recs[len(recs)-1])
				}
			})
		})
	}
}

// Outside an interactive session nothing draws a dialog once the hook
// returns — `claude -p` denies the tool — so a subagent's decide, even a
// bubble one, is held like the main agent's while someone is there, and
// the watcher never releases it (ADR 2026-10.gw8w).
func TestNonInteractiveSubagentDecideIsHeldWhileSomeoneIsThere(t *testing.T) {
	for _, hook := range []record.Hook{
		{Event: "PermissionRequest", Mode: "default", Subagent: true, Entrypoint: "sdk-cli"},
		{Event: "PermissionRequest", Mode: record.ModeBubble, Subagent: true, Entrypoint: "sdk-cli"},
		{Event: "PermissionRequest", Mode: "auto", Subagent: true, Entrypoint: "claude-vscode"},
	} {
		t.Run(hook.Mode+"/"+hook.Entrypoint, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h, sampler := presenceHarness(t, 5*time.Second, presence.DefaultThreshold)
				defer h.stop(t)
				got := startHold(t.Context(), h, decide("01ARYZ6S41TSV4RRFFQ69G5FAV"), hook)
				synctest.Wait()
				// Away and back: reported, never released.
				sampler.set(time.Hour)
				time.Sleep(presencePoll)
				synctest.Wait()
				sampler.set(time.Second)
				time.Sleep(presencePoll)
				synctest.Wait()
				select {
				case r := <-got:
					t.Fatalf("Hold returned %+v, want it held for the phone", r)
				default:
				}
				recs, envs := records(t, h)
				if len(recs) != 3 || envs[0].Wake != envelope.WakeNow || recs[1].Path != record.PathPresence || recs[2].Path != record.PathPresence {
					t.Fatalf("uploaded %+v, want the decide as now and two presence records, no cancel", recs)
				}
				env := h.phone.seal(record.Record{Kind: record.KindResponse, ReqID: "01ARYZ6S41TSV4RRFFQ69G5FAV", Status: 204})
				h.relay.events <- relay.Event{Kind: relay.EventEnvelope, Cursor: "1", Envelope: &env}
				synctest.Wait()
				if r := <-got; r.err != nil || !r.ok || r.resp.Status != 204 {
					t.Fatalf("Hold = %+v, want the phone's 204", r)
				}
			})
		})
	}
}

func TestPresenceChangeIsReportedOnlyWhileADecideIsHeld(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h, sampler := presenceHarness(t, 5*time.Second, presence.DefaultThreshold)
		defer h.stop(t)
		// Nothing held: flips are not even sampled.
		sampler.set(time.Hour)
		time.Sleep(3 * presencePoll)
		synctest.Wait()
		if n := sampler.count(); n != 0 {
			t.Errorf("sampled %d times with nothing held, want 0", n)
		}
		sampler.set(5 * time.Second)
		// A main-agent prompt is held whoever is there; leaving makes it buzz.
		got := startHold(t.Context(), h, decide("01ARYZ6S41TSV4RRFFQ69G5FAV"), event("PermissionRequest"))
		synctest.Wait()
		sampler.set(time.Hour)
		time.Sleep(presencePoll)
		synctest.Wait()
		recs, envs := records(t, h)
		if len(recs) != 2 || recs[1].Path != record.PathPresence || envs[1].Wake != envelope.WakeNow {
			t.Fatalf("uploaded %+v, want the decide then a presence record as now", recs)
		}
		select {
		case r := <-got:
			t.Fatalf("a main-agent hold returned %+v on a presence change", r)
		default:
		}
		// Coming back is reported too, and the hold stays.
		sampler.set(time.Second)
		time.Sleep(presencePoll)
		synctest.Wait()
		if recs, _ := records(t, h); len(recs) != 3 || recs[2].Path != record.PathPresence || string(recs[2].Body) != `{"idleMs":1000}` {
			t.Fatalf("uploaded %+v, want a second presence record", recs)
		}
		// The phone answers; after that, flips are quiet again.
		env := h.phone.seal(record.Record{Kind: record.KindResponse, ReqID: "01ARYZ6S41TSV4RRFFQ69G5FAV", Status: 204})
		h.relay.events <- relay.Event{Kind: relay.EventEnvelope, Cursor: "1", Envelope: &env}
		synctest.Wait()
		if r := <-got; r.err != nil || !r.ok || r.resp.Status != 204 {
			t.Fatalf("Hold = %+v, want the phone's 204", r)
		}
		sampler.set(time.Hour)
		time.Sleep(2 * presencePoll)
		synctest.Wait()
		if recs, _ := records(t, h); len(recs) != 3 {
			t.Errorf("uploaded %d records after the answer, want no more presence", len(recs))
		}
	})
}

func TestBubbledDecideIsHeldWithoutASignalOrWithTheRuleOff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// No sampler: nothing is stamped and nothing released.
		h := newHarness(t, nil)
		got := startHold(t.Context(), h, decide("01ARYZ6S41TSV4RRFFQ69G5FAV"), bubbled())
		synctest.Wait()
		select {
		case r := <-got:
			t.Fatalf("Hold without a sampler returned %+v", r)
		default:
		}
		if recs, _ := records(t, h); len(recs) != 1 || recs[0].Headers[record.IdleHeader] != "" {
			t.Errorf("uploaded %+v, want one unstamped request", recs)
		}
		h.stop(t)
		if r := <-got; r.ok {
			t.Errorf("Hold after stop = %+v", r)
		}

		// The phone switched the rule off (threshold 0): held, but stamped.
		h2, _ := presenceHarness(t, time.Second, 0)
		defer h2.stop(t)
		got = startHold(t.Context(), h2, decide("01ARYZ6S41TSV4RRFFQ69G5FAV"), bubbled())
		synctest.Wait()
		select {
		case r := <-got:
			t.Fatalf("Hold with the rule off returned %+v", r)
		default:
		}
		if recs, _ := records(t, h2); len(recs) != 1 || recs[0].Headers[record.IdleHeader] != "1000" {
			t.Errorf("uploaded %+v, want one stamped request", recs)
		}
	})
}

func TestPolicyControlMovesTheThreshold(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h, _ := presenceHarness(t, 200*time.Second, presence.DefaultThreshold)
		defer h.stop(t)
		five := 300
		env := h.phone.seal(record.Record{Kind: record.KindControl, Control: record.ControlPolicy, Presence: &record.Presence{IdleThresholdSec: &five}})
		h.relay.events <- relay.Event{Kind: relay.EventEnvelope, Cursor: "1", Envelope: &env}
		synctest.Wait()
		h.mu.Lock()
		policies := h.policies
		h.mu.Unlock()
		if len(policies) != 1 || policies[0].IdleThresholdSec == nil || *policies[0].IdleThresholdSec != 300 {
			t.Fatalf("OnPolicy got %+v, want idleThresholdSec 300", policies)
		}
		if st := h.tun.Snapshot(); st[0].IdleThresholdSec != 300 {
			t.Errorf("threshold = %d, want 300", st[0].IdleThresholdSec)
		}
		// 200 s idle is now "present": a bubbled decide is released at once.
		got := startHold(t.Context(), h, decide("01ARYZ6S41TSV4RRFFQ69G5FAV"), bubbled())
		synctest.Wait()
		select {
		case r := <-got:
			if r.ok || r.err != nil {
				t.Fatalf("Hold = %+v", r)
			}
		default:
			t.Fatal("Hold blocked after the threshold moved above the idle time")
		}
		// A threshold past a day is clamped, here and as persisted (AG-19).
		huge := 1 << 40
		env = h.phone.seal(record.Record{Kind: record.KindControl, Control: record.ControlPolicy, Presence: &record.Presence{IdleThresholdSec: &huge}})
		h.relay.events <- relay.Event{Kind: relay.EventEnvelope, Cursor: "2", Envelope: &env}
		synctest.Wait()
		h.mu.Lock()
		policies = h.policies
		h.mu.Unlock()
		if last := policies[len(policies)-1]; last.IdleThresholdSec == nil || *last.IdleThresholdSec != presence.MaxThresholdSec {
			t.Errorf("OnPolicy got %+v, want idleThresholdSec clamped to %d", last, presence.MaxThresholdSec)
		}
		if st := h.tun.Snapshot(); st[0].IdleThresholdSec != presence.MaxThresholdSec {
			t.Errorf("threshold = %d, want %d", st[0].IdleThresholdSec, presence.MaxThresholdSec)
		}
		// A policy without a threshold leaves it alone.
		env = h.phone.seal(record.Record{Kind: record.KindControl, Control: record.ControlPolicy, Presence: &record.Presence{}})
		h.relay.events <- relay.Event{Kind: relay.EventEnvelope, Cursor: "3", Envelope: &env}
		synctest.Wait()
		if st := h.tun.Snapshot(); st[0].IdleThresholdSec != presence.MaxThresholdSec {
			t.Errorf("threshold after an empty policy = %d, want it left at %d", st[0].IdleThresholdSec, presence.MaxThresholdSec)
		}
	})
}

func TestIdleIsStampedOnEveryRequestAndCancelsCarryTheirReason(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h, _ := presenceHarness(t, 42*time.Second, presence.DefaultThreshold)
		defer h.stop(t)
		hostOnly := hook("Stop")
		hostOnly.Headers = map[string]string{record.HostHeader: "walter-laptop"}
		if err := h.tun.Enqueue(hostOnly, event("Stop")); err != nil {
			t.Fatal(err)
		}
		if len(hostOnly.Headers) != 1 {
			t.Errorf("Enqueue changed the caller's headers: %v", hostOnly.Headers)
		}
		statusline := record.Record{Kind: record.KindRequest, ReqID: "01ARYZ6S41TSV4RRFFQ69G5FSL", Path: record.PathStatusline, Body: json.RawMessage(`{}`)}
		if err := h.tun.Enqueue(statusline, record.Hook{}); err != nil {
			t.Fatal(err)
		}
		holdCtx, abandon := context.WithCancel(t.Context())
		got := startHold(holdCtx, h, decide("01ARYZ6S41TSV4RRFFQ69G5FAV"), event("PermissionRequest"))
		synctest.Wait()
		abandon()
		synctest.Wait()
		if r := <-got; !errors.Is(r.err, context.Canceled) {
			t.Fatalf("Hold after the client left = %+v", r)
		}
		recs, _ := records(t, h)
		if len(recs) != 4 {
			t.Fatalf("uploaded %d records, want event, statusline, decide, cancel", len(recs))
		}
		for i, rec := range recs[:3] {
			if rec.Headers[record.IdleHeader] != "42000" {
				t.Errorf("record %d headers = %v, want X-Clair-Idle-Ms 42000", i, rec.Headers)
			}
		}
		if recs[0].Headers[record.HostHeader] != "walter-laptop" {
			t.Errorf("event headers = %v, want the host header kept", recs[0].Headers)
		}
		if c := recs[3]; c.Control != record.ControlCancel || c.Reason != record.CancelClient {
			t.Errorf("cancel = %+v, want reason client", c)
		}
		// Drain's cancels say the agent is stopping.
		got = startHold(t.Context(), h, decide("01ARYZ6S41TSV4RRFFQ69G5FAW"), event("PermissionRequest"))
		synctest.Wait()
		h.tun.Drain(t.Context())
		if r := <-got; r.ok || r.err != nil {
			t.Fatalf("Hold on drain = %+v", r)
		}
		synctest.Wait()
		recs, _ = records(t, h)
		if c := recs[len(recs)-1]; c.Control != record.ControlCancel || c.Reason != record.CancelStop {
			t.Errorf("cancel on drain = %+v, want reason stop", c)
		}
		// A timeout's cancel says the decide expired.
		if _, ok, err := h.tun.Hold(t.Context(), decide("01ARYZ6S41TSV4RRFFQ69G5FAX"), event("PermissionRequest"), record.MinDecideTimeout); ok || err != nil {
			t.Fatalf("Hold to its timeout = ok %v, err %v", ok, err)
		}
		synctest.Wait()
		recs, _ = records(t, h)
		if c := recs[len(recs)-1]; c.Control != record.ControlCancel || c.Reason != record.CancelTimeout {
			t.Errorf("cancel on timeout = %+v, want reason timeout", c)
		}
	})
}
