package daemon_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"claircode.app/clair-agent/internal/claudecfg"
	"claircode.app/clair-agent/internal/ctl"
	"claircode.app/clair-agent/internal/daemon"
	"claircode.app/clair-agent/internal/envelope"
	"claircode.app/clair-agent/internal/identity"
	"claircode.app/clair-agent/internal/presence"
	"claircode.app/clair-agent/internal/record"
	"claircode.app/clair-agent/internal/relay"
	"claircode.app/clair-agent/internal/relay/relaytest"
	"claircode.app/clair-agent/internal/state"
)

const pairID = "AAAAAAAAAAAAAAAAAAAAAA"

// installer records what the daemon asked of the host's hook configuration.
type installer struct {
	mu        sync.Mutex
	snippets  [][]byte
	refreshes int
	uninstall int
}

func (i *installer) InstallSnippet(s json.RawMessage) (claudecfg.SnippetReport, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.snippets = append(i.snippets, bytes.Clone(s))
	return claudecfg.SnippetReport{}, nil
}

// RefreshHooks finds an older block of nine groups and rewrites it.
func (i *installer) RefreshHooks() (claudecfg.RefreshReport, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.refreshes++
	return claudecfg.RefreshReport{Report: claudecfg.Report{Backup: "settings.json.bak-1"}, Groups: 9}, nil
}

func (i *installer) refreshCount() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.refreshes
}

func (i *installer) Uninstall() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.uninstall++
	return nil
}

// phone is the far end: it streams h2p envelopes from the fake relay, opens
// them, hands the records to the test, and answers decides.
type phone struct {
	t      *testing.T
	keys   *envelope.Keys
	client *relay.Client
	seen   chan *record.Record
	n      uint64
	mu     sync.Mutex
	answer func(req *record.Record) *record.Record // nil → no answer
	wakes  map[uint64]envelope.Wake                // by the record's n
}

// wakeOf is the hint the envelope carrying record n was stamped with.
func (p *phone) wakeOf(n uint64) envelope.Wake {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.wakes[n]
}

func (p *phone) seal(rec record.Record) envelope.Envelope {
	p.t.Helper()
	p.n++
	rec.N = p.n
	plain, err := record.Marshal(&rec)
	if err != nil {
		p.t.Fatal(err)
	}
	id, err := envelope.NewID(time.Now(), rand.Reader)
	if err != nil {
		p.t.Fatal(err)
	}
	env, err := envelope.Seal(p.keys.Key(envelope.DirP2H), envelope.Header{Pair: pairID, ID: id, Dir: envelope.DirP2H, Wake: envelope.WakeSoon, TTLSec: 600}, plain, rand.Reader)
	if err != nil {
		p.t.Fatal(err)
	}
	return env
}

func (p *phone) send(ctx context.Context, rec record.Record) {
	p.t.Helper()
	if _, err := p.client.Upload(ctx, pairID, []envelope.Envelope{p.seal(rec)}); err != nil {
		p.t.Errorf("phone upload: %v", err)
	}
}

func (p *phone) run(ctx context.Context) error {
	return p.client.Stream(ctx, pairID, "", func(ctx context.Context, ev relay.Event) error {
		if ev.Kind != relay.EventEnvelope {
			return nil
		}
		env := *ev.Envelope
		if err := env.Validate(pairID, envelope.DirH2P); err != nil {
			return err
		}
		plain, err := envelope.Open(p.keys.Key(envelope.DirH2P), env)
		if err != nil {
			return err
		}
		rec, err := record.Unmarshal(plain)
		if err != nil {
			return err
		}
		p.mu.Lock()
		answer := p.answer
		p.wakes[rec.N] = env.Wake
		p.mu.Unlock()
		if rec.Kind == record.KindRequest && rec.Path == record.PathDecide && answer != nil {
			if resp := answer(rec); resp != nil {
				p.send(ctx, *resp)
			}
		}
		p.seen <- rec
		return p.client.Ack(ctx, pairID, ev.Cursor)
	})
}

// next waits for the phone's next record.
func (p *phone) next(t *testing.T) *record.Record {
	t.Helper()
	select {
	case rec := <-p.seen:
		return rec
	case <-time.After(10 * time.Second):
		t.Fatal("the phone received nothing")
		return nil
	}
}

type world struct {
	fake    *relaytest.Fake
	dir     *state.Dir
	agent   state.Agent
	hostKey string
	phone   *phone
	inst    *installer
	sampler *sampler
	addr    string
	done    chan error
	stop    context.CancelFunc
}

// sampler is the host's terminal-input reading, moved by the test.
type sampler struct {
	mu   sync.Mutex
	idle time.Duration
}

func (s *sampler) Sample() presence.Sample {
	s.mu.Lock()
	defer s.mu.Unlock()
	return presence.Sample{Idle: s.idle, Known: true, Source: "fake"}
}

func (s *sampler) set(idle time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.idle = idle
}

// newWorld pairs a host and a phone by hand (the flow `clair pair` runs) and
// starts the daemon.
func newWorld(t *testing.T) *world {
	t.Helper()
	fake := relaytest.New()
	t.Cleanup(fake.Close)
	dir, err := state.Open(filepath.Join(t.TempDir(), "clair"))
	if err != nil {
		t.Fatal(err)
	}
	agent, _, err := dir.EnsureAgent(rand.Reader, state.Agent{Listen: "127.0.0.1:0", Relay: fake.URL, LogLevel: "debug"})
	if err != nil {
		t.Fatal(err)
	}
	host, _, err := dir.EnsureHostKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	phoneKeys, err := identity.Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var k [envelope.PairingSecretSize]byte
	if _, readErr := rand.Read(k[:]); readErr != nil {
		t.Fatal(readErr)
	}
	hostSide, err := envelope.Derive(host.Agreement(), phoneKeys.AgreementPublic(), k[:])
	if err != nil {
		t.Fatal(err)
	}
	phoneSide, err := envelope.Derive(phoneKeys.Agreement(), host.AgreementPublic(), k[:])
	if err != nil {
		t.Fatal(err)
	}
	pair := state.Pair{PairID: pairID, Relay: fake.URL, PhonePub: base64.RawURLEncoding.EncodeToString(phoneKeys.AgreementPublic()), PhoneName: "Pixel 9 Pro", CreatedAt: time.Now(), PendingHelloAck: true}
	pair.SetKeys(hostSide)
	if saveErr := dir.SavePair(pair); saveErr != nil {
		t.Fatal(saveErr)
	}
	fake.AddPair(pairID, base64.RawURLEncoding.EncodeToString(host.AuthPublic()), base64.RawURLEncoding.EncodeToString(phoneKeys.AuthPublic()))

	phoneClient, err := relay.New(phoneKeys.Auth(), relay.Options{BaseURL: fake.URL})
	if err != nil {
		t.Fatal(err)
	}
	w := &world{fake: fake, dir: dir, agent: agent, hostKey: base64.RawURLEncoding.EncodeToString(host.AuthPublic()), inst: &installer{}, sampler: &sampler{idle: 5 * time.Second}}
	w.phone = &phone{t: t, keys: phoneSide, client: phoneClient, seen: make(chan *record.Record, 64), wakes: make(map[uint64]envelope.Wake)}

	phoneCtx, stopPhone := context.WithCancel(t.Context())
	t.Cleanup(stopPhone)
	go func() {
		if err := w.phone.run(phoneCtx); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, relay.ErrRevoked) {
			t.Errorf("phone stream: %v", err)
		}
	}()
	w.start(t)
	return w
}

// start runs a daemon on the world's config directory until w.stop; its
// result arrives on w.done.
func (w *world) start(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	w.stop = cancel
	t.Cleanup(cancel)
	done := make(chan error, 1)
	w.done = done
	ready := make(chan string, 1)
	go func() {
		done <- daemon.Run(ctx, daemon.Options{
			Dir: w.dir, Agent: w.agent, Listen: "127.0.0.1:0", Version: "test",
			Now: time.Now, Entropy: rand.Reader, Installer: w.inst, Presence: w.sampler, Ready: ready,
		})
	}()
	select {
	case w.addr = <-ready:
	case err := <-done:
		t.Fatalf("daemon stopped before it was ready: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("daemon never became ready")
	}
}

// hostCalls is the statuses the relay answered the host's requests with,
// for one method and path, in order.
func (w *world) hostCalls(method, path string) []int {
	var out []int
	for _, r := range w.fake.Requests() {
		if r.Key == w.hostKey && r.Method == method && r.RequestURI == path {
			out = append(out, r.Status)
		}
	}
	return out
}

// hook posts a hook as Claude Code would and returns the status, body and content type.
func (w *world) hook(ctx context.Context, t *testing.T, path, body string) (int, []byte, string) {
	t.Helper()
	return w.hookWith(ctx, t, path, body, nil)
}

// hookWith is hook with further request headers, as a hook's `headers` adds them.
func (w *world) hookWith(ctx context.Context, t *testing.T, path, body string, headers map[string]string) (int, []byte, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+w.addr+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+w.agent.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(record.HostHeader, "walter-laptop")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, ""
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data, resp.Header.Get("Content-Type")
}

const (
	preToolUse = `{"session_id":"sess-1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls > out"}}`
	permission = `{"session_id":"sess-1","hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"ls > out"}}`
	bubbled    = `{"session_id":"sess-1","hook_event_name":"PermissionRequest","permission_mode":"bubble","tool_name":"Bash","tool_input":{"command":"ls > out"}}`
	allow      = `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}`

	// A background agent's prompt in an auto-mode session, as Claude Code
	// 2.1.289 sends it: the parent's mode, and an agent_id.
	subagent = `{"session_id":"sess-1","hook_event_name":"PermissionRequest","permission_mode":"auto","agent_id":"acdcc84898a5d17b0","agent_type":"mesh-lab-reviewer","tool_name":"Bash","tool_input":{"command":"ls > out"}}`
)

func TestEndToEnd(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	ctx := t.Context()

	// The daemon's first words: the hello-ack `clair pair` left pending, then reset.
	if rec := w.phone.next(t); rec.Control != record.ControlHelloAck || rec.AgentVersion != "test" || rec.Hostname == "" || rec.N != 1 {
		t.Fatalf("first record = %+v, want hello-ack n=1", rec)
	}
	if rec := w.phone.next(t); rec.Control != record.ControlReset || rec.N != 2 {
		t.Fatalf("second record = %+v, want reset n=2", rec)
	}
	waitFor(t, func() bool {
		p, err := w.dir.LoadPair(pairID)
		return err == nil && !p.PendingHelloAck
	})

	// With the relay refusing uploads, an event hook is still 204 at once and
	// arrives, in order, once the relay recovers.
	w.fake.Set(func(f *relaytest.Fake) { f.MailboxFull = true })
	start := time.Now()
	for i := range 3 {
		body := strings.Replace(preToolUse, `"ls > out"`, `"ls `+strings.Repeat("x", i)+`"`, 1)
		if code, _, _ := w.hook(ctx, t, record.PathEvent, body); code != http.StatusNoContent {
			t.Fatalf("event hook %d = %d, want 204", i, code)
		}
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("three event hooks took %v with the relay down, want them answered locally", d)
	}
	w.fake.Set(func(f *relaytest.Fake) { f.MailboxFull = false })
	var lastN uint64 = 2
	for i := range 3 {
		rec := w.phone.next(t)
		if rec.Kind != record.KindRequest || rec.Path != record.PathEvent || rec.Headers[record.HostHeader] != "walter-laptop" {
			t.Fatalf("event %d = %+v", i, rec)
		}
		if !bytes.Contains(rec.Body, []byte(`"ls `+strings.Repeat("x", i)+`"`)) {
			t.Errorf("event %d body out of order: %s", i, rec.Body)
		}
		if rec.N <= lastN {
			t.Errorf("event %d n=%d, want above %d", i, rec.N, lastN)
		}
		lastN = rec.N
	}

	// A decide round trip: the phone allows, Claude Code gets the hook output.
	w.phone.mu.Lock()
	w.phone.answer = func(req *record.Record) *record.Record {
		return &record.Record{Kind: record.KindResponse, ReqID: req.ReqID, Status: 200, Body: json.RawMessage(allow)}
	}
	w.phone.mu.Unlock()
	code, body, ctype := w.hook(ctx, t, record.PathDecide+"?timeout=30", permission)
	if code != http.StatusOK || string(body) != allow || !strings.HasPrefix(ctype, "application/json") {
		t.Fatalf("decide = %d %q (%s), want 200 with the phone's output", code, body, ctype)
	}
	if rec := w.phone.next(t); rec.Path != record.PathDecide || rec.Query["timeout"] != "30" || rec.Headers[record.IdleHeader] != "5000" {
		t.Fatalf("decide record = %+v, want it stamped with X-Clair-Idle-Ms 5000", rec)
	}

	// Claude Code abandons a decide: the phone is told to cancel it.
	w.phone.mu.Lock()
	w.phone.answer = nil
	w.phone.mu.Unlock()
	hookCtx, abandon := context.WithCancel(ctx)
	abandoned := make(chan int, 1)
	go func() {
		code, _, _ := w.hook(hookCtx, t, record.PathDecide+"?timeout=60", permission)
		abandoned <- code
	}()
	held := w.phone.next(t)
	if held.Path != record.PathDecide {
		t.Fatalf("held decide = %+v", held)
	}
	abandon()
	if code := <-abandoned; code != 0 {
		t.Errorf("abandoned decide returned %d, want the client to see its own cancellation", code)
	}
	if rec := w.phone.next(t); rec.Control != record.ControlCancel || rec.ReqID != held.ReqID || rec.Reason != record.CancelClient {
		t.Fatalf("after abandoning: %+v, want cancel (client) for %s", rec, held.ReqID)
	}

	// The phone sends a hooks snippet; the installer gets it.
	snippet := json.RawMessage(`{"hooks":{"Stop":[]}}`)
	w.phone.send(ctx, record.Record{Kind: record.KindControl, Control: record.ControlSnippet, Snippet: snippet})
	waitFor(t, func() bool {
		w.inst.mu.Lock()
		defer w.inst.mu.Unlock()
		return len(w.inst.snippets) == 1 && bytes.Equal(w.inst.snippets[0], snippet)
	})

	// The phone unpairs as RELAY.md r9 §6.6 has it: its sealed revoke, and
	// the DELETE once the relay took it. The relay keeps the record for the
	// host, whose stream drains it before `revoked`: hooks and the host key
	// go, the daemon keeps answering locally, and the relay is told too
	// (alone, the DELETE would only park the pair:
	// TestRelayOnlyRevokeKeepsTheHostsState). The daemon may drain the
	// revoke and DELETE first, and then the phone's own DELETE is a 410.
	w.phone.send(ctx, record.Record{Kind: record.KindControl, Control: record.ControlRevoke})
	if err := w.phone.client.Revoke(ctx, pairID); err != nil && !errors.Is(err, relay.ErrRevoked) {
		t.Fatalf("phone revoke: %v", err)
	}
	waitFor(t, func() bool {
		w.inst.mu.Lock()
		defer w.inst.mu.Unlock()
		return w.inst.uninstall == 1
	})
	waitFor(t, func() bool {
		_, err := w.dir.LoadHostKey()
		return errors.Is(err, state.ErrNotFound)
	})
	waitFor(t, func() bool { return len(w.hostCalls(http.MethodDelete, "/v1/pairs/"+pairID)) == 1 })
	// The receiver's final counter flush must not resurrect the pair file.
	time.Sleep(100 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(w.dir.Path(), "pairs", pairID+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("pair file after the revoke: err = %v, want gone", err)
	}
	if code, _, _ := w.hook(ctx, t, record.PathEvent, preToolUse); code != http.StatusNoContent {
		t.Errorf("event hook after the revoke = %d, want 204", code)
	}
	if code, _, _ := w.hook(ctx, t, record.PathDecide, permission); code != http.StatusNoContent {
		t.Errorf("decide after the revoke = %d, want 204 at once", code)
	}
	statusReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+w.addr+record.PathStatus, http.NoBody)
	statusReq.Header.Set("Authorization", "Bearer "+w.agent.Token)
	resp, err := http.DefaultClient.Do(statusReq)
	if err != nil {
		t.Fatal(err)
	}
	statusBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !bytes.Contains(statusBody, []byte(`"paired":false`)) || !bytes.Contains(statusBody, []byte(`"unpaired":"revoked by the phone"`)) {
		t.Errorf("status after the revoke = %s", statusBody)
	}

	w.stop()
	select {
	case err := <-w.done:
		if err != nil {
			t.Fatalf("daemon.Run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("daemon did not stop")
	}
}

// TestRelayOnlyRevokeKeepsTheHostsState is AG-3 end to end: a pair the relay
// reports revoked, with no sealed word from the phone, is parked — hooks
// answered locally at once — while its file, the host key and the hooks stay.
func TestRelayOnlyRevokeKeepsTheHostsState(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	ctx := t.Context()
	if rec := w.phone.next(t); rec.Control != record.ControlHelloAck {
		t.Fatalf("first record = %+v, want hello-ack", rec)
	}
	w.fake.Revoke(pairID)
	status := func() []byte {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+w.addr+record.PathStatus, http.NoBody)
		req.Header.Set("Authorization", "Bearer "+w.agent.Token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		return body
	}
	waitFor(t, func() bool {
		return bytes.Contains(status(), []byte(`"dormant":{"reason":"the relay reports the pair revoked"`))
	})
	waitFor(t, func() bool {
		p, err := w.dir.LoadPair(pairID)
		return err == nil && p.RelayRevokedAt != nil
	})
	if _, err := w.dir.LoadHostKey(); err != nil {
		t.Errorf("host key after a relay-only revoke: %v, want kept", err)
	}
	w.inst.mu.Lock()
	uninstalled := w.inst.uninstall
	w.inst.mu.Unlock()
	if uninstalled != 0 {
		t.Errorf("hooks uninstalled %d times, want kept", uninstalled)
	}
	if code, _, _ := w.hook(ctx, t, record.PathDecide, permission); code != http.StatusNoContent {
		t.Errorf("decide while dormant = %d, want 204 at once", code)
	}
	w.stop()
	if err := <-w.done; err != nil {
		t.Fatalf("daemon.Run: %v", err)
	}
}

// TestBubbledDecideGoesToTheTerminalWhileSomeoneIsThere is RELAY.md §4.3
// end to end: a background subagent's prompt is answered "no decision" at
// once while the host's terminal input is fresh, so Claude Code draws its
// dialog, and the phone is told; with nobody at a terminal the same prompt
// is held for the watch.
func TestBubbledDecideGoesToTheTerminalWhileSomeoneIsThere(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	ctx := t.Context()
	w.phone.next(t) // hello-ack
	w.phone.next(t) // reset
	w.phone.mu.Lock()
	w.phone.answer = func(req *record.Record) *record.Record {
		return &record.Record{Kind: record.KindResponse, ReqID: req.ReqID, Status: 200, Body: json.RawMessage(allow)}
	}
	w.phone.mu.Unlock()

	// Someone typed 5 s ago: released at once, whatever the phone would say.
	start := time.Now()
	code, body, _ := w.hook(ctx, t, record.PathDecide+"?timeout=600", bubbled)
	if code != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("bubbled decide = %d %q, want 204 at once", code, body)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("the bubbled decide took %v, want it released without a round trip", d)
	}
	req := w.phone.next(t)
	if req.Path != record.PathDecide || req.Headers[record.IdleHeader] != "5000" || w.phone.wakeOf(req.N) != envelope.WakeSoon {
		t.Fatalf("released decide = %+v (wake %s), want it stamped and sent as soon", req, w.phone.wakeOf(req.N))
	}
	if rec := w.phone.next(t); rec.Control != record.ControlCancel || rec.ReqID != req.ReqID || rec.Reason != record.CancelTerminal {
		t.Fatalf("after the release: %+v, want cancel (terminal) for %s", rec, req.ReqID)
	}
	// Nobody there: held and answered from the phone, like any decide.
	w.sampler.set(15 * time.Minute)
	code, body, _ = w.hook(ctx, t, record.PathDecide+"?timeout=600", bubbled)
	if code != http.StatusOK || string(body) != allow {
		t.Fatalf("bubbled decide with nobody there = %d %q, want the phone's 200", code, body)
	}
	if req := w.phone.next(t); req.Path != record.PathDecide || req.Headers[record.IdleHeader] != "900000" || w.phone.wakeOf(req.N) != envelope.WakeNow {
		t.Fatalf("held decide = %+v (wake %s), want it stamped and sent as now", req, w.phone.wakeOf(req.N))
	}

	// clair status shows the reading and the threshold in force.
	statusReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+w.addr+record.PathStatus, http.NoBody)
	statusReq.Header.Set("Authorization", "Bearer "+w.agent.Token)
	resp, err := http.DefaultClient.Do(statusReq)
	if err != nil {
		t.Fatal(err)
	}
	statusBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	for _, want := range []string{`"presence":{"idleMs":900000,"source":"fake"}`, `"idleThresholdSec":120`} {
		if !bytes.Contains(statusBody, []byte(want)) {
			t.Errorf("status lacks %s: %s", want, statusBody)
		}
	}

	// The phone moves the threshold; the daemon persists it and applies it.
	threshold := 1200
	w.phone.send(ctx, record.Record{Kind: record.KindControl, Control: record.ControlPolicy, Presence: &record.Presence{IdleThresholdSec: &threshold}})
	waitFor(t, func() bool {
		p, err := w.dir.LoadPair(pairID)
		return err == nil && p.IdleThresholdSec != nil && *p.IdleThresholdSec == 1200
	})
	if code, _, _ := w.hook(ctx, t, record.PathDecide+"?timeout=600", bubbled); code != http.StatusNoContent {
		t.Fatalf("bubbled decide under the new threshold = %d, want 204 (15 min idle is now present)", code)
	}
}

// TestSubagentDecideInAutoModeGoesToTheTerminal is issue #2 end to end (ADR
// 2026-10.gw8w): a background agent's prompt in an auto-mode session carries
// the parent's mode, not `bubble`, and its agent_id is what hands it to the
// terminal while someone is there. The same prompt from `claude -p`, where
// nothing would draw it once the hook returns, is held for the phone.
func TestSubagentDecideInAutoModeGoesToTheTerminal(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	ctx := t.Context()
	w.phone.next(t) // hello-ack
	w.phone.next(t) // reset
	w.phone.mu.Lock()
	w.phone.answer = func(req *record.Record) *record.Record {
		return &record.Record{Kind: record.KindResponse, ReqID: req.ReqID, Status: 200, Body: json.RawMessage(allow)}
	}
	w.phone.mu.Unlock()

	// An interactive session, someone typed 5 s ago: released at once, and
	// the entrypoint header stays on the host.
	code, body, _ := w.hookWith(ctx, t, record.PathDecide+"?timeout=600", subagent, map[string]string{record.EntrypointHeader: record.EntrypointCLI})
	if code != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("subagent decide = %d %q, want 204 at once", code, body)
	}
	req := w.phone.next(t)
	if req.Path != record.PathDecide || w.phone.wakeOf(req.N) != envelope.WakeSoon || req.Headers[record.EntrypointHeader] != "" {
		t.Fatalf("released decide = %+v (wake %s), want it sent as soon without the entrypoint", req, w.phone.wakeOf(req.N))
	}
	if rec := w.phone.next(t); rec.Control != record.ControlCancel || rec.ReqID != req.ReqID || rec.Reason != record.CancelTerminal {
		t.Fatalf("after the release: %+v, want cancel (terminal) for %s", rec, req.ReqID)
	}

	// claude -p, someone still there: held and answered from the phone.
	code, body, _ = w.hookWith(ctx, t, record.PathDecide+"?timeout=600", subagent, map[string]string{record.EntrypointHeader: "sdk-cli"})
	if code != http.StatusOK || string(body) != allow {
		t.Fatalf("subagent decide from claude -p = %d %q, want the phone's 200", code, body)
	}
	if req := w.phone.next(t); req.Path != record.PathDecide || w.phone.wakeOf(req.N) != envelope.WakeNow {
		t.Fatalf("held decide = %+v (wake %s), want it sent as now", req, w.phone.wakeOf(req.N))
	}
}

func TestShutdownReleasesHeldDecides(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	ctx := t.Context()
	w.phone.next(t) // hello-ack
	w.phone.next(t) // reset
	answered := make(chan int, 1)
	go func() {
		code, _, _ := w.hook(ctx, t, record.PathDecide+"?timeout=600", permission)
		answered <- code
	}()
	if rec := w.phone.next(t); rec.Path != record.PathDecide {
		t.Fatalf("held decide = %+v", rec)
	}
	start := time.Now()
	w.stop()
	select {
	case code := <-answered:
		if code != http.StatusNoContent {
			t.Errorf("held decide on shutdown = %d, want 204", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("held decide was not answered on shutdown")
	}
	select {
	case err := <-w.done:
		if err != nil {
			t.Fatalf("daemon.Run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("daemon did not stop")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("shutdown took %v", d)
	}
	if rec := w.phone.next(t); rec.Control != record.ControlCancel || rec.Reason != record.CancelStop {
		t.Errorf("after shutdown the phone got %+v, want the cancel (stop)", rec)
	}
	// The stream was let go of on purpose before the daemon returned, so the
	// phone sees the host leave at once (ADR 2026-09.hu4b).
	if got := w.hostCalls(http.MethodDelete, "/v1/pairs/"+pairID+"/events"); len(got) != 1 || got[0] != http.StatusNoContent {
		t.Errorf("stream releases on shutdown = %v, want one 204", got)
	}
}

// A stop through the control surface is a clean shutdown, as a signal is:
// Task Scheduler can only kill, so `clair service stop` asks first.
func TestControlStopShutsDownCleanly(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	ctx := t.Context()
	w.phone.next(t) // hello-ack
	w.phone.next(t) // reset
	control := &ctl.Client{Base: "http://" + w.addr, AdminToken: w.agent.AdminToken}
	if err := control.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	select {
	case err := <-w.done:
		if err != nil {
			t.Fatalf("daemon.Run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("daemon did not stop")
	}
	if got := w.hostCalls(http.MethodDelete, "/v1/pairs/"+pairID+"/events"); len(got) != 1 || got[0] != http.StatusNoContent {
		t.Errorf("stream releases on a control stop = %v, want one 204", got)
	}
	if _, err := control.Status(ctx); !errors.Is(err, ctl.ErrUnreachable) {
		t.Errorf("status after the stop: %v, want ctl.ErrUnreachable", err)
	}
}

// A paired daemon brings the hooks block up to its own template once, as it
// starts, and says what it found; an unpaired one leaves settings.json alone
// (ADR 2026-10.sm5c).
func TestStartRefreshesTheHooksOfAPairedHost(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	ctx := t.Context()
	control := &ctl.Client{Base: "http://" + w.addr, AdminToken: w.agent.AdminToken}
	st, err := control.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	want := ctl.HooksStatus{Outcome: ctl.HooksRewritten, Groups: 9, Backup: "settings.json.bak-1"}
	if st.Hooks == nil || *st.Hooks != want {
		t.Errorf("status hooks = %+v, want %+v", st.Hooks, want)
	}
	if got := w.inst.refreshCount(); got != 1 {
		t.Errorf("refreshes at start = %d, want 1", got)
	}
	w.stop()
	if err := <-w.done; err != nil {
		t.Fatalf("daemon.Run: %v", err)
	}

	if err := w.dir.DeletePair(pairID); err != nil {
		t.Fatal(err)
	}
	w.start(t)
	if st, err := (&ctl.Client{Base: "http://" + w.addr, AdminToken: w.agent.AdminToken}).Status(ctx); err != nil || st.Hooks != nil {
		t.Errorf("unpaired status = %+v, %v; want no hooks refresh", st.Hooks, err)
	}
	if got := w.inst.refreshCount(); got != 1 {
		t.Errorf("refreshes after an unpaired start = %d, want still 1", got)
	}
	w.stop()
	if err := <-w.done; err != nil {
		t.Fatalf("daemon.Run: %v", err)
	}
}

// The control surface's release stops a pair — its stream let go of at the
// relay — and hands its file to the CLI, which seals the pair's goodbye from
// it (ADR 2026-09.69ym): the daemon no longer deletes it.
func TestReleasePairHandsTheFileOver(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	ctx := t.Context()
	w.phone.next(t) // hello-ack
	w.phone.next(t) // reset
	control := &ctl.Client{Base: "http://" + w.addr, AdminToken: w.agent.AdminToken}
	if err := control.ReleasePair(ctx, pairID); err != nil {
		t.Fatalf("ReleasePair: %v", err)
	}
	if got := w.hostCalls(http.MethodDelete, "/v1/pairs/"+pairID+"/events"); len(got) != 1 || got[0] != http.StatusNoContent {
		t.Errorf("stream releases by the time ReleasePair returned = %v, want one 204", got)
	}
	if _, err := w.dir.LoadPair(pairID); err != nil {
		t.Errorf("pair file after the release: %v, want it left for the CLI", err)
	}
	if st, err := control.Status(ctx); err != nil || st.Paired {
		t.Errorf("status after the release = %+v, %v; want nothing running", st, err)
	}
	if err := control.ReleasePair(ctx, pairID); !errors.Is(err, ctl.ErrNotFound) {
		t.Errorf("a second release: %v, want ctl.ErrNotFound", err)
	}
	w.stop()
	if err := <-w.done; err != nil {
		t.Fatalf("daemon.Run: %v", err)
	}
}

// The phone unpairs while the host is down (RELAY.md r9 §6.6): the relay
// keeps its sealed revoke for the host. The daemon starts, its reset is
// refused, the pair parks; the stream drains the record and the pair ends —
// hooks and host key gone — without resuming in between: nothing it sends is
// accepted, and the relay is told too (ADR 2026-09.32b5).
func TestPhoneUnpairWhileTheHostIsDownEndsThePairCleanly(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	ctx := t.Context()
	w.phone.next(t) // hello-ack
	w.phone.next(t) // reset
	w.stop()
	if err := <-w.done; err != nil {
		t.Fatalf("daemon.Run: %v", err)
	}
	accepted := len(w.fake.Rows(pairID, envelope.DirH2P))
	w.phone.send(ctx, record.Record{Kind: record.KindControl, Control: record.ControlRevoke})
	if err := w.phone.client.Revoke(ctx, pairID); err != nil {
		t.Fatalf("phone revoke: %v", err)
	}
	before := len(w.hostCalls(http.MethodPost, "/v1/pairs/"+pairID+"/envelopes"))

	w.start(t)
	waitFor(t, func() bool {
		w.inst.mu.Lock()
		defer w.inst.mu.Unlock()
		return w.inst.uninstall == 1
	})
	waitFor(t, func() bool {
		_, err := w.dir.LoadHostKey()
		return errors.Is(err, state.ErrNotFound)
	})
	waitFor(t, func() bool { return len(w.hostCalls(http.MethodDelete, "/v1/pairs/"+pairID)) == 1 })
	if _, err := os.Stat(filepath.Join(w.dir.Path(), "pairs", pairID+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("pair file after the drained revoke: err = %v, want gone", err)
	}
	// At most the start's reset and one probe, both refused: no resume.
	uploads := w.hostCalls(http.MethodPost, "/v1/pairs/"+pairID+"/envelopes")[before:]
	for _, status := range uploads {
		if status != http.StatusGone {
			t.Errorf("the host's uploads after the phone unpaired = %v, want each refused 410", uploads)
			break
		}
	}
	if len(uploads) > 2 {
		t.Errorf("the host uploaded %d times on a pair the phone had unpaired, want the start's reset and one probe at most", len(uploads))
	}
	if got := len(w.fake.Rows(pairID, envelope.DirH2P)); got > accepted {
		t.Errorf("the relay holds %d host rows, had %d: something the restarted host sent was taken", got, accepted)
	}
	w.stop()
	if err := <-w.done; err != nil {
		t.Fatalf("daemon.Run: %v", err)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition never held")
}
