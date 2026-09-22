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

	"claircode.app/clair-agent/internal/daemon"
	"claircode.app/clair-agent/internal/envelope"
	"claircode.app/clair-agent/internal/identity"
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
	uninstall int
}

func (i *installer) InstallSnippet(s json.RawMessage) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.snippets = append(i.snippets, bytes.Clone(s))
	return nil
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
	fake  *relaytest.Fake
	dir   *state.Dir
	agent state.Agent
	phone *phone
	inst  *installer
	addr  string
	done  chan error
	stop  context.CancelFunc
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
	w := &world{fake: fake, dir: dir, agent: agent, inst: &installer{}, done: make(chan error, 1)}
	w.phone = &phone{t: t, keys: phoneSide, client: phoneClient, seen: make(chan *record.Record, 64)}

	ctx, cancel := context.WithCancel(t.Context())
	w.stop = cancel
	t.Cleanup(cancel)
	phoneCtx, stopPhone := context.WithCancel(t.Context())
	t.Cleanup(stopPhone)
	go func() {
		if err := w.phone.run(phoneCtx); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, relay.ErrRevoked) {
			t.Errorf("phone stream: %v", err)
		}
	}()
	ready := make(chan string, 1)
	go func() {
		w.done <- daemon.Run(ctx, daemon.Options{
			Dir: dir, Agent: agent, Listen: "127.0.0.1:0", Version: "test",
			Now: time.Now, Entropy: rand.Reader, Installer: w.inst, Ready: ready,
		})
	}()
	select {
	case w.addr = <-ready:
	case err := <-w.done:
		t.Fatalf("daemon stopped before it was ready: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("daemon never became ready")
	}
	return w
}

// hook posts a hook as Claude Code would and returns the status, body and content type.
func (w *world) hook(ctx context.Context, t *testing.T, path, body string) (int, []byte, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+w.addr+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+w.agent.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(record.HostHeader, "walter-laptop")
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
	allow      = `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}`
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
	if rec := w.phone.next(t); rec.Path != record.PathDecide || rec.Query["timeout"] != "30" {
		t.Fatalf("decide record = %+v", rec)
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
	if rec := w.phone.next(t); rec.Control != record.ControlCancel || rec.ReqID != held.ReqID {
		t.Fatalf("after abandoning: %+v, want cancel for %s", rec, held.ReqID)
	}

	// The phone sends a hooks snippet; the installer gets it.
	snippet := json.RawMessage(`{"hooks":{"Stop":[]}}`)
	w.phone.send(ctx, record.Record{Kind: record.KindControl, Control: record.ControlSnippet, Snippet: snippet})
	waitFor(t, func() bool {
		w.inst.mu.Lock()
		defer w.inst.mu.Unlock()
		return len(w.inst.snippets) == 1 && bytes.Equal(w.inst.snippets[0], snippet)
	})

	// The phone revokes the pair: hooks and the host key go, the daemon keeps
	// answering locally.
	if err := w.phone.client.Revoke(ctx, pairID); err != nil {
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
	if rec := w.phone.next(t); rec.Control != record.ControlCancel {
		t.Errorf("after shutdown the phone got %+v, want the cancel", rec)
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
