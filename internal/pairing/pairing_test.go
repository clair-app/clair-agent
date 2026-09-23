package pairing

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"claircode.app/clair-agent/internal/claudecfg"
	"claircode.app/clair-agent/internal/ctl"
	"claircode.app/clair-agent/internal/envelope"
	"claircode.app/clair-agent/internal/identity"
	"claircode.app/clair-agent/internal/presence"
	"claircode.app/clair-agent/internal/record"
	"claircode.app/clair-agent/internal/relay"
	"claircode.app/clair-agent/internal/relay/relaytest"
	"claircode.app/clair-agent/internal/state"
)

func fixedPayload() Payload {
	var p Payload
	p.V = payloadVersion
	for i := range p.PairingID {
		p.PairingID[i] = byte(i)
	}
	for i := range p.HostPub {
		p.HostPub[i] = byte(0x40 + i)
	}
	for i := range p.K {
		p.K[i] = byte(0xA0 + i)
	}
	return p
}

func TestPayloadRoundTripAndLayout(t *testing.T) {
	t.Parallel()

	p := fixedPayload()
	data, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	want := "01" + "000102030405060708090a0b0c0d0e0f" + "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" + "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
	if got := hex.EncodeToString(data); got != want {
		t.Fatalf("payload = %s\nwant      %s", got, want)
	}
	back, err := ParsePayload(data)
	if err != nil || back != p {
		t.Fatalf("ParsePayload = %+v, %v", back, err)
	}
	p.Relay = "relay.example.org:8443"
	data, _ = p.MarshalBinary()
	back, err = ParsePayload(data)
	if err != nil || back.Relay != p.Relay {
		t.Fatalf("ParsePayload with a relay = %+v, %v", back, err)
	}
	if p.PairingIDString() != base64.RawURLEncoding.EncodeToString(p.PairingID[:]) {
		t.Error("PairingIDString is not base64url of the id")
	}
	for name, in := range map[string][]byte{"short": data[:payloadMinSize-1], "version": append([]byte{2}, data[1:]...), "empty": nil} {
		if _, err := ParsePayload(in); !errors.Is(err, ErrPayload) {
			t.Errorf("ParsePayload(%s): err = %v, want ErrPayload", name, err)
		}
	}
	if _, err := (Payload{V: 2}).MarshalBinary(); !errors.Is(err, ErrPayload) {
		t.Error("MarshalBinary of a bad version: want ErrPayload")
	}
}

func TestPayloadURL(t *testing.T) {
	t.Parallel()

	p := fixedPayload()
	link, err := PayloadURL("https://relay.claircode.app/", p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(link, "https://relay.claircode.app/p#") || strings.Contains(link, "=") {
		t.Fatalf("PayloadURL = %s", link)
	}
	if fragment := link[strings.Index(link, "#")+1:]; len(fragment) != 87 {
		t.Errorf("fragment is %d characters, want 87 (65 bytes of base64url)", len(fragment))
	}
	relayURL, back, err := ParseURL(link)
	if err != nil || relayURL != "https://relay.claircode.app" || back != p {
		t.Fatalf("ParseURL = %q, %+v, %v", relayURL, back, err)
	}
	p.Relay = "self.example"
	link, _ = PayloadURL("http://localhost:3000", p)
	relayURL, _, err = ParseURL(link)
	if err != nil || relayURL != "https://self.example" {
		t.Errorf("ParseURL with a relay field = %q, %v", relayURL, err)
	}
	for _, bad := range []string{"https://relay.claircode.app/p", "https://relay.claircode.app/other#AAAA", "https://relay.claircode.app/p#AAAA", "https://relay.claircode.app/p#=="} {
		if _, _, err := ParseURL(bad); !errors.Is(err, ErrPayload) {
			t.Errorf("ParseURL(%q): err = %v, want ErrPayload", bad, err)
		}
	}
}

func TestRenderQRFitsATerminal(t *testing.T) {
	t.Parallel()

	link, err := PayloadURL("https://relay.claircode.app", fixedPayload())
	if err != nil {
		t.Fatal(err)
	}
	var unicode, ascii, none bytes.Buffer
	size, err := RenderQR(&unicode, link, QRUnicode, false)
	if err != nil {
		t.Fatal(err)
	}
	if size > 41 {
		t.Errorf("default QR is version %d (%d modules), want ≤ version 6 (41)", (size-17)/4, size)
	}
	lines := strings.Split(strings.TrimSuffix(unicode.String(), "\n"), "\n")
	if want := (size + 2*qrQuiet + 1) / 2; len(lines) != want {
		t.Errorf("unicode rendering has %d lines, want %d", len(lines), want)
	}
	for i, line := range lines {
		if n := len([]rune(line)); n != size+2*qrQuiet {
			t.Errorf("unicode line %d is %d runes, want %d", i, n, size+2*qrQuiet)
		}
	}
	if _, err := RenderQR(&ascii, link, QRASCII, false); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(ascii.String(), "\n"); got != size+2*qrQuiet {
		t.Errorf("ascii rendering has %d lines, want %d", got, size+2*qrQuiet)
	}
	if _, err := RenderQR(&none, link, QRNone, false); err != nil || none.Len() != 0 {
		t.Errorf("QRNone wrote %q, %v", none.String(), err)
	}
	var inverted bytes.Buffer
	_, _ = RenderQR(&inverted, link, QRUnicode, true)
	if inverted.String() == unicode.String() {
		t.Error("invert changed nothing")
	}
	for name, got := range map[string]string{"qr-unicode.txt": unicode.String(), "qr-ascii.txt": ascii.String()} {
		want, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatalf("read golden %s: %v", name, err)
		}
		if got != string(want) {
			t.Errorf("%s differs from the golden rendering", name)
		}
	}
}

func TestParseYesNo(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]bool{"y\n": true, "YES\r\n": true, "n": false, "no\n": false, "": true, "maybe": true} {
		if got := parseYesNo(in, true); got != want {
			t.Errorf("parseYesNo(%q, default yes) = %v, want %v", in, got, want)
		}
	}
	if parseYesNo("", false) || parseYesNo("what", false) {
		t.Error("parseYesNo with default no accepted an empty or unknown answer")
	}
}

// fakeTerm answers prompts from a script and records them; onConfirm, when
// set, runs first and its error is the answer's.
type fakeTerm struct {
	mu        sync.Mutex
	answers   []bool
	prompts   []string
	onConfirm func(ctx context.Context) error
}

func (f *fakeTerm) Confirm(ctx context.Context, prompt string, def bool) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prompts = append(f.prompts, prompt)
	if f.onConfirm != nil {
		if err := f.onConfirm(ctx); err != nil {
			return false, err
		}
	}
	if len(f.answers) == 0 {
		return def, nil
	}
	a := f.answers[0]
	f.answers = f.answers[1:]
	return a, nil
}

// fakeDaemon records control calls. Its onRelease runs as a release hands
// a pair file over, for a test to leave in it what a running daemon would.
type fakeDaemon struct {
	mu          sync.Mutex
	unreachable bool
	reloads     int
	released    []string
	onRelease   func(id string)
}

func (f *fakeDaemon) Reload(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.unreachable {
		return ctl.ErrUnreachable
	}
	f.reloads++
	return nil
}

func (f *fakeDaemon) ReleasePair(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.unreachable {
		return ctl.ErrUnreachable
	}
	f.released = append(f.released, id)
	if f.onRelease != nil {
		f.onRelease(id)
	}
	return nil
}

// lockedBuffer is a Writer the test may read while Pair writes.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// world is a fake relay, a config dir and the callbacks Pair needs.
type world struct {
	fake      *relaytest.Fake
	dir       *state.Dir
	daemon    *fakeDaemon
	term      *fakeTerm
	stdout    *lockedBuffer
	stderr    *lockedBuffer
	mu        sync.Mutex
	installed []json.RawMessage
	uninstall int
	// installReport and installErr are what Install answers.
	installReport claudecfg.SnippetReport
	installErr    error
	// helloN and helloThreshold override what the scanning phone's hello
	// says; zero keeps n=1 and 90 s.
	helloN         uint64
	helloThreshold int
}

func newWorld(t *testing.T) *world {
	t.Helper()
	fake := relaytest.New()
	t.Cleanup(fake.Close)
	dir, err := state.Open(filepath.Join(t.TempDir(), "clair"))
	if err != nil {
		t.Fatal(err)
	}
	return &world{fake: fake, dir: dir, daemon: &fakeDaemon{}, term: &fakeTerm{}, stdout: &lockedBuffer{}, stderr: &lockedBuffer{}}
}

func (w *world) options() Options {
	return Options{
		Dir:      w.dir,
		RelayURL: w.fake.URL,
		NewRelay: func(baseURL string, auth ed25519.PrivateKey) (Relay, error) {
			return relay.New(auth, relay.Options{BaseURL: baseURL})
		},
		Daemon: w.daemon,
		Install: func(s json.RawMessage) (claudecfg.SnippetReport, error) {
			w.mu.Lock()
			defer w.mu.Unlock()
			w.installed = append(w.installed, s)
			return w.installReport, w.installErr
		},
		Uninstall: func() error {
			w.mu.Lock()
			defer w.mu.Unlock()
			w.uninstall++
			return nil
		},
		Stdout:       w.stdout,
		Stderr:       w.stderr,
		Term:         w.term,
		QR:           QRNone,
		Entropy:      rand.Reader,
		Hostname:     "walter-laptop",
		AgentVersion: "test",
	}
}

// link waits for Pair to print the QR link.
func (w *world) link(t *testing.T) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for line := range strings.SplitSeq(w.stdout.String(), "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(line, PathPage+"#") {
				return line
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("Pair never printed a link; stdout:\n%s", w.stdout.String())
	return ""
}

// phone completes a pairing from a scanned link, with the given k (nil = the scanned one).
type phone struct {
	keys    *identity.Keys
	client  *relay.Client
	pairID  string
	traffic *envelope.Keys
}

func (w *world) scan(t *testing.T, link string, wrongK bool, snippet json.RawMessage) *phone {
	t.Helper()
	relayURL, payload, err := ParseURL(link)
	if err != nil {
		t.Fatal(err)
	}
	if relayURL != w.fake.URL {
		t.Fatalf("link names relay %q, want %q", relayURL, w.fake.URL)
	}
	keys, err := identity.Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k := payload.K[:]
	if wrongK {
		k = bytes.Repeat([]byte{0xFF}, envelope.PairingSecretSize)
	}
	traffic, err := envelope.Derive(keys.Agreement(), payload.HostPub[:], k)
	if err != nil {
		t.Fatal(err)
	}
	threshold, n := 90, uint64(1)
	if w.helloThreshold != 0 {
		threshold = w.helloThreshold
	}
	if w.helloN != 0 {
		n = w.helloN
	}
	hello := record.Record{N: n, Kind: record.KindControl, Control: record.ControlHello, Name: "Pixel 9 Pro", Snippet: snippet, Presence: &record.Presence{IdleThresholdSec: &threshold}}
	plain, _ := record.Marshal(&hello)
	id, _ := envelope.NewID(time.Now(), rand.Reader)
	env, err := envelope.Seal(traffic.Key(envelope.DirP2H), envelope.Header{Pair: payload.PairingIDString(), ID: id, Dir: envelope.DirP2H, Wake: envelope.WakeSoon, TTLSec: 600}, plain, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client, err := relay.New(keys.Auth(), relay.Options{BaseURL: relayURL})
	if err != nil {
		t.Fatal(err)
	}
	pairID, err := client.CompletePairing(t.Context(), payload.PairingIDString(), keys.AgreementPublic(), "fcm", env)
	if err != nil {
		t.Fatalf("CompletePairing: %v", err)
	}
	return &phone{keys: keys, client: client, pairID: pairID, traffic: traffic}
}

func TestPairHappyPath(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	done := make(chan error, 1)
	go func() { done <- Pair(t.Context(), w.options()) }()
	snippet := json.RawMessage(`{"hooks":{}}`)
	ph := w.scan(t, w.link(t), false, snippet)
	if err := <-done; err != nil {
		t.Fatalf("Pair: %v\nstdout:\n%s\nstderr:\n%s", err, w.stdout.String(), w.stderr.String())
	}

	pairs, err := w.dir.ListPairs()
	if err != nil || len(pairs) != 1 {
		t.Fatalf("pairs = %v, %v; want one", pairs, err)
	}
	p := pairs[0]
	if p.PairID != ph.pairID || p.PhoneName != "Pixel 9 Pro" || p.Relay != w.fake.URL || p.H2PNext != 2 || p.P2HLast != 1 || p.PendingHelloAck {
		t.Errorf("pair file = %+v", p)
	}
	if p.IdleThresholdSec == nil || *p.IdleThresholdSec != 90 {
		t.Errorf("pair file threshold = %v, want the hello's 90", p.IdleThresholdSec)
	}
	stored, err := p.Keys()
	if err != nil || *stored != *ph.traffic {
		t.Errorf("stored keys differ from the phone's derivation (%v)", err)
	}
	if _, err := w.dir.LoadHostKey(); err != nil {
		t.Errorf("host key: %v", err)
	}
	if got := w.fake.Rows(ph.pairID, envelope.DirH2P); len(got) != 1 {
		t.Fatalf("host mailbox holds %d rows, want the hello-ack", len(got))
	} else if plain, err := envelope.Open(ph.traffic.Key(envelope.DirH2P), got[0]); err != nil {
		t.Errorf("hello-ack does not open with the phone's key: %v", err)
	} else if rec, _ := record.Unmarshal(plain); rec == nil || rec.Control != record.ControlHelloAck || rec.Hostname != "walter-laptop" || rec.AgentVersion != "test" || rec.N != 1 {
		t.Errorf("hello-ack = %+v", rec)
	}
	w.mu.Lock()
	installed := w.installed
	w.mu.Unlock()
	if len(installed) != 1 || !bytes.Equal(installed[0], snippet) {
		t.Errorf("Install called with %q, want the phone's snippet", installed)
	}
	if w.daemon.reloads != 1 {
		t.Errorf("daemon reloaded %d times, want 1", w.daemon.reloads)
	}
	if prompts := w.term.prompts; len(prompts) != 1 || !strings.Contains(prompts[0], `"Pixel 9 Pro"`) {
		t.Errorf("prompts = %q, want the pair confirmation naming the phone", prompts)
	}
	out := w.stdout.String()
	if !strings.Contains(out, "Fingerprint: "+ph.traffic.Fingerprint()) || !strings.Contains(out, "Restart any running Claude Code") {
		t.Errorf("stdout:\n%s", out)
	}
}

func TestPairRefusesAPhoneThatDidNotScanThisCode(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	done := make(chan error, 1)
	go func() { done <- Pair(t.Context(), w.options()) }()
	ph := w.scan(t, w.link(t), true, nil)
	err := <-done
	if !errors.Is(err, ErrNotThisPhone) {
		t.Fatalf("Pair: err = %v, want ErrNotThisPhone", err)
	}
	if pairs, _ := w.dir.ListPairs(); len(pairs) != 0 {
		t.Error("a pair file was written for a phone that did not scan the code")
	}
	if _, err := ph.client.Upload(t.Context(), ph.pairID, nil); err != nil {
		t.Errorf("empty upload: %v", err)
	}
	// The pair was revoked at the relay: the impostor's next call is refused.
	env := envelope.Envelope{V: 1, Pair: ph.pairID, ID: "01ARYZ6S41TSV4RRFFQ69G5FAV", Dir: envelope.DirP2H, Wake: envelope.WakeNo, TTLSec: 60, CT: base64.RawURLEncoding.EncodeToString(make([]byte, 40))}
	if _, err := ph.client.Upload(t.Context(), ph.pairID, []envelope.Envelope{env}); !errors.Is(err, relay.ErrRevoked) {
		t.Errorf("impostor upload after refusal: err = %v, want ErrRevoked", err)
	}
	if len(w.installed) != 0 {
		t.Error("hooks were installed for a refused pairing")
	}
}

func TestPairDeclinedAndHeadless(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	w.term.answers = []bool{false}
	done := make(chan error, 1)
	go func() { done <- Pair(t.Context(), w.options()) }()
	ph := w.scan(t, w.link(t), false, nil)
	if err := <-done; !errors.Is(err, ErrDeclined) {
		t.Fatalf("Pair: err = %v, want ErrDeclined", err)
	}
	if pairs, _ := w.dir.ListPairs(); len(pairs) != 0 {
		t.Error("a declined pairing wrote a pair file")
	}
	if err := ph.client.Ack(t.Context(), ph.pairID, "1"); !errors.Is(err, relay.ErrRevoked) {
		t.Errorf("declined pair not revoked at the relay: %v", err)
	}

	// Headless: no terminal, the built-in block (nil snippet) is installed.
	w2 := newWorld(t)
	opts := w2.options()
	opts.Term = nil
	opts.Daemon = &fakeDaemon{unreachable: true}
	done2 := make(chan error, 1)
	go func() { done2 <- Pair(t.Context(), opts) }()
	w2.scan(t, w2.link(t), false, nil)
	if err := <-done2; err != nil {
		t.Fatalf("headless Pair: %v", err)
	}
	if len(w2.installed) != 1 || w2.installed[0] != nil {
		t.Errorf("headless install = %v, want one call with a nil snippet (built-in)", w2.installed)
	}
	if out := w2.stdout.String(); !strings.Contains(out, `Pairing with "Pixel 9 Pro"`) || !strings.Contains(out, "clair daemon") {
		t.Errorf("headless stdout:\n%s", out)
	}
}

// interruptingRelay is the relay client whose first upload — the
// hello-ack — is cut short by an interrupt: the command's context ends, as
// on Ctrl-C, and nothing reaches the relay.
type interruptingRelay struct {
	Relay

	cancel context.CancelFunc
	mu     sync.Mutex
	cut    bool
}

func (r *interruptingRelay) Upload(ctx context.Context, pair string, envs []envelope.Envelope) (relay.Receipt, error) {
	r.mu.Lock()
	first := !r.cut
	r.cut = true
	r.mu.Unlock()
	if first {
		r.cancel()
		return relay.Receipt{}, ctx.Err()
	}
	return r.Relay.Upload(ctx, pair, envs)
}

// upload is the phone's next upload. A revoked pair refuses every one, while
// its stream and ack stay open to the side that did not revoke it for as
// long as the revoker's records wait there (RELAY.md r9 §6.6).
func (ph *phone) upload(t *testing.T) error {
	t.Helper()
	env := envelope.Envelope{V: 1, Pair: ph.pairID, ID: "01ARYZ6S41TSV4RRFFQ69G5FAV", Dir: envelope.DirP2H, Wake: envelope.WakeNo, TTLSec: 60, CT: base64.RawURLEncoding.EncodeToString(make([]byte, 40))}
	_, err := ph.client.Upload(t.Context(), ph.pairID, []envelope.Envelope{env})
	return err
}

// controls opens the host's records in a pair's mailbox with the phone's key.
func controls(t *testing.T, w *world, ph *phone) []string {
	t.Helper()
	rows := w.fake.Rows(ph.pairID, envelope.DirH2P)
	out := make([]string, 0, len(rows))
	for _, env := range rows {
		plain, err := envelope.Open(ph.traffic.Key(envelope.DirH2P), env)
		if err != nil {
			t.Fatalf("a host record does not open with the phone's key: %v", err)
		}
		rec, err := record.Unmarshal(plain)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, fmt.Sprintf("%s n=%d", rec.Control, rec.N))
	}
	return out
}

// Every way out of `clair pair` between the relay's completion and the
// saved pair file revokes the pair at the relay — on a context of its own,
// as the command's may be what ended — and once the phone may hold the
// hello-ack, sends it a sealed revoke first (ADR 2026-09.mwfw).
func TestAnUnfinishedPairingIsRevoked(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		setup        func(w *world, opts *Options, cancel context.CancelFunc)
		wantErr      string
		wantControls []string
	}{
		{
			name:    "declined",
			setup:   func(w *world, _ *Options, _ context.CancelFunc) { w.term.answers = []bool{false} },
			wantErr: ErrDeclined.Error(),
		},
		{
			name: "the terminal fails",
			setup: func(w *world, _ *Options, _ context.CancelFunc) {
				w.term.onConfirm = func(context.Context) error { return errors.New("pairing: read terminal: input/output error") }
			},
			wantErr: "read terminal",
		},
		{
			name: "interrupted at the prompt",
			setup: func(w *world, _ *Options, cancel context.CancelFunc) {
				w.term.onConfirm = func(ctx context.Context) error { cancel(); return ctx.Err() }
			},
			wantErr: "interrupted before the pair was saved",
		},
		{
			name: "interrupted during the hello-ack",
			setup: func(_ *world, opts *Options, cancel context.CancelFunc) {
				opts.NewRelay = func(baseURL string, auth ed25519.PrivateKey) (Relay, error) {
					c, err := relay.New(auth, relay.Options{BaseURL: baseURL})
					return &interruptingRelay{Relay: c, cancel: cancel}, err
				}
			},
			wantErr:      "interrupted before the pair was saved",
			wantControls: []string{"revoke n=2"},
		},
		{
			name: "the pair file cannot be saved",
			setup: func(w *world, _ *Options, _ context.CancelFunc) {
				pairs := filepath.Join(w.dir.Path(), "pairs")
				w.term.onConfirm = func(context.Context) error {
					if err := os.RemoveAll(pairs); err != nil {
						return err
					}
					return os.WriteFile(pairs, nil, 0o600)
				}
			},
			wantErr:      "pairs",
			wantControls: []string{"hello-ack n=1", "revoke n=2"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			opts := w.options()
			tt.setup(w, &opts, cancel)
			done := make(chan error, 1)
			go func() { done <- Pair(ctx, opts) }()
			ph := w.scan(t, w.link(t), false, nil)
			err := <-done
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Pair: err = %v, want one containing %q", err, tt.wantErr)
			}
			if pairs, _ := w.dir.ListPairs(); len(pairs) != 0 {
				t.Errorf("pairs = %+v, want none", pairs)
			}
			if err := ph.upload(t); !errors.Is(err, relay.ErrRevoked) {
				t.Errorf("the phone's next upload: err = %v, want ErrRevoked", err)
			}
			if got := controls(t, w, ph); strings.Join(got, ", ") != strings.Join(tt.wantControls, ", ") {
				t.Errorf("records for the phone = %q, want %q", got, tt.wantControls)
			}
			if len(w.installed) != 0 {
				t.Error("hooks were installed for a pair that was not kept")
			}
		})
	}
}

// What the install did is said: a refused snippet or dropped events as
// warnings, and no hooks at all as a failure that keeps the pair.
func TestPairReportsTheHooksOutcome(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                     string
		report                   claudecfg.SnippetReport
		err                      error
		wantOut, wantStderr, not string
		wantErr                  bool
	}{
		{name: "written", report: claudecfg.SnippetReport{Report: claudecfg.Report{Backup: "x.bak"}}, wantOut: "Hooks written to Claude Code's settings.json (a .bak", not: "clair pair:"},
		{name: "unchanged", report: claudecfg.SnippetReport{Report: claudecfg.Report{Unchanged: true}}, wantOut: "already had these hooks", not: "Hooks written"},
		{
			name:       "the phone's snippet refused",
			report:     claudecfg.SnippetReport{Refused: fmt.Errorf("%w: Stop: url is not on http://127.0.0.1:7317", claudecfg.ErrSnippetRejected)},
			wantOut:    "Paired with",
			wantStderr: "clair pair: the phone's hooks were refused (claudecfg: snippet rejected: Stop: url is not on http://127.0.0.1:7317); the built-in hooks were written instead.",
		},
		{
			name:       "no hooks at all",
			report:     claudecfg.SnippetReport{Refused: claudecfg.ErrSnippetRejected},
			err:        errors.New("claudecfg: settings.json is not a JSON object; not touching it"),
			wantErr:    true,
			wantStderr: "refused",
			not:        "Paired with",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			w.installReport, w.installErr = tt.report, tt.err
			done := make(chan error, 1)
			go func() { done <- Pair(t.Context(), w.options()) }()
			ph := w.scan(t, w.link(t), false, nil)
			err := <-done
			if tt.wantErr {
				if !errors.Is(err, ErrHooksNotWritten) || !strings.Contains(err.Error(), "not a JSON object") || !strings.Contains(err.Error(), "clair pair --replace") {
					t.Errorf("Pair: err = %v, want ErrHooksNotWritten with the cause and the way back", err)
				}
			} else if err != nil {
				t.Fatalf("Pair: %v", err)
			}
			if !strings.Contains(w.stdout.String(), tt.wantOut) || !strings.Contains(w.stderr.String(), tt.wantStderr) {
				t.Errorf("stdout:\n%s\nstderr:\n%s\nwant %q and %q", w.stdout.String(), w.stderr.String(), tt.wantOut, tt.wantStderr)
			}
			if tt.not != "" && strings.Contains(w.stdout.String()+w.stderr.String(), tt.not) {
				t.Errorf("output has %q:\n%s%s", tt.not, w.stdout.String(), w.stderr.String())
			}
			// Whatever the hooks, the pair is kept and the daemon has it.
			if pairs, _ := w.dir.ListPairs(); len(pairs) != 1 || w.daemon.reloads != 1 {
				t.Errorf("pairs = %d, reloads = %d; want the pair saved and the daemon told", len(pairs), w.daemon.reloads)
			}
			if err := ph.client.Ack(t.Context(), ph.pairID, "1"); err != nil {
				t.Errorf("the kept pair at the relay: %v", err)
			}
		})
	}
}

func TestPairReplacesAnExistingPair(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	oldHost, _, err := w.dir.EnsureHostKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := state.Pair{PairID: "BBBBBBBBBBBBBBBBBBBBBB", Relay: w.fake.URL, PhoneName: "Old phone", CreatedAt: time.Now()}
	old.SetKeys(&envelope.Keys{})
	if err := w.dir.SavePair(old); err != nil {
		t.Fatal(err)
	}
	w.fake.AddPair(old.PairID, base64.RawURLEncoding.EncodeToString(oldHost.AuthPublic()), "phone")

	headless := w.options()
	headless.Term = nil
	if err := Pair(t.Context(), headless); !errors.Is(err, ErrAlreadyPaired) {
		t.Fatalf("headless Pair without --replace: err = %v, want ErrAlreadyPaired", err)
	}
	w.term.answers = []bool{false}
	if err := Pair(t.Context(), w.options()); !errors.Is(err, ErrDeclined) {
		t.Fatalf("Pair with replace declined: err = %v, want ErrDeclined", err)
	}
	if pairs, _ := w.dir.ListPairs(); len(pairs) != 1 {
		t.Fatal("the old pair was touched although the replace was declined")
	}

	opts := w.options()
	opts.Replace = true
	done := make(chan error, 1)
	go func() { done <- Pair(t.Context(), opts) }()
	w.scan(t, w.link(t), false, nil)
	if err := <-done; err != nil {
		t.Fatalf("Pair --replace: %v\n%s", err, w.stderr.String())
	}
	if len(w.daemon.released) == 0 || w.daemon.released[0] != old.PairID {
		t.Errorf("daemon released %v, want the old pair", w.daemon.released)
	}
	pairs, _ := w.dir.ListPairs()
	if len(pairs) != 1 || pairs[0].PairID == old.PairID {
		t.Errorf("pairs after replace = %+v, want only the new one", pairs)
	}
	newHost, _ := w.dir.LoadHostKey()
	if bytes.Equal(newHost.AuthPublic(), oldHost.AuthPublic()) {
		t.Error("host key was kept across a replace; RELAY.md §6.6 wants new keys")
	}
	oldClient, _ := relay.New(oldHost.Auth(), relay.Options{BaseURL: w.fake.URL})
	if err := oldClient.Ack(t.Context(), old.PairID, "1"); !errors.Is(err, relay.ErrRevoked) {
		t.Errorf("old pair not revoked at the relay: %v", err)
	}
	if rec := goodbye(t, w.fake, &old); rec == nil {
		t.Error("the old phone was not sent a sealed revoke")
	}
}

// goodbye is the sealed revoke the relay keeps for a pair's phone, opened
// with the pair's keys, or nil when there is none.
func goodbye(t *testing.T, fake *relaytest.Fake, p *state.Pair) *record.Record {
	t.Helper()
	rows := fake.Rows(p.PairID, envelope.DirH2P)
	if len(rows) == 0 {
		return nil
	}
	if len(rows) > 1 {
		t.Fatalf("the phone's mailbox holds %d rows, want the revoke alone", len(rows))
	}
	keys, err := p.Keys()
	if err != nil {
		t.Fatal(err)
	}
	env := rows[0]
	if verr := env.Validate(p.PairID, envelope.DirH2P); verr != nil || env.Wake != envelope.WakeSoon || env.TTLSec != 86400 {
		t.Fatalf("goodbye envelope = %+v (%v), want a valid h2p one, soon, for a day", env, verr)
	}
	plain, err := envelope.Open(keys.Key(envelope.DirH2P), env)
	if err != nil {
		t.Fatalf("goodbye does not open with the pair's key: %v", err)
	}
	rec, err := record.Unmarshal(plain)
	if err != nil || rec.Kind != record.KindControl || rec.Control != record.ControlRevoke {
		t.Fatalf("goodbye = %+v (%v), want a revoke control record", rec, err)
	}
	return rec
}

// A replace that does not complete — the phone declined, the code expired
// — leaves the old pairs and the host key exactly as they were (AG-19).
func TestReplaceKeepsTheOldStateUntilTheNewPairingIsAccepted(t *testing.T) {
	t.Parallel()

	for _, tt := range []string{"declined", "expired"} {
		t.Run(tt, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			oldHost, _, err := w.dir.EnsureHostKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			old := state.Pair{PairID: "BBBBBBBBBBBBBBBBBBBBBB", Relay: w.fake.URL, PhoneName: "Old phone", CreatedAt: time.Now()}
			old.SetKeys(&envelope.Keys{})
			if err := w.dir.SavePair(old); err != nil {
				t.Fatal(err)
			}
			w.fake.AddPair(old.PairID, base64.RawURLEncoding.EncodeToString(oldHost.AuthPublic()), "phone")
			opts := w.options()
			opts.Replace = true
			switch tt {
			case "declined":
				w.term.answers = []bool{false}
				done := make(chan error, 1)
				go func() { done <- Pair(t.Context(), opts) }()
				w.scan(t, w.link(t), false, nil)
				if err := <-done; !errors.Is(err, ErrDeclined) {
					t.Fatalf("Pair: err = %v, want ErrDeclined", err)
				}
			case "expired":
				script := &scriptedRelay{
					mint: func() (relay.Pairing, error) {
						return relay.Pairing{ID: "AAAAAAAAAAAAAAAAAAAAAA", ExpiresAt: time.Now().Add(10 * time.Minute)}, nil
					},
					wait: func() (relay.Completed, error) { return relay.Completed{}, relay.ErrPairingExpired },
				}
				opts.NewRelay = func(string, ed25519.PrivateKey) (Relay, error) { return script, nil }
				if err := Pair(t.Context(), opts); err == nil {
					t.Fatal("Pair with an expired code: want an error")
				}
			}
			if pairs, _ := w.dir.ListPairs(); len(pairs) != 1 || pairs[0].PairID != old.PairID {
				t.Errorf("pairs = %+v, want the old one untouched", pairs)
			}
			if host, err := w.dir.LoadHostKey(); err != nil || !bytes.Equal(host.AuthPublic(), oldHost.AuthPublic()) {
				t.Errorf("host key after a %s replace: %v; want the old one kept", tt, err)
			}
			if len(w.daemon.released) != 0 {
				t.Errorf("daemon released %v, want nothing", w.daemon.released)
			}
			oldClient, _ := relay.New(oldHost.Auth(), relay.Options{BaseURL: w.fake.URL})
			if err := oldClient.Ack(t.Context(), old.PairID, "1"); errors.Is(err, relay.ErrRevoked) {
				t.Error("the old pair was revoked at the relay by a replace that did not complete")
			}
		})
	}
}

// What the phone's hello says about counters and presence is bounded: an
// absurd counter refuses the pair, an absurd threshold is clamped (AG-19).
func TestPairBoundsWhatTheHelloSays(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	w.helloN = maxHelloN + 1
	done := make(chan error, 1)
	go func() { done <- Pair(t.Context(), w.options()) }()
	ph := w.scan(t, w.link(t), false, nil)
	if err := <-done; err == nil || !strings.Contains(err.Error(), "claims n=") {
		t.Fatalf("Pair with hello n=%d: err = %v", w.helloN, err)
	}
	if pairs, _ := w.dir.ListPairs(); len(pairs) != 0 {
		t.Error("a hello with an absurd counter wrote a pair file")
	}
	if err := ph.client.Ack(t.Context(), ph.pairID, "1"); !errors.Is(err, relay.ErrRevoked) {
		t.Errorf("refused pair not revoked at the relay: %v", err)
	}

	w2 := newWorld(t)
	w2.helloThreshold = 1 << 40
	done2 := make(chan error, 1)
	go func() { done2 <- Pair(t.Context(), w2.options()) }()
	ph2 := w2.scan(t, w2.link(t), false, nil)
	if err := <-done2; err != nil {
		t.Fatalf("Pair: %v", err)
	}
	p, err := w2.dir.LoadPair(ph2.pairID)
	if err != nil {
		t.Fatal(err)
	}
	if p.IdleThresholdSec == nil || *p.IdleThresholdSec != presence.MaxThresholdSec {
		t.Errorf("persisted threshold = %v, want %d", p.IdleThresholdSec, presence.MaxThresholdSec)
	}
}

// scriptedRelay answers the pairing calls from a script.
type scriptedRelay struct {
	mint    func() (relay.Pairing, error)
	wait    func() (relay.Completed, error)
	revoked []string
}

func (s *scriptedRelay) MintPairing(context.Context) (relay.Pairing, error) { return s.mint() }
func (s *scriptedRelay) WaitPairing(context.Context, string) (relay.Completed, error) {
	return s.wait()
}

func (*scriptedRelay) Upload(context.Context, string, []envelope.Envelope) (relay.Receipt, error) {
	return relay.Receipt{}, nil
}

func (s *scriptedRelay) Revoke(_ context.Context, pair string) error {
	s.revoked = append(s.revoked, pair)
	return nil
}

func TestPairExplainsRelayRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mint error
		wait error
		want string
	}{
		{name: "rate limited", mint: fmt.Errorf("x: %w", relay.ErrRateLimited), want: "rate limiting"},
		{name: "expired", wait: fmt.Errorf("x: %w", relay.ErrPairingExpired), want: "expired"},
		{name: "used", wait: fmt.Errorf("x: %w", relay.ErrPairingUsed), want: "already used"},
		{name: "other", wait: fmt.Errorf("x: %w", relay.ErrUnauthorized), want: "wait for the phone"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			script := &scriptedRelay{
				mint: func() (relay.Pairing, error) {
					if tt.mint != nil {
						return relay.Pairing{}, tt.mint
					}
					return relay.Pairing{ID: "AAAAAAAAAAAAAAAAAAAAAA", ExpiresAt: time.Now().Add(10 * time.Minute)}, nil
				},
				wait: func() (relay.Completed, error) { return relay.Completed{}, tt.wait },
			}
			opts := w.options()
			opts.NewRelay = func(string, ed25519.PrivateKey) (Relay, error) { return script, nil }
			err := Pair(t.Context(), opts)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Pair: err = %v, want one mentioning %q", err, tt.want)
			}
		})
	}
}

func TestPairRejectsAnOddPairingID(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	script := &scriptedRelay{mint: func() (relay.Pairing, error) { return relay.Pairing{ID: "short"}, nil }}
	opts := w.options()
	opts.NewRelay = func(string, ed25519.PrivateKey) (Relay, error) { return script, nil }
	if err := Pair(t.Context(), opts); err == nil || !strings.Contains(err.Error(), "16 bytes") {
		t.Fatalf("Pair with a 5-byte pairing id: err = %v", err)
	}
}

// pairedHost gives the world's config dir a host key and one pair the fake
// relay knows, as `clair pair` would have left them.
func (w *world) pairedHost(t *testing.T, mod func(*state.Pair)) (*identity.Keys, state.Pair) {
	t.Helper()
	host, _, err := w.dir.EnsureHostKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := &envelope.Keys{}
	for i := range keys.H2P {
		keys.H2P[i] = byte(i + 1)
	}
	p := state.Pair{PairID: "BBBBBBBBBBBBBBBBBBBBBB", Relay: w.fake.URL, PhoneName: "Pixel", CreatedAt: time.Now(), H2PNext: 2 + envelope.CounterBlock}
	p.SetKeys(keys)
	if mod != nil {
		mod(&p)
	}
	if err := w.dir.SavePair(p); err != nil {
		t.Fatal(err)
	}
	w.fake.AddPair(p.PairID, base64.RawURLEncoding.EncodeToString(host.AuthPublic()), "phone")
	return host, p
}

func TestUnpair(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	if err := Unpair(t.Context(), w.options()); !errors.Is(err, ErrNothingToUnpair) {
		t.Fatalf("Unpair on a fresh host: err = %v, want ErrNothingToUnpair", err)
	}
	host, p := w.pairedHost(t, nil)
	if err := Unpair(t.Context(), w.options()); err != nil {
		t.Fatalf("Unpair: %v", err)
	}
	if pairs, _ := w.dir.ListPairs(); len(pairs) != 0 {
		t.Error("pair file remains")
	}
	if _, err := w.dir.LoadHostKey(); !errors.Is(err, state.ErrNotFound) {
		t.Error("host key remains")
	}
	if w.uninstall != 1 || w.daemon.reloads != 1 || len(w.daemon.released) != 1 {
		t.Errorf("uninstall %d, reloads %d, released %v", w.uninstall, w.daemon.reloads, w.daemon.released)
	}
	client, _ := relay.New(host.Auth(), relay.Options{BaseURL: w.fake.URL})
	if err := client.Ack(t.Context(), p.PairID, "1"); !errors.Is(err, relay.ErrRevoked) {
		t.Errorf("pair not revoked at the relay: %v", err)
	}
	// The phone is told on the host's own word, above every n the host used.
	if rec := goodbye(t, w.fake, &p); rec == nil || rec.N != p.H2PNext {
		t.Errorf("sealed revoke = %+v, want one with n = %d", rec, p.H2PNext)
	}

	// With the daemon down the file is taken directly.
	w2 := newWorld(t)
	_, p2 := w2.pairedHost(t, nil)
	opts := w2.options()
	opts.Daemon = &fakeDaemon{unreachable: true}
	if err := Unpair(t.Context(), opts); err != nil {
		t.Fatalf("Unpair without a daemon: %v", err)
	}
	if pairs, _ := w2.dir.ListPairs(); len(pairs) != 0 {
		t.Error("pair file remains without a daemon")
	}
	if goodbye(t, w2.fake, &p2) == nil {
		t.Error("no sealed revoke without a daemon")
	}
}

// The daemon owns a pair's counter while it runs it: the goodbye is sealed
// from the file only once the daemon has let go and written its last
// reservation, so its n is one the daemon never used.
func TestUnpairSealsAboveTheDaemonsLastReservation(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	_, p := w.pairedHost(t, nil)
	reserved := p.H2PNext + envelope.CounterBlock
	w.daemon.onRelease = func(id string) {
		if err := w.dir.ReserveH2P(id, reserved); err != nil {
			t.Error(err)
		}
	}
	if err := Unpair(t.Context(), w.options()); err != nil {
		t.Fatalf("Unpair: %v", err)
	}
	if rec := goodbye(t, w.fake, &p); rec == nil || rec.N != reserved {
		t.Errorf("sealed revoke = %+v, want n = %d, the daemon's last limit", rec, reserved)
	}
}

// A pair the relay already reports gone is not sent a goodbye it could not
// take; the DELETE still goes.
func TestUnpairSendsAParkedPairNoGoodbye(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	_, p := w.pairedHost(t, func(p *state.Pair) { p.RelayRevokedAt = new(time.Now().Add(-time.Hour)) })
	if err := Unpair(t.Context(), w.options()); err != nil {
		t.Fatalf("Unpair: %v", err)
	}
	if rec := goodbye(t, w.fake, &p); rec != nil {
		t.Errorf("a parked pair was sent %+v, want nothing", rec)
	}
	var deleted bool
	for _, r := range w.fake.Requests() {
		deleted = deleted || (r.Method == http.MethodDelete && r.RequestURI == "/v1/pairs/"+p.PairID && r.Status == http.StatusNoContent)
	}
	if !deleted {
		t.Error("the parked pair was not deleted at the relay")
	}
}

// An unreachable relay delays unpairing by the goodbye's bound, never more,
// and never keeps it from happening.
func TestUnpairIsNotHeldUpByAnUnreachableRelay(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	// Reading the body lets the server notice the client leave, so the
	// handler ends with the request instead of holding up Close.
	hang := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	}))
	t.Cleanup(hang.Close)
	w.pairedHost(t, func(p *state.Pair) { p.Relay = hang.URL })
	opts := w.options()
	opts.GoodbyeTimeout = 50 * time.Millisecond
	start := time.Now()
	if err := Unpair(t.Context(), opts); err != nil {
		t.Fatalf("Unpair: %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("Unpair took %v against a relay that never answers, want about twice the 50ms bound", d)
	}
	if _, err := w.dir.LoadHostKey(); !errors.Is(err, state.ErrNotFound) {
		t.Error("host key remains")
	}
	if pairs, _ := w.dir.ListPairs(); len(pairs) != 0 || w.uninstall != 1 {
		t.Errorf("after Unpair: %d pairs, %d uninstalls; want none and one", len(pairs), w.uninstall)
	}
	if !strings.Contains(w.stderr.String(), "did not revoke") {
		t.Errorf("stderr = %q, want it to say the relay was not told", w.stderr.String())
	}
}

func TestDeriveMatchesPhoneSide(t *testing.T) {
	t.Parallel()

	// A sanity check that the payload's HostPub is the key the phone must use.
	host, _ := identity.Generate(rand.Reader)
	p := Payload{V: payloadVersion}
	copy(p.HostPub[:], host.AgreementPublic())
	pub, err := ecdh.X25519().NewPublicKey(p.HostPub[:])
	if err != nil || !bytes.Equal(pub.Bytes(), host.AgreementPublic()) {
		t.Fatalf("HostPub round trip: %v", err)
	}
}
