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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"claircode.app/clair-agent/internal/ctl"
	"claircode.app/clair-agent/internal/envelope"
	"claircode.app/clair-agent/internal/identity"
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

// fakeTerm answers prompts from a script and records them.
type fakeTerm struct {
	mu      sync.Mutex
	answers []bool
	prompts []string
}

func (f *fakeTerm) Confirm(_ context.Context, prompt string, def bool) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prompts = append(f.prompts, prompt)
	if len(f.answers) == 0 {
		return def, nil
	}
	a := f.answers[0]
	f.answers = f.answers[1:]
	return a, nil
}

// fakeDaemon records control calls.
type fakeDaemon struct {
	mu          sync.Mutex
	unreachable bool
	reloads     int
	released    []string
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
		Install: func(s json.RawMessage) error {
			w.mu.Lock()
			defer w.mu.Unlock()
			w.installed = append(w.installed, s)
			return nil
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
	threshold := 90
	hello := record.Record{N: 1, Kind: record.KindControl, Control: record.ControlHello, Name: "Pixel 9 Pro", Snippet: snippet, Presence: &record.Presence{IdleThresholdSec: &threshold}}
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

func TestUnpair(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	if err := Unpair(t.Context(), w.options()); !errors.Is(err, ErrNothingToUnpair) {
		t.Fatalf("Unpair on a fresh host: err = %v, want ErrNothingToUnpair", err)
	}
	host, _, err := w.dir.EnsureHostKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := state.Pair{PairID: "BBBBBBBBBBBBBBBBBBBBBB", Relay: w.fake.URL, PhoneName: "Pixel", CreatedAt: time.Now()}
	p.SetKeys(&envelope.Keys{})
	if err := w.dir.SavePair(p); err != nil {
		t.Fatal(err)
	}
	w.fake.AddPair(p.PairID, base64.RawURLEncoding.EncodeToString(host.AuthPublic()), "phone")
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

	// With the daemon down the file is removed directly.
	w2 := newWorld(t)
	if _, _, err := w2.dir.EnsureHostKey(rand.Reader); err != nil {
		t.Fatal(err)
	}
	if err := w2.dir.SavePair(p); err != nil {
		t.Fatal(err)
	}
	opts := w2.options()
	opts.Daemon = &fakeDaemon{unreachable: true}
	if err := Unpair(t.Context(), opts); err != nil {
		t.Fatalf("Unpair without a daemon: %v", err)
	}
	if pairs, _ := w2.dir.ListPairs(); len(pairs) != 0 {
		t.Error("pair file remains without a daemon")
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
