package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
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
	"claircode.app/clair-agent/internal/pairing"
	"claircode.app/clair-agent/internal/record"
	"claircode.app/clair-agent/internal/relay"
	"claircode.app/clair-agent/internal/relay/relaytest"
	"claircode.app/clair-agent/internal/state"
)

func TestCommandUsageErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		wantStatus int
		wantErr    string
	}{
		{name: "pair rejects a bad qr mode", args: []string{"pair", "-qr", "braille"}, wantStatus: exitUsage, wantErr: "-qr must be"},
		{name: "pair rejects positionals", args: []string{"pair", "now"}, wantStatus: exitUsage, wantErr: "unexpected argument"},
		{name: "pair help", args: []string{"pair", "-h"}, wantStatus: exitOK, wantErr: "-replace"},
		{name: "unpair help", args: []string{"unpair", "-h"}, wantStatus: exitOK, wantErr: "-relay-ca"},
		{name: "status help", args: []string{"status", "-h"}, wantStatus: exitOK, wantErr: "-json"},
		{name: "daemon rejects a missing ca file", args: []string{"daemon", "-relay-ca", "/nonexistent.pem", "-config-dir", t.TempDir()}, wantStatus: exitUsage, wantErr: "read --relay-ca"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			got := runWith(t.Context(), testDeps(nil), tt.args, &stdout, &stderr)
			if got != tt.wantStatus {
				t.Errorf("run(%q) = %d, want %d; stderr %q", tt.args, got, tt.wantStatus, stderr.String())
			}
			if !strings.Contains(stderr.String(), tt.wantErr) {
				t.Errorf("stderr = %q, want substring %q", stderr.String(), tt.wantErr)
			}
		})
	}
}

func TestStatusWithoutAConfigOrDaemon(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	dir := t.TempDir()
	if got := runWith(t.Context(), testDeps(nil), []string{"status", "-config-dir", dir}, &stdout, &stderr); got != exitUnreachable {
		t.Fatalf("status on a fresh dir = %d, want %d; stderr %s", got, exitUnreachable, stderr.String())
	}
	if !strings.Contains(stdout.String(), "clair pair") {
		t.Errorf("stdout = %q, want a pointer to clair pair", stdout.String())
	}

	// An agent.json whose daemon is not running.
	d, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.EnsureAgent(testDeps(nil).entropy, state.Agent{Listen: "127.0.0.1:1", Relay: "https://relay.test"}); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if got := runWith(t.Context(), testDeps(nil), []string{"status", "-config-dir", dir}, &stdout, &stderr); got != exitUnreachable {
		t.Fatalf("status without a daemon = %d, want %d", got, exitUnreachable)
	}
	if !strings.Contains(stdout.String(), "clair daemon") {
		t.Errorf("stdout = %q, want a pointer to clair daemon", stdout.String())
	}
}

func TestStatusAgainstARunningDaemon(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	var mu sync.Mutex
	var log bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- runWith(ctx, testDeps(map[string]string{state.EnvConfigDir: dir}), []string{"daemon", "-listen", "127.0.0.1:0"}, &bytes.Buffer{}, &lockedWriter{w: &log, mu: &mu})
	}()
	var agent state.Agent
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(filepath.Join(dir, "agent.json"))
		if err == nil && json.Unmarshal(data, &agent) == nil {
			mu.Lock()
			out := log.String()
			mu.Unlock()
			if i := strings.Index(out, "listen=127.0.0.1:"); i >= 0 {
				agent.Listen = strings.Fields(out[i+len("listen="):])[0]
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if agent.Listen == "" || agent.Listen == "127.0.0.1:0" {
		t.Fatalf("daemon never reported its port; log:\n%s", log.String())
	}
	// Point agent.json at the bound port so `status` finds the daemon.
	d, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SaveAgent(agent); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if got := runWith(t.Context(), testDeps(nil), []string{"status", "-config-dir", dir}, &stdout, &stderr); got != exitOK {
		t.Fatalf("status = %d; stderr %s", got, stderr.String())
	}
	if !strings.Contains(stdout.String(), "not paired") || !strings.Contains(stdout.String(), "listening on "+agent.Listen) {
		t.Errorf("status output:\n%s", stdout.String())
	}
	stdout.Reset()
	if got := runWith(t.Context(), testDeps(nil), []string{"status", "-config-dir", dir, "-json"}, &stdout, &stderr); got != exitOK {
		t.Fatalf("status -json = %d; stderr %s", got, stderr.String())
	}
	var st ctl.Status
	if err := json.Unmarshal(stdout.Bytes(), &st); err != nil || st.Paired || st.Listen != agent.Listen {
		t.Errorf("status -json = %s (%v)", stdout.String(), err)
	}
	cancel()
	select {
	case code := <-done:
		if code != exitOK {
			t.Fatalf("daemon exited %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not stop")
	}
}

func TestPrintStatus(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	printStatus(&out, ctl.Status{Version: "v1", Listen: "127.0.0.1:7317", Relay: "https://r", UptimeSec: 3661, Paired: true, Presence: &ctl.Presence{IdleMs: 12345, Source: "pty"}, Pairs: []ctl.PairStatus{{
		PhoneName: "Pixel", Fingerprint: "aaaa bbbb", Phone: "connected", PhoneSeenAt: time.Now(), QueueRecords: 2, QueueBytes: 300, Held: 1,
		Uploader: ctl.Link{State: "backoff", LastError: "relay down"}, Stream: ctl.Link{State: "connected"}, SkewSec: -2, IdleThresholdSec: 120,
	}}})
	got := out.String()
	for _, want := range []string{"up 1h1m1s", "terminal input: idle 12s (pty)", `paired with "Pixel" (fingerprint aaaa bbbb)`, "phone: connected since", "queue: 2 records (300 bytes)", "held decides: 1", "uploader: backoff (relay down)", "stream: connected", "clock skew: -2s", "subagent prompts go to the terminal while input is under 120s idle"} {
		if !strings.Contains(got, want) {
			t.Errorf("printStatus output lacks %q:\n%s", want, got)
		}
	}
	out.Reset()
	since := time.Date(2026, 9, 20, 8, 0, 0, 0, time.Local)
	printStatus(&out, ctl.Status{Paired: true, Pairs: []ctl.PairStatus{{PhoneName: "Pixel", Dormant: &ctl.Dormant{
		Reason: "the relay reports the pair revoked", Since: since, DeleteAfter: since.Add(7 * 24 * time.Hour),
	}}}})
	if want := "dormant: the relay reports the pair revoked since 2026-09-20 08:00 — hooks are answered here; run `clair unpair` to confirm, or it is removed after 2026-09-27 08:00"; !strings.Contains(out.String(), want) {
		t.Errorf("dormant output lacks %q:\n%s", want, out.String())
	}
	out.Reset()
	printStatus(&out, ctl.Status{Unpaired: "revoked by the phone"})
	for _, want := range []string{"terminal input: no signal", "not paired (revoked by the phone)"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("unpaired output lacks %q:\n%s", want, out.String())
		}
	}
	out.Reset()
	printStatus(&out, ctl.Status{Paired: true, Pairs: []ctl.PairStatus{{PhoneName: "Pixel"}}})
	if !strings.Contains(out.String(), "subagent prompts are always held for the phone") {
		t.Errorf("rule-off output:\n%s", out.String())
	}
}

// scanAsPhone waits for `clair pair` to print its link, then completes the
// pairing the way the phone does, with the phone's own hooks template.
func scanAsPhone(t *testing.T, stdout func() string, snippet json.RawMessage) {
	t.Helper()
	var link string
	for deadline := time.Now().Add(10 * time.Second); link == "" && time.Now().Before(deadline); {
		for line := range strings.SplitSeq(stdout(), "\n") {
			if line = strings.TrimSpace(line); strings.Contains(line, pairing.PathPage+"#") {
				link = line
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	relayURL, payload, err := pairing.ParseURL(link)
	if err != nil {
		t.Fatalf("no link in stdout (%v):\n%s", err, stdout())
	}
	keys, err := identity.Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	traffic, err := envelope.Derive(keys.Agreement(), payload.HostPub[:], payload.K[:])
	if err != nil {
		t.Fatal(err)
	}
	hello := record.Record{N: 1, Kind: record.KindControl, Control: record.ControlHello, Name: "Pixel 9 Pro", Snippet: snippet}
	plain, err := record.Marshal(&hello)
	if err != nil {
		t.Fatal(err)
	}
	id, err := envelope.NewID(time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env, err := envelope.Seal(traffic.Key(envelope.DirP2H), envelope.Header{Pair: payload.PairingIDString(), ID: id, Dir: envelope.DirP2H, Wake: envelope.WakeSoon, TTLSec: 600}, plain, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client, err := relay.New(keys.Auth(), relay.Options{BaseURL: relayURL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CompletePairing(t.Context(), payload.PairingIDString(), keys.AgreementPublic(), "fcm", env); err != nil {
		t.Fatalf("CompletePairing: %v", err)
	}
}

// `clair pair` end to end in-process: the phone's own snippet is installed
// for a binary whose path the shell must quote, and a settings.json nothing
// can be written to is a failure that says the pair is kept (ADR 2026-09.bckr).
func TestPairInstallsThePhonesHooks(t *testing.T) {
	t.Parallel()

	template, err := os.ReadFile("../../internal/claudecfg/testdata/phone-relay-snippet.json")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, settings string
		wantStatus     int
		wantErr        string
	}{
		{name: "a binary path with a quote and a space", wantStatus: exitOK},
		{name: "a settings.json that is not an object", settings: `[1]`, wantStatus: exitError, wantErr: "clair pair --replace"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fake := relaytest.New()
			t.Cleanup(fake.Close)
			configDir, claudeDir := t.TempDir(), t.TempDir()
			// No daemon: agent.json points at a port nothing listens on.
			dir, oerr := state.Open(configDir)
			if oerr != nil {
				t.Fatal(oerr)
			}
			if _, _, aerr := dir.EnsureAgent(rand.Reader, state.Agent{Listen: "127.0.0.1:1", Relay: fake.URL}); aerr != nil {
				t.Fatal(aerr)
			}
			settings := filepath.Join(claudeDir, "settings.json")
			if tt.settings != "" {
				if werr := os.WriteFile(settings, []byte(tt.settings), 0o600); werr != nil {
					t.Fatal(werr)
				}
			}
			d := testDeps(map[string]string{state.EnvConfigDir: configDir, claudecfg.EnvConfigDir: claudeDir})
			const exe = "/opt/Walter's tools/clair"
			d.exe = func() (string, error) { return exe, nil }
			var mu sync.Mutex
			var stdout, stderr bytes.Buffer
			done := make(chan int, 1)
			go func() {
				done <- runWith(t.Context(), d, []string{"pair", "-qr", "none", "-yes"}, &lockedWriter{w: &stdout, mu: &mu}, &lockedWriter{w: &stderr, mu: &mu})
			}()
			scanAsPhone(t, func() string { mu.Lock(); defer mu.Unlock(); return stdout.String() }, template)
			status := <-done
			mu.Lock()
			defer mu.Unlock()
			if status != tt.wantStatus || !strings.Contains(stderr.String(), tt.wantErr) {
				t.Fatalf("pair = %d, want %d with %q\nstdout:\n%s\nstderr:\n%s", status, tt.wantStatus, tt.wantErr, stdout.String(), stderr.String())
			}
			if pairs, _ := dir.ListPairs(); len(pairs) != 1 {
				t.Errorf("pairs = %d, want the pair kept", len(pairs))
			}
			if tt.wantStatus != exitOK {
				return
			}
			data, err := os.ReadFile(settings)
			if err != nil {
				t.Fatal(err)
			}
			if want, _ := json.Marshal(claudecfg.HookEventCommand(exe)); !bytes.Contains(data, want) || !bytes.Contains(data, []byte(`"url": "http://127.0.0.1:1/clair/v1/hook/decide?timeout=86400"`)) {
				t.Errorf("settings.json lacks the phone's hooks for %q:\n%s", exe, data)
			}
			if strings.Contains(stderr.String(), "refused") {
				t.Errorf("the phone's snippet was refused:\n%s", stderr.String())
			}
		})
	}
}

func TestDefaultQRMode(t *testing.T) {
	t.Parallel()

	env := func(wt string) func(string) string {
		return func(key string) string {
			if key == "WT_SESSION" {
				return wt
			}
			return ""
		}
	}
	tests := []struct {
		name    string
		goos    string
		wt      string
		console bool
		want    pairing.QRMode
	}{
		{name: "linux piped", goos: "linux", want: pairing.QRUnicode},
		{name: "windows console handed to Windows Terminal", goos: "windows", console: true, want: pairing.QRUnicode},
		{name: "windows piped inside Windows Terminal", goos: "windows", wt: "0f1e", want: pairing.QRUnicode},
		{name: "windows piped", goos: "windows", want: pairing.QRASCII},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := defaultQRMode(tt.goos, env(tt.wt), tt.console); got != tt.want {
				t.Errorf("defaultQRMode(%q, WT_SESSION=%q, console=%v) = %q, want %q", tt.goos, tt.wt, tt.console, got, tt.want)
			}
		})
	}
}
