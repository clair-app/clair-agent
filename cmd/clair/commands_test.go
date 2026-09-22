package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"claircode.app/clair-agent/internal/ctl"
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
	printStatus(&out, ctl.Status{Version: "v1", Listen: "127.0.0.1:7317", Relay: "https://r", UptimeSec: 3661, Paired: true, Pairs: []ctl.PairStatus{{
		PhoneName: "Pixel", Fingerprint: "aaaa bbbb", Phone: "connected", PhoneSeenAt: time.Now(), QueueRecords: 2, QueueBytes: 300, Held: 1,
		Uploader: ctl.Link{State: "backoff", LastError: "relay down"}, Stream: ctl.Link{State: "connected"}, SkewSec: -2,
	}}})
	got := out.String()
	for _, want := range []string{"up 1h1m1s", `paired with "Pixel" (fingerprint aaaa bbbb)`, "phone: connected since", "queue: 2 records (300 bytes)", "held decides: 1", "uploader: backoff (relay down)", "stream: connected", "clock skew: -2s"} {
		if !strings.Contains(got, want) {
			t.Errorf("printStatus output lacks %q:\n%s", want, got)
		}
	}
	out.Reset()
	printStatus(&out, ctl.Status{Unpaired: "revoked by the phone"})
	if !strings.Contains(out.String(), "not paired (revoked by the phone)") {
		t.Errorf("unpaired output:\n%s", out.String())
	}
}
