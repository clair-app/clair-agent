package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"claircode.app/clair-agent/internal/state"
)

func testDeps(env map[string]string) deps {
	return deps{
		getenv:  func(k string) string { return env[k] },
		now:     time.Now,
		entropy: rand.Reader,
		stdin:   strings.NewReader(""),
		exe:     func() (string, error) { return "/opt/clair/clair", nil },
		home:    func() (string, error) { return "/home/nobody", nil },
	}
}

func TestRun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		wantStatus int
		wantOut    string // substring of stdout
		wantErr    string // substring of stderr
	}{
		{name: "no args prints usage to stderr", args: nil, wantStatus: exitUsage, wantErr: "usage: clair"},
		{name: "version", args: []string{"version"}, wantStatus: exitOK, wantOut: "clair "},
		{name: "help", args: []string{"help"}, wantStatus: exitOK, wantOut: "usage: clair"},
		{name: "-h", args: []string{"-h"}, wantStatus: exitOK, wantOut: "usage: clair"},
		{name: "unknown command", args: []string{"frobnicate"}, wantStatus: exitUsage, wantErr: `unknown command "frobnicate"`},
		{name: "daemon rejects positional arguments", args: []string{"daemon", "extra"}, wantStatus: exitUsage, wantErr: "unexpected argument"},
		{name: "daemon rejects unknown flags", args: []string{"daemon", "-nope"}, wantStatus: exitUsage, wantErr: "flag provided but not defined"},
		{name: "daemon help", args: []string{"daemon", "-h"}, wantStatus: exitOK, wantErr: "-config-dir"},
		{name: "statusline help", args: []string{"statusline", "-h"}, wantStatus: exitOK, wantErr: "-config-dir"},
		{name: "statusline without a config dir runs quietly", args: []string{"statusline", "-config-dir", "/nonexistent/clair"}, wantStatus: exitOK},
		{name: "hook-event without a config dir never fails", args: []string{"hook-event", "-config-dir", "/nonexistent/clair", "/clair/v1/hook/event"}, wantStatus: exitOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer
			got := runWith(t.Context(), testDeps(nil), tt.args, &stdout, &stderr)

			if got != tt.wantStatus {
				t.Errorf("run(%q) = %d, want %d", tt.args, got, tt.wantStatus)
			}
			if !strings.Contains(stdout.String(), tt.wantOut) {
				t.Errorf("stdout = %q, want substring %q", stdout.String(), tt.wantOut)
			}
			if !strings.Contains(stderr.String(), tt.wantErr) {
				t.Errorf("stderr = %q, want substring %q", stderr.String(), tt.wantErr)
			}
		})
	}
}

func TestDaemonServesAndStops(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	var stderr bytes.Buffer
	var mu sync.Mutex
	locked := &lockedWriter{w: &stderr, mu: &mu}
	done := make(chan int, 1)
	go func() {
		done <- runWith(ctx, testDeps(map[string]string{state.EnvConfigDir: dir}), []string{"daemon", "-listen", "127.0.0.1:0", "-log-level", "debug"}, &bytes.Buffer{}, locked)
	}()

	// agent.json appears once the daemon has opened its config; the bound
	// address is in the log line.
	var agent state.Agent
	var addr string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(filepath.Join(dir, "agent.json"))
		if err == nil && json.Unmarshal(data, &agent) == nil {
			mu.Lock()
			out := stderr.String()
			mu.Unlock()
			if i := strings.Index(out, "listen=127.0.0.1:"); i >= 0 {
				addr = strings.Fields(out[i+len("listen="):])[0]
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == "" {
		t.Fatalf("daemon never reported its address; stderr:\n%s", stderr.String())
	}
	if agent.Token == "" || agent.AdminToken == "" || agent.Relay == "" {
		t.Fatalf("agent.json = %+v, want tokens and a relay", agent)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	get := func(path, auth string) int {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+addr+path, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if code := get("/", ""); code != http.StatusNotFound {
		t.Errorf("GET / = %d, want 404", code)
	}
	if code := get("/clair/v1/status", ""); code != http.StatusUnauthorized {
		t.Errorf("GET /clair/v1/status without a bearer = %d, want 401", code)
	}
	if code := get("/clair/v1/status", agent.Token); code != http.StatusOK {
		t.Errorf("GET /clair/v1/status = %d, want 200", code)
	}
	if code := get("/clair/ctl/status", agent.AdminToken); code != http.StatusOK {
		t.Errorf("GET /clair/ctl/status = %d, want 200", code)
	}

	cancel()
	select {
	case code := <-done:
		if code != exitOK {
			t.Fatalf("daemon exited %d; stderr:\n%s", code, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not stop after its context ended")
	}
}

// lockedWriter lets the test read stderr while the daemon writes it.
type lockedWriter struct {
	w  *bytes.Buffer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func TestBuildVersionFallsBackToDefaults(t *testing.T) {
	t.Parallel()

	ver, rev := buildVersion()
	if ver == "" || rev == "" {
		t.Fatalf("buildVersion() = (%q, %q), want both non-empty", ver, rev)
	}
}

func TestNewLoggerLevels(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"", "debug", "INFO", "warn", "error"} {
		if _, err := newLogger(&bytes.Buffer{}, name, ""); err != nil {
			t.Errorf("newLogger(%q): %v", name, err)
		}
	}
	if _, err := newLogger(&bytes.Buffer{}, "loud", ""); err == nil {
		t.Error("newLogger(loud): want an error")
	}
	if _, err := newLogger(&bytes.Buffer{}, "", "warn"); err != nil {
		t.Errorf("newLogger with the file's level: %v", err)
	}
}

// A hangup ends a command through its context like Ctrl-C does, so `clair
// pair` can revoke what it has not saved — unless SIGHUP is ignored (nohup).
func TestStopSignalsIncludeTheHangup(t *testing.T) {
	t.Parallel()

	sigs := stopSignals()
	if !slices.Contains(sigs, os.Interrupt) || !slices.Contains(sigs, os.Signal(syscall.SIGTERM)) {
		t.Errorf("stopSignals = %v, want SIGINT and SIGTERM", sigs)
	}
	if got, want := slices.Contains(sigs, os.Signal(syscall.SIGHUP)), !signal.Ignored(syscall.SIGHUP); got != want {
		t.Errorf("SIGHUP in stopSignals = %v, want %v (ignored: %v)", got, want, !want)
	}
}
