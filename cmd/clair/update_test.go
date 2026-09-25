package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"claircode.app/clair-agent/internal/ctl"
	"claircode.app/clair-agent/internal/state"
	"claircode.app/clair-agent/internal/update"
)

var releaseKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))

// fakeBuild is a "binary" that is exactly what its `version` prints.
func fakeBuild(version string) []byte {
	return []byte("clair " + version + " (fake, 2026-09-24T00:00:00Z)\n")
}

func readVersion(_ context.Context, path string) (string, error) {
	data, err := os.ReadFile(path)
	return string(data), err
}

// serveRelease serves one signed release of this host's build as
// claircode.app lays it out, signed with releaseKey.
func serveRelease(t *testing.T, version string) string {
	t.Helper()
	asset := update.AssetName(version, runtime.GOOS, runtime.GOARCH)
	build := fakeBuild(version)
	sum := sha256.Sum256(build)
	sums := []byte(hex.EncodeToString(sum[:]) + "  " + asset + "\n")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /latest.txt", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, version) })
	mux.HandleFunc("GET /"+version+"/SHA256SUMS.txt", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(sums) })
	mux.HandleFunc("GET /"+version+"/SHA256SUMS.txt.sig", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, update.Sign(releaseKey, sums))
	})
	mux.HandleFunc("GET /"+version+"/"+asset, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(build) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// updateDeps is a release build, v0.1.0, installed at exe.
func updateDeps(env map[string]string, exe string) deps {
	d := testDeps(env)
	d.exe = func() (string, error) { return exe, nil }
	d.goos, d.goarch = runtime.GOOS, runtime.GOARCH
	d.release = "v0.1.0"
	d.releaseTestKey = base64.StdEncoding.EncodeToString(releaseKey[ed25519.SeedSize:])
	d.runVersion = readVersion
	return d
}

func installFake(t *testing.T, version string) string {
	t.Helper()
	exe := filepath.Join(t.TempDir(), "clair")
	if err := os.WriteFile(exe, fakeBuild(version), 0o755); err != nil {
		t.Fatal(err)
	}
	return exe
}

// closedPort is a loopback address nothing listens on.
func closedPort(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func TestUpdateWithoutADaemon(t *testing.T) {
	t.Parallel()

	releases := serveRelease(t, "v0.2.0")
	// One config dir has no agent.json; one names a daemon that is not
	// running; one a daemon from before the self-updater, which answers 404.
	// Every time, the command does the check itself.
	older := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(older.Close)
	withAgent := func(listen string) string {
		dir := t.TempDir()
		agent, err := json.Marshal(state.Agent{V: 1, Listen: listen, AdminToken: "x"})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "agent.json"), agent, 0o600); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	for _, configDir := range []string{t.TempDir(), withAgent(closedPort(t)), withAgent(strings.TrimPrefix(older.URL, "http://"))} {
		exe := installFake(t, "v0.1.0")
		d := updateDeps(map[string]string{state.EnvConfigDir: configDir}, exe)
		steps := []struct {
			args     []string
			want     int
			stdout   string
			onDisk   string
			stderrIn string
		}{
			{args: []string{"update", "-check", "-releases", releases}, want: exitOK, stdout: "clair v0.2.0 is available (this is v0.1.0)", onDisk: "v0.1.0"},
			{args: []string{"update", "-releases", releases}, want: exitOK, stdout: "Installed clair v0.2.0 at " + exe, onDisk: "v0.2.0"},
			{args: []string{"update", "-releases", releases}, want: exitOK, stdout: "clair v0.2.0 is already installed at " + exe, onDisk: "v0.2.0"},
		}
		for _, st := range steps {
			var stdout, stderr bytes.Buffer
			if got := runWith(t.Context(), d, st.args, &stdout, &stderr); got != st.want || !strings.Contains(stdout.String(), st.stdout) {
				t.Fatalf("%v = %d\nstdout: %s\nstderr: %s\nwant %d and %q", st.args, got, stdout.String(), stderr.String(), st.want, st.stdout)
			}
			if data, _ := os.ReadFile(exe); !bytes.Equal(data, fakeBuild(st.onDisk)) {
				t.Fatalf("after %v the binary is %q, want %s", st.args, data, st.onDisk)
			}
		}
	}
}

func TestUpdateRefusals(t *testing.T) {
	t.Parallel()

	releases := serveRelease(t, "v0.2.0")
	exe := installFake(t, "v0.1.0")

	dev := updateDeps(map[string]string{state.EnvConfigDir: t.TempDir()}, exe)
	dev.release = "v0.1.0-4-gabc1234"
	var stdout, stderr bytes.Buffer
	if got := runWith(t.Context(), dev, []string{"update", "-releases", releases}, &stdout, &stderr); got != exitError || !strings.Contains(stderr.String(), "development build (v0.1.0-4-gabc1234)") {
		t.Errorf("a development build: %d %q", got, stderr.String())
	}

	// Signed by a key this build does not have.
	unknown := updateDeps(map[string]string{state.EnvConfigDir: t.TempDir()}, exe)
	unknown.releaseTestKey = ""
	stdout.Reset()
	stderr.Reset()
	if got := runWith(t.Context(), unknown, []string{"update", "-releases", releases}, &stdout, &stderr); got != exitError || !strings.Contains(stderr.String(), "bad release signature") {
		t.Errorf("an unknown key: %d %q", got, stderr.String())
	}
	if data, _ := os.ReadFile(exe); !bytes.Equal(data, fakeBuild("v0.1.0")) {
		t.Errorf("a refused update changed the binary to %q", data)
	}

	stderr.Reset()
	if got := runWith(t.Context(), unknown, []string{"update", "extra"}, &stdout, &stderr); got != exitUsage {
		t.Errorf("a positional argument = %d, want %d", got, exitUsage)
	}
}

// TestUpdateThroughTheDaemon: `clair update` asks the running daemon, which
// replaces its own binary, keeps running, and says so in `clair status`.
func TestUpdateThroughTheDaemon(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	exe := installFake(t, "v0.1.0")
	releases := serveRelease(t, "v0.2.0")
	d := updateDeps(map[string]string{state.EnvConfigDir: dir}, exe)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	var mu sync.Mutex
	var daemonErr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- runWith(ctx, d, []string{"daemon", "-listen", "127.0.0.1:0"}, &bytes.Buffer{}, &lockedWriter{w: &daemonErr, mu: &mu})
	}()
	// agent.json names 127.0.0.1:0 until the daemon rewrites it; the bound
	// address is in the daemon's log.
	var addr string
	for deadline := time.Now().Add(5 * time.Second); addr == "" && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		mu.Lock()
		out := daemonErr.String()
		mu.Unlock()
		if i := strings.Index(out, "listen=127.0.0.1:"); i >= 0 {
			addr = strings.Fields(out[i+len("listen="):])[0]
		}
	}
	if addr == "" {
		t.Fatalf("daemon never reported its address:\n%s", daemonErr.String())
	}
	dirState, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	agent, err := dirState.LoadAgent()
	if err != nil {
		t.Fatal(err)
	}
	agent.Listen = addr
	if err := dirState.SaveAgent(agent); err != nil {
		t.Fatal(err)
	}

	// The daemon, not this process, does it: this command's own version is
	// irrelevant, so make it one that would refuse.
	cli := d
	cli.release = "dev"
	var stdout, stderr bytes.Buffer
	if got := runWith(t.Context(), cli, []string{"update", "-releases", releases}, &stdout, &stderr); got != exitOK {
		t.Fatalf("update = %d\nstdout: %s\nstderr: %s", got, stdout.String(), stderr.String())
	}
	for _, want := range []string{"Installed clair v0.2.0 at " + exe, "The agent runs v0.1.0 until it restarts; `clair service restart` switches now."} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("update output lacks %q:\n%s", want, stdout.String())
		}
	}
	if data, _ := os.ReadFile(exe); !bytes.Equal(data, fakeBuild("v0.2.0")) {
		t.Errorf("the binary is %q, want v0.2.0", data)
	}

	stdout.Reset()
	if got := runWith(t.Context(), cli, []string{"status"}, &stdout, &stderr); got != exitOK {
		t.Fatalf("status = %d: %s", got, stderr.String())
	}
	if want := "updates: clair v0.2.0 is installed and runs from the next start"; !strings.Contains(stdout.String(), want) {
		t.Errorf("status lacks %q:\n%s", want, stdout.String())
	}

	cancel()
	select {
	case code := <-done:
		if code != exitOK {
			t.Fatalf("daemon exited %d:\n%s", code, daemonErr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not stop")
	}
}

func TestVersionSaysTestKey(t *testing.T) {
	t.Parallel()

	d := testDeps(nil)
	d.releaseTestKey = "AAAA"
	var stdout bytes.Buffer
	if got := runWith(t.Context(), d, []string{"version"}, &stdout, &bytes.Buffer{}); got != exitOK || !strings.HasSuffix(stdout.String(), "\n"+testKeyLine+"\n") {
		t.Errorf("version = %d %q, want the test-key line last", got, stdout.String())
	}
}

func TestPrintUpdateStatus(t *testing.T) {
	t.Parallel()

	at := time.Date(2026, 9, 24, 9, 30, 0, 0, time.Local)
	tests := []struct {
		name string
		st   *ctl.UpdateStatus
		want []string
	}{
		{name: "an older daemon says nothing", st: nil, want: nil},
		{name: "off", st: &ctl.UpdateStatus{Off: "this is a development build (dev)"}, want: []string{"updates: off — this is a development build (dev)"}},
		{name: "not checked", st: &ctl.UpdateStatus{}, want: []string{"updates: not checked yet"}},
		{name: "up to date", st: &ctl.UpdateStatus{Latest: "v0.1.0", LastCheckAt: at}, want: []string{"updates: up to date (latest v0.1.0, checked 2026-09-24 09:30:00)"}},
		{name: "staged", st: &ctl.UpdateStatus{Latest: "v0.2.0", Staged: "v0.2.0", LastCheckAt: at}, want: []string{"updates: clair v0.2.0 is installed and runs from the next start (`clair service restart`)"}},
		{name: "failed", st: &ctl.UpdateStatus{LastError: "update: bad release signature", LastCheckAt: at}, want: []string{"updates: the check at 2026-09-24 09:30:00 failed (update: bad release signature)"}},
		{name: "left alone", st: &ctl.UpdateStatus{Note: "/opt/clair is already v0.3.0", LastCheckAt: at}, want: []string{"updates: /opt/clair is already v0.3.0"}},
		{name: "paused", st: &ctl.UpdateStatus{Paused: true}, want: []string{"updates: not checked yet", "background checks are off (autoUpdate in agent.json)"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			printUpdateStatus(&out, tt.st)
			if tt.want == nil && out.Len() > 0 {
				t.Fatalf("printed %q, want nothing", out.String())
			}
			for _, w := range tt.want {
				if !strings.Contains(out.String(), w) {
					t.Errorf("output lacks %q:\n%s", w, out.String())
				}
			}
		})
	}
}

func TestPrintSkew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		self string
		st   ctl.Status
		want bool
	}{
		{name: "the same release", self: "v0.2.0", st: ctl.Status{Version: "v0.2.0"}},
		{name: "a newer binary on disk", self: "v0.2.0", st: ctl.Status{Version: "v0.1.0"}, want: true},
		{name: "the staged release is already said", self: "v0.2.0", st: ctl.Status{Version: "v0.1.0", Update: &ctl.UpdateStatus{Staged: "v0.2.0"}}},
		{name: "a development command", self: "dev", st: ctl.Status{Version: "v0.1.0"}},
		{name: "a development daemon", self: "v0.2.0", st: ctl.Status{Version: "v0.2.0-1-gabc"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			printSkew(&out, tt.self, tt.st)
			if got := out.Len() > 0; got != tt.want {
				t.Errorf("printed %q, want a note: %v", out.String(), tt.want)
			}
		})
	}
}
