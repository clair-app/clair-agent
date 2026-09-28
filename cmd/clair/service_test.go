package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"claircode.app/clair-agent/internal/service"
	"claircode.app/clair-agent/internal/state"
)

// serviceDeps is testDeps on a given OS, with a real binary to point the
// service at and a home of its own.
func serviceDeps(t *testing.T, goos string, run service.Runner) deps {
	t.Helper()
	d := testDeps(nil)
	root := t.TempDir()
	exe := filepath.Join(root, "bin", "clair")
	if err := os.MkdirAll(filepath.Dir(exe), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	d.exe = func() (string, error) { return exe, nil }
	d.home = func() (string, error) { return filepath.Join(root, "home"), nil }
	d.goos, d.uid, d.tempDir, d.runner = goos, 501, filepath.Join(root, "tmp"), run
	d.sid = func() (string, error) { return "S-1-5-21-1-2-3-1001", nil }
	return d
}

func TestServiceUsage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		wantStatus int
		wantOut    string
		wantErr    string
	}{
		{name: "no verb", args: []string{"service"}, wantStatus: exitUsage, wantErr: "usage: clair service"},
		{name: "unknown verb", args: []string{"service", "enable"}, wantStatus: exitUsage, wantErr: `unknown command "enable"`},
		{name: "help", args: []string{"service", "help"}, wantStatus: exitOK, wantOut: "usage: clair service"},
		{name: "install flags", args: []string{"service", "install", "-h"}, wantStatus: exitOK, wantErr: "-no-start"},
		{name: "only install takes -print", args: []string{"service", "start", "-print"}, wantStatus: exitUsage, wantErr: "flag provided but not defined"},
		{name: "positionals", args: []string{"service", "stop", "now"}, wantStatus: exitUsage, wantErr: "unexpected argument"},
		{name: "an OS without a manager", args: []string{"service", "status", "-config-dir", t.TempDir()}, wantStatus: exitError, wantErr: "under your own supervisor"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			got := runWith(t.Context(), serviceDeps(t, "plan9", nil), tt.args, &stdout, &stderr)
			if got != tt.wantStatus {
				t.Errorf("run(%q) = %d, want %d; stderr %q", tt.args, got, tt.wantStatus, stderr.String())
			}
			if !strings.Contains(stdout.String(), tt.wantOut) || !strings.Contains(stderr.String(), tt.wantErr) {
				t.Errorf("stdout %q, stderr %q; want %q and %q", stdout.String(), stderr.String(), tt.wantOut, tt.wantErr)
			}
		})
	}
}

func TestServiceInstallPrint(t *testing.T) {
	t.Parallel()

	for goos, want := range map[string][]string{
		"linux":   {"ExecStart=", " daemon -config-dir ", "Environment=\"HTTPS_PROXY=http://proxy:3128\""},
		"darwin":  {"<string>-log-file</string>", "Library/Logs/clair/daemon.log", "<key>HTTPS_PROXY</key>"},
		"windows": {"conhost.exe", "-log-file", "<UserId>S-1-5-21-1-2-3-1001</UserId>", " -supervise</Arguments>"},
	} {
		t.Run(goos, func(t *testing.T) {
			t.Parallel()
			if goos == "linux" && runtime.GOOS == "windows" {
				t.Skip("a unit escapes this host's backslashed temp paths; internal/service's goldens cover the rendering")
			}
			d := serviceDeps(t, goos, nil)
			d.getenv = func(k string) string { return map[string]string{"HTTPS_PROXY": "http://proxy:3128"}[k] }
			dir := filepath.Join(t.TempDir(), "clair")
			var stdout, stderr bytes.Buffer
			if got := runWith(t.Context(), d, []string{"service", "install", "-print", "-config-dir", dir}, &stdout, &stderr); got != exitOK {
				t.Fatalf("install -print = %d; stderr %s", got, stderr.String())
			}
			for _, w := range append(want, dir) {
				if !strings.Contains(stdout.String(), w) {
					t.Errorf("printed:\n%s\nwant it to contain %q", stdout.String(), w)
				}
			}
			// systemd and launchd restart a crashed daemon themselves.
			if goos != "windows" && strings.Contains(stdout.String(), "-supervise") {
				t.Errorf("a %s registration runs the supervisor:\n%s", goos, stdout.String())
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Errorf("-print created the config directory: %v", err)
			}
		})
	}

	t.Run("refuses a go run build", func(t *testing.T) {
		t.Parallel()
		d := serviceDeps(t, "linux", nil)
		d.exe = func() (string, error) { return d.tempDir, nil }
		if err := os.MkdirAll(d.tempDir, 0o755); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		if got := runWith(t.Context(), d, []string{"service", "install", "-print"}, &stdout, &stderr); got != exitError || !strings.Contains(stderr.String(), "temporary build") {
			t.Errorf("install from the temp dir = %d, stderr %q; want a refusal", got, stderr.String())
		}
	})
}

// systemctl fakes a user manager whose start runs a real daemon in this
// process, so install, status and stop meet the agent they would.
type systemctl struct {
	t   *testing.T
	dir string

	mu      sync.Mutex
	running bool
	stop    context.CancelFunc
	done    chan int
}

func (s *systemctl) run(ctx context.Context, name string, args ...string) (service.Result, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	s.mu.Lock()
	defer s.mu.Unlock()
	switch line {
	case "systemctl --user start clair.service":
		if !s.running {
			daemonCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
			s.running, s.stop, s.done = true, cancel, make(chan int, 1)
			done := s.done
			go func() {
				done <- runWith(daemonCtx, testDeps(nil), []string{"daemon", "-config-dir", s.dir}, &bytes.Buffer{}, &bytes.Buffer{})
			}()
		}
	case "systemctl --user stop clair.service", "systemctl --user disable --now clair.service":
		if s.running {
			s.stop()
			if code := <-s.done; code != exitOK {
				s.t.Errorf("daemon exited %d", code)
			}
			s.running = false
		}
	case "systemctl --user is-active clair.service":
		if !s.running {
			return service.Result{Code: 3, Out: []byte("inactive\n")}, nil
		}
		return service.Result{Out: []byte("active\n")}, nil
	}
	return service.Result{}, nil
}

// freeAddr is a loopback address nothing listens on.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// freeAgent writes an agent.json on a loopback port nothing listens on.
func freeAgent(t *testing.T, dir string) state.Agent {
	t.Helper()
	d, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	agent, _, err := d.EnsureAgent(testDeps(nil).entropy, state.Agent{Listen: freeAddr(t), Relay: "https://relay.test", LogLevel: "info"})
	if err != nil {
		t.Fatal(err)
	}
	return agent
}

func TestServiceLifecycle(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	agent := freeAgent(t, dir)
	fake := &systemctl{t: t, dir: dir}
	d := serviceDeps(t, "linux", fake.run)
	step := func(want int, args ...string) string {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if got := runWith(t.Context(), d, append(append([]string{"service"}, args...), "-config-dir", dir), &stdout, &stderr); got != want {
			t.Fatalf("service %s = %d, want %d; stdout %q, stderr %q", args, got, want, stdout.String(), stderr.String())
		}
		return stdout.String()
	}

	if out := step(exitUnreachable, "status"); !strings.Contains(out, "not installed") {
		t.Errorf("status before install:\n%s", out)
	}
	out := step(exitOK, "install")
	for _, w := range []string{"Installed the systemd user unit", "is running: clair", "on " + agent.Listen, "journalctl --user -u clair", "Next: `clair pair`"} {
		if !strings.Contains(out, w) {
			t.Errorf("install said:\n%s\nwant %q", out, w)
		}
	}
	if out := step(exitOK, "install"); !strings.Contains(out, "already installed") || fake.done == nil {
		t.Errorf("a second install said:\n%s", out)
	}
	if out := step(exitOK, "status"); !strings.Contains(out, "clair.service, active") || !strings.Contains(out, "answering on "+agent.Listen) {
		t.Errorf("status while running:\n%s", out)
	}
	if out := step(exitOK, "stop"); !strings.Contains(out, "stopped") {
		t.Errorf("stop said:\n%s", out)
	}
	if out := step(exitUnreachable, "status"); !strings.Contains(out, "inactive") || !strings.Contains(out, "not answering") {
		t.Errorf("status after stop:\n%s", out)
	}
	step(exitOK, "start")
	if out := step(exitOK, "uninstall"); !strings.Contains(out, "Removed the systemd user unit") {
		t.Errorf("uninstall said:\n%s", out)
	}
	if fake.running {
		t.Error("the daemon still runs after uninstall")
	}
	if out := step(exitOK, "uninstall"); !strings.Contains(out, "not installed") {
		t.Errorf("a second uninstall said:\n%s", out)
	}
}

// A first install writes agent.json, and with it the admin token the
// readiness check must present: `curl | sh` on a new machine.
func TestServiceInstallOnANewMachine(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "clair")
	fake := &systemctl{t: t, dir: dir}
	d := serviceDeps(t, "linux", fake.run)
	d.listen = freeAddr(t)
	var stdout, stderr bytes.Buffer
	if got := runWith(t.Context(), d, []string{"service", "install", "-config-dir", dir}, &stdout, &stderr); got != exitOK || !strings.Contains(stdout.String(), "is running: clair") {
		t.Errorf("install = %d; stdout %q, stderr %q", got, stdout.String(), stderr.String())
	}
	if agent, ok := readAgent(dir); !ok || agent.Listen != d.listen || agent.AdminToken == "" {
		t.Errorf("agent.json = %+v, %v; want one on %s with an admin token", agent, ok, d.listen)
	}
	runWith(t.Context(), d, []string{"service", "uninstall", "-config-dir", dir}, &bytes.Buffer{}, &bytes.Buffer{})
}

func TestServiceInstallRefusesWhileATerminalDaemonAnswers(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	freeAgent(t, dir)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan int, 1)
	go func() {
		done <- runWith(ctx, testDeps(nil), []string{"daemon", "-config-dir", dir}, &bytes.Buffer{}, &bytes.Buffer{})
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	agent, _ := readAgent(dir)
	control := controlClient(agent)
	deadline := time.Now().Add(5 * time.Second)
	for _, err := control.Status(t.Context()); err != nil; _, err = control.Status(t.Context()) {
		if time.Now().After(deadline) {
			t.Fatalf("the terminal daemon never answered: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	fake := &systemctl{t: t, dir: dir}
	d := serviceDeps(t, "linux", fake.run)
	var stdout, stderr bytes.Buffer
	if got := runWith(t.Context(), d, []string{"service", "install", "-config-dir", dir}, &stdout, &stderr); got != exitError || !strings.Contains(stderr.String(), "already answering") {
		t.Errorf("install = %d, stderr %q; want a refusal", got, stderr.String())
	}
	home, _ := d.home()
	if _, err := os.Stat(filepath.Join(home, ".config", "systemd", "user", "clair.service")); !os.IsNotExist(err) {
		t.Errorf("a unit was written anyway: %v", err)
	}
}
