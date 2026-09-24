package service

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"claircode.app/clair-agent/internal/ctl"
)

// fakeRunner answers commands from a table keyed by the joined command
// line, in order when a line has several answers, and records every call.
// An unlisted command succeeds with no output.
type fakeRunner struct {
	mu      sync.Mutex
	answers map[string][]Result
	calls   []string
}

func newFakeRunner() *fakeRunner { return &fakeRunner{answers: make(map[string][]Result)} }

// on queues answers for a command line.
func (f *fakeRunner) on(line string, answers ...Result) *fakeRunner {
	f.answers[line] = append(f.answers[line], answers...)
	return f
}

func (f *fakeRunner) run(_ context.Context, name string, args ...string) (Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	line := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, line)
	queue := f.answers[line]
	if len(queue) == 0 {
		return Result{}, nil
	}
	res := queue[0]
	if len(queue) > 1 {
		f.answers[line] = queue[1:]
	}
	return res, nil
}

// fakeDaemon is the control surface: up until asked to stop.
type fakeDaemon struct {
	mu    sync.Mutex
	up    bool
	stops int
}

func (d *fakeDaemon) Status(context.Context) (ctl.Status, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.up {
		return ctl.Status{}, ctl.ErrUnreachable
	}
	return ctl.Status{Version: "test"}, nil
}

func (d *fakeDaemon) Stop(context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.up {
		return ctl.ErrUnreachable
	}
	d.stops++
	d.up = false
	return nil
}

func checkCalls(t *testing.T, r *fakeRunner, want ...string) {
	t.Helper()
	if !slices.Equal(r.calls, want) {
		t.Errorf("commands run:\n  %s\nwant:\n  %s", strings.Join(r.calls, "\n  "), strings.Join(want, "\n  "))
	}
	r.calls = nil
}

var spec = Spec{Exe: "/opt/clair/clair", Args: []string{"daemon", "-config-dir", "/cfg"}}

func TestSystemd(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	t.Run("install writes, reloads and enables, then only enables", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner()
		env := testEnv(t.TempDir(), nil)
		env.Run = r.run
		m := newSystemd(env)
		changed, err := m.Install(ctx, spec)
		if err != nil || !changed {
			t.Fatalf("Install = %v, %v; want changed", changed, err)
		}
		checkCalls(t, r, "systemctl --user show --property=Version", "systemctl --user daemon-reload", "systemctl --user enable clair.service")
		unit, _ := os.ReadFile(m.Path())
		if !bytes.Contains(unit, []byte("ExecStart=/opt/clair/clair daemon -config-dir /cfg\n")) {
			t.Errorf("unit = %s, want the spec's ExecStart", unit)
		}
		if changed, err = m.Install(ctx, spec); err != nil || changed {
			t.Fatalf("second Install = %v, %v; want unchanged", changed, err)
		}
		checkCalls(t, r, "systemctl --user show --property=Version", "systemctl --user enable clair.service")

		if err := m.Restart(ctx); err != nil {
			t.Fatal(err)
		}
		checkCalls(t, r, "systemctl --user restart clair.service")

		if err := m.Uninstall(ctx); err != nil {
			t.Fatal(err)
		}
		checkCalls(t, r, "systemctl --user show --property=Version", "systemctl --user disable --now clair.service",
			"systemctl --user reset-failed clair.service", "systemctl --user daemon-reload")
		if exists(m.Path()) {
			t.Error("the unit is still there after Uninstall")
		}
	})

	t.Run("no user manager writes nothing", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner().on("systemctl --user show --property=Version", Result{Code: 1, Out: []byte("Failed to connect to bus: No medium found")})
		env := testEnv(t.TempDir(), nil)
		env.Run = r.run
		m := newSystemd(env)
		if _, err := m.Install(ctx, spec); !errors.Is(err, ErrNoManager) {
			t.Fatalf("Install: %v, want ErrNoManager", err)
		}
		if exists(m.Path()) {
			t.Error("a unit was written without a manager to load it")
		}
	})

	t.Run("a failed command is an error with its output", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner().on("systemctl --user enable clair.service", Result{Code: 1, Out: []byte("Access denied")})
		env := testEnv(t.TempDir(), nil)
		env.Run = r.run
		if _, err := newSystemd(env).Install(ctx, spec); err == nil || !strings.Contains(err.Error(), "Access denied") {
			t.Errorf("Install: %v, want the enable's output", err)
		}
	})

	t.Run("state and verbs before install", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner().on("systemctl --user is-active clair.service", Result{Code: 3, Out: []byte("failed\n")})
		env := testEnv(t.TempDir(), nil)
		env.Run = r.run
		m := newSystemd(env)
		if st, err := m.State(ctx); err != nil || st.Installed {
			t.Errorf("State before install = %+v, %v; want not installed", st, err)
		}
		for _, verb := range []func(context.Context) error{m.Start, m.Stop, m.Restart, m.Uninstall} {
			if err := verb(ctx); !errors.Is(err, ErrNotInstalled) {
				t.Errorf("verb before install: %v, want ErrNotInstalled", err)
			}
		}
		if _, err := m.Install(ctx, spec); err != nil {
			t.Fatal(err)
		}
		if st, err := m.State(ctx); err != nil || !st.Installed || st.Running || st.Detail != "failed" {
			t.Errorf("State = %+v, %v; want installed, not running, failed", st, err)
		}
	})
}

func TestLaunchd(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	const (
		domain = "launchctl print gui/501"
		target = "launchctl print gui/501/app.claircode.clair"
	)
	notLoaded := Result{Code: 113, Out: []byte("Could not find service")}
	running := Result{Out: []byte("gui/501/app.claircode.clair = {\n\tstate = running\n}")}

	t.Run("install then start bootstraps; restart kicks", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner().on(target, notLoaded, notLoaded, running)
		env := testEnv(t.TempDir(), nil)
		env.Run = r.run
		m := newLaunchd(env)
		if changed, err := m.Install(ctx, spec); err != nil || !changed {
			t.Fatalf("Install = %v, %v; want changed", changed, err)
		}
		checkCalls(t, r, domain, target)
		if info, err := os.Stat(filepath.Dir(m.LogFile())); err != nil || info.Mode().Perm() != 0o700 {
			t.Errorf("log directory: %v, %v; want it made 0700", info, err)
		}
		if err := m.Start(ctx); err != nil {
			t.Fatal(err)
		}
		checkCalls(t, r, target, domain, "launchctl bootstrap gui/501 "+m.Path())
		if err := m.Restart(ctx); err != nil {
			t.Fatal(err)
		}
		checkCalls(t, r, target, "launchctl kickstart -k gui/501/app.claircode.clair")
	})

	t.Run("a changed plist unloads the running agent", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner().on(target, running)
		env := testEnv(t.TempDir(), nil)
		env.Run = r.run
		m := newLaunchd(env)
		if _, err := m.Install(ctx, spec); err != nil {
			t.Fatal(err)
		}
		checkCalls(t, r, domain, target, "launchctl bootout gui/501/app.claircode.clair")
		if changed, err := m.Install(ctx, spec); err != nil || changed {
			t.Fatalf("second Install = %v, %v; want unchanged", changed, err)
		}
		checkCalls(t, r, domain)
	})

	t.Run("stop and uninstall boot the agent out", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner().on(target, notLoaded, running, running)
		env := testEnv(t.TempDir(), nil)
		env.Run = r.run
		m := newLaunchd(env)
		if _, err := m.Install(ctx, spec); err != nil {
			t.Fatal(err)
		}
		r.calls = nil
		if st, err := m.State(ctx); err != nil || !st.Running {
			t.Errorf("State = %+v, %v; want running", st, err)
		}
		if err := m.Uninstall(ctx); err != nil {
			t.Fatal(err)
		}
		checkCalls(t, r, target, target, "launchctl bootout gui/501/app.claircode.clair")
		if exists(m.Path()) {
			t.Error("the plist is still there after Uninstall")
		}
	})

	t.Run("no GUI domain", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner().on(domain, Result{Code: 113})
		env := testEnv(t.TempDir(), nil)
		env.Run = r.run
		if _, err := newLaunchd(env).Install(ctx, spec); !errors.Is(err, ErrNoManager) {
			t.Errorf("Install: %v, want ErrNoManager", err)
		}
	})
}

func TestTaskScheduler(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	const query = "schtasks /Query /TN clair"
	missing := Result{Code: 1, Out: []byte("ERROR: The system cannot find the file specified.")}

	newTask := func(t *testing.T, r *fakeRunner, d *fakeDaemon) *taskScheduler {
		t.Helper()
		env := testEnv(t.TempDir(), make(map[string]string))
		env.Run = r.run
		if d != nil {
			env.Daemon = d
		}
		return newTaskScheduler(env)
	}

	t.Run("install registers the UTF-16 XML once", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner().on(query, missing, Result{})
		m := newTask(t, r, nil)
		if changed, err := m.Install(ctx, spec); err != nil || !changed {
			t.Fatalf("Install = %v, %v; want changed", changed, err)
		}
		checkCalls(t, r, query, "schtasks /Create /TN clair /XML "+m.xmlPath()+" /F")
		data, _ := os.ReadFile(m.xmlPath())
		text, _ := m.Render(spec)
		if !bytes.Equal(data, utf16LE(text)) {
			t.Error("the registered XML is not the rendering in UTF-16")
		}
		if !bytes.Contains(text, []byte("<UserId>"+testSID+"</UserId>")) {
			t.Errorf("task XML names no principal:\n%s", text)
		}
		if changed, err := m.Install(ctx, spec); err != nil || changed {
			t.Fatalf("second Install = %v, %v; want unchanged", changed, err)
		}
		checkCalls(t, r, query)
	})

	t.Run("a task deleted by hand is registered again", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner()
		m := newTask(t, r, nil)
		if _, err := m.Install(ctx, spec); err != nil {
			t.Fatal(err)
		}
		r.on(query, missing)
		r.calls = nil
		if changed, err := m.Install(ctx, spec); err != nil || !changed {
			t.Fatalf("Install = %v, %v; want registered again", changed, err)
		}
		checkCalls(t, r, query, "schtasks /Create /TN clair /XML "+m.xmlPath()+" /F")
	})

	t.Run("a refused registration leaves no copy behind", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner().on(query, missing)
		m := newTask(t, r, nil)
		r.on("schtasks /Create /TN clair /XML "+m.xmlPath()+" /F", Result{Code: 1, Out: []byte("ERROR: Access is denied.")})
		if _, err := m.Install(ctx, spec); err == nil || !strings.Contains(err.Error(), "Access is denied") {
			t.Fatalf("Install: %v, want the refusal", err)
		}
		if exists(m.xmlPath()) {
			t.Error("the XML copy survived a refused registration")
		}
	})

	t.Run("stop asks the daemon first, then ends the task", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner()
		d := &fakeDaemon{up: true}
		m := newTask(t, r, d)
		if st, err := m.State(ctx); err != nil || !st.Installed || !st.Running {
			t.Errorf("State = %+v, %v; want installed and running", st, err)
		}
		r.calls = nil
		if err := m.Stop(ctx); err != nil {
			t.Fatal(err)
		}
		if d.stops != 1 {
			t.Errorf("the daemon was asked to stop %d times, want once", d.stops)
		}
		checkCalls(t, r, query, "schtasks /End /TN clair")
		if err := m.Restart(ctx); err != nil {
			t.Fatal(err)
		}
		checkCalls(t, r, query, "schtasks /End /TN clair", "schtasks /Run /TN clair")
	})

	t.Run("uninstall stops and deletes", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner()
		m := newTask(t, r, &fakeDaemon{up: true})
		if _, err := m.Install(ctx, spec); err != nil {
			t.Fatal(err)
		}
		r.calls = nil
		if err := m.Uninstall(ctx); err != nil {
			t.Fatal(err)
		}
		checkCalls(t, r, query, query, "schtasks /End /TN clair", "schtasks /Delete /TN clair /F")
		if exists(m.xmlPath()) {
			t.Error("the XML copy is still there after Uninstall")
		}
	})

	t.Run("not installed", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner().on(query, missing, missing, missing, missing, missing)
		m := newTask(t, r, nil)
		for _, verb := range []func(context.Context) error{m.Start, m.Stop, m.Restart, m.Uninstall} {
			if err := verb(ctx); !errors.Is(err, ErrNotInstalled) {
				t.Errorf("verb before install: %v, want ErrNotInstalled", err)
			}
		}
		if st, err := m.State(ctx); err != nil || st.Installed {
			t.Errorf("State = %+v, %v; want not installed", st, err)
		}
	})

	t.Run("no SID", func(t *testing.T) {
		t.Parallel()
		env := testEnv(t.TempDir(), make(map[string]string))
		env.SID, env.Run = "", newFakeRunner().run
		if _, err := newTaskScheduler(env).Install(ctx, spec); err == nil {
			t.Error("Install without a SID succeeded")
		}
	})
}
