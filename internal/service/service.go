// Package service registers `clair daemon` with the host's own service
// manager as a per-user login service: a systemd user unit on Linux, a
// LaunchAgent on macOS, a logon Scheduled Task on Windows. Never a system
// service and never elevated: the daemon reads the user's terminal input idle
// (RELAY.md §4.3), which only the user's own session can see — a Windows
// service in session 0 would read nothing (ADR 2026-09.ahq8).
//
// Each manager renders its file from a Spec (pure, golden-tested) and applies
// it through an injected Runner, so every platform's file and command
// sequence is tested on any host.
package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"claircode.app/clair-agent/internal/ctl"
)

// Name is the service's short name: the systemd unit and the task.
const Name = "clair"

// Label is the LaunchAgent's label, the product's reverse-DNS id.
const Label = "app.claircode.clair"

// Errors a caller can test with errors.Is.
var (
	// ErrUnsupported is an OS with no manager here.
	ErrUnsupported = errors.New("service: no service manager for this OS")
	// ErrNoManager is a host whose service manager is not reachable from
	// this session: no systemd user manager (WSL without systemd, a
	// container, OpenRC), no launchd GUI domain (an SSH-only login).
	ErrNoManager = errors.New("service: the service manager is not available")
	// ErrNotInstalled is an operation on a service that is not registered.
	ErrNotInstalled = errors.New("service: not installed")
)

// Result is a finished command: its combined output and exit code.
type Result struct {
	Out  []byte
	Code int
}

// Runner runs a command. The error is for a command that could not run at
// all; one that ran and failed is a Result with a non-zero Code.
type Runner func(ctx context.Context, name string, args ...string) (Result, error)

// Exec is the Runner that runs real commands.
func Exec(ctx context.Context, name string, args ...string) (Result, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput() //nolint:gosec // the managers run systemctl, launchctl and schtasks with arguments they build
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		return Result{Out: out, Code: exitErr.ExitCode()}, nil
	}
	if err != nil {
		return Result{}, fmt.Errorf("service: run %s: %w", name, err)
	}
	return Result{Out: out}, nil
}

// Daemon is the running agent's control surface (a *ctl.Client).
type Daemon interface {
	Status(ctx context.Context) (ctl.Status, error)
	Stop(ctx context.Context) error
}

// Spec is what the service runs.
type Spec struct {
	// Exe is this binary, absolute and resolved (ResolveExe).
	Exe string
	// Args follow Exe: `daemon -config-dir <dir> …`.
	Args []string
	// Env is KEY=VALUE, captured from the installing shell (CaptureEnv),
	// sorted. The Scheduled Task cannot carry it; see MissingFromUserEnv.
	Env []string
}

// State is what the service manager says about the service.
type State struct {
	// Installed is a registered service: the unit, plist or task exists.
	Installed bool
	// Running is the manager's word that the process is up; on Windows,
	// where the task's state is localised text, the daemon answering.
	Running bool
	// Detail is the manager's own one-word state, when it has one.
	Detail string
}

// Manager installs and drives the service on one OS.
type Manager interface {
	// Kind names the mechanism for people: "systemd user unit" and so on.
	Kind() string
	// Path is where the registration lives: a file, or the task's name.
	Path() string
	// LogFile is where the daemon should write its log (`-log-file`), or ""
	// when the manager keeps it (journald).
	LogFile() string
	// Logs tells a person where to read the log.
	Logs() string
	// Render is the unit, plist or task XML for spec, as text.
	Render(spec Spec) ([]byte, error)
	// Install writes and registers the service without starting it; changed
	// is false when it was already registered exactly so.
	Install(ctx context.Context, spec Spec) (changed bool, err error)
	// Uninstall stops the service and removes its registration.
	Uninstall(ctx context.Context) error
	Start(ctx context.Context) error
	// Stop stops the service cleanly: held decides answered, streams
	// released (RELAY.md §13).
	Stop(ctx context.Context) error
	// Restart stops and starts it, picking up a changed registration.
	Restart(ctx context.Context) error
	State(ctx context.Context) (State, error)
}

// Env is the host the managers act on.
type Env struct {
	Getenv func(string) string
	// Home is the user's home directory.
	Home string
	// UID is the user's id (launchd's gui/<uid> domain).
	UID int
	// SID is the user's security identifier (the task's principal).
	SID string
	Run Runner
	// Daemon is the agent's control surface, for a clean stop where the
	// manager can only kill (Task Scheduler) and for Windows' State.
	Daemon Daemon
}

// ForOS picks the manager for goos (runtime.GOOS).
func ForOS(goos string, env Env) (Manager, error) {
	switch goos {
	case "linux":
		return newSystemd(env), nil
	case "darwin":
		return newLaunchd(env), nil
	case "windows":
		return newTaskScheduler(env), nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupported, goos)
	}
}

// capturedEnv are the variables the daemon needs from the installing shell,
// which a service manager does not pass on: where Claude Code's settings are
// (the daemon rewrites them on a snippet or a revoke), and how to reach the
// relay (RELAY.md §12). CLAIR_CONFIG_DIR is not among them: the resolved
// directory is passed as `-config-dir`.
var capturedEnv = []string{
	"CLAUDE_CONFIG_DIR",
	"HTTPS_PROXY", "https_proxy",
	"HTTP_PROXY", "http_proxy",
	"NO_PROXY", "no_proxy",
	"SSL_CERT_FILE", "SSL_CERT_DIR",
}

// CaptureEnv returns the set ones of the variables the daemon needs from
// this shell, as sorted KEY=VALUE.
func CaptureEnv(getenv func(string) string) []string {
	var env []string
	for _, key := range capturedEnv {
		if v := getenv(key); v != "" {
			env = append(env, key+"="+v)
		}
	}
	slices.Sort(env)
	return env
}

// ResolveExe makes exe absolute and resolves its symlinks, and refuses a
// binary a service must not point at: one `go run` built, or anything under
// the temporary directory, which is gone by the next login.
func ResolveExe(exe, tempDir string) (string, error) {
	abs, err := filepath.Abs(exe)
	if err != nil {
		return "", fmt.Errorf("service: locate this binary: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("service: locate this binary: %w", err)
	}
	temp := tempDir
	if t, err := filepath.EvalSymlinks(tempDir); err == nil {
		temp = t
	}
	if strings.Contains(resolved, string(filepath.Separator)+"go-build") || within(resolved, temp) {
		return "", fmt.Errorf("service: %s is a temporary build; install the clair binary somewhere it will stay and run that", resolved)
	}
	return resolved, nil
}

// within reports whether path is dir or below it.
func within(path, dir string) bool {
	if dir == "" {
		return false
	}
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// writeIfChanged writes data to path (creating its directory 0755) unless it
// already holds exactly that; changed says whether it wrote.
func writeIfChanged(path string, data []byte) (changed bool, err error) {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // the user's own unit and agent directories, as the managers create them
		return false, fmt.Errorf("service: create %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil { //nolint:gosec // units and plists are world-readable by convention and hold no secret
		return false, fmt.Errorf("service: write %s: %w", path, err)
	}
	return true, nil
}

// exists reports whether path is there.
func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// run runs a command that must succeed.
func run(ctx context.Context, r Runner, name string, args ...string) error {
	res, err := r(ctx, name, args...)
	if err != nil {
		return err
	}
	if res.Code != 0 {
		return fmt.Errorf("service: %s %s: exit %d: %s", name, strings.Join(args, " "), res.Code, bytes.TrimSpace(res.Out))
	}
	return nil
}
