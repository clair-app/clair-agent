package service

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
)

// launchd is a LaunchAgent in the user's GUI domain: loaded at login, run as
// the user, with terminal input idle readable from /dev/ttys*.
//
// Unverified on hardware: written from launchd.plist(5) and launchctl(1),
// tested here against a fake launchctl (ADR 2026-09.ahq8).
type launchd struct {
	env    Env
	path   string
	logDir string
}

// newLaunchd builds the manager. A LaunchAgent's paths are POSIX paths, joined
// with path rather than filepath so the plist renders the same on any host.
func newLaunchd(env Env) *launchd {
	return &launchd{
		env:    env,
		path:   path.Join(env.Home, "Library", "LaunchAgents", Label+".plist"),
		logDir: path.Join(env.Home, "Library", "Logs", "clair"),
	}
}

func (*launchd) Kind() string      { return "launchd agent" }
func (l *launchd) Path() string    { return l.path }
func (l *launchd) LogFile() string { return path.Join(l.logDir, "daemon.log") }

// RestartsOnCrash is KeepAlive's SuccessfulExit false.
func (*launchd) RestartsOnCrash() bool { return true }
func (l *launchd) Logs() string        { return l.LogFile() }

// stderrLog catches what the daemon's own log cannot: a panic, or a failure
// before the log file opened.
func (l *launchd) stderrLog() string { return path.Join(l.logDir, "daemon.stderr.log") }

func (l *launchd) domain() string { return "gui/" + strconv.Itoa(l.env.UID) }
func (l *launchd) target() string { return l.domain() + "/" + Label }

// Render writes the plist. KeepAlive restarts a daemon that failed but not
// one that exited cleanly; Interactive keeps launchd from coalescing the
// timers a held decide and the relay's stream run on.
func (l *launchd) Render(spec Spec) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(xml.Header)
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString(`<plist version="1.0">` + "\n<dict>\n")
	key := func(indent, k string) {
		b.WriteString(indent + "<key>")
		_ = xml.EscapeText(&b, []byte(k))
		b.WriteString("</key>\n")
	}
	str := func(indent, v string) {
		b.WriteString(indent + "<string>")
		_ = xml.EscapeText(&b, []byte(v))
		b.WriteString("</string>\n")
	}
	key("\t", "Label")
	str("\t", Label)
	key("\t", "ProgramArguments")
	b.WriteString("\t<array>\n")
	for _, arg := range append([]string{spec.Exe}, spec.Args...) {
		str("\t\t", arg)
	}
	b.WriteString("\t</array>\n")
	if len(spec.Env) > 0 {
		key("\t", "EnvironmentVariables")
		b.WriteString("\t<dict>\n")
		for _, kv := range spec.Env {
			k, v, _ := strings.Cut(kv, "=")
			key("\t\t", k)
			str("\t\t", v)
		}
		b.WriteString("\t</dict>\n")
	}
	key("\t", "RunAtLoad")
	b.WriteString("\t<true/>\n")
	key("\t", "KeepAlive")
	b.WriteString("\t<dict>\n")
	key("\t\t", "SuccessfulExit")
	b.WriteString("\t\t<false/>\n\t</dict>\n")
	key("\t", "ThrottleInterval")
	b.WriteString("\t<integer>10</integer>\n")
	key("\t", "ProcessType")
	str("\t", "Interactive")
	key("\t", "StandardErrorPath")
	str("\t", l.stderrLog())
	b.WriteString("</dict>\n</plist>\n")
	return b.Bytes(), nil
}

// loaded asks launchd whether the agent is in the GUI domain; its print
// output says whether the process is up.
func (l *launchd) loaded(ctx context.Context) (loaded, running bool, err error) {
	res, err := l.env.Run(ctx, "launchctl", "print", l.target())
	if err != nil {
		return false, false, err
	}
	if res.Code != 0 {
		return false, false, nil
	}
	return true, bytes.Contains(res.Out, []byte("state = running")), nil
}

// available checks for the GUI domain: an SSH-only login has none.
func (l *launchd) available(ctx context.Context) error {
	res, err := l.env.Run(ctx, "launchctl", "print", l.domain())
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNoManager, err)
	}
	if res.Code != 0 {
		return fmt.Errorf("%w: no %s domain; log in at the Mac's screen once, or run `clair daemon` yourself", ErrNoManager, l.domain())
	}
	return nil
}

// Install writes the plist. A loaded agent keeps the definition it was
// loaded with, so a changed plist unloads it; Start or Restart loads it again.
func (l *launchd) Install(ctx context.Context, spec Spec) (bool, error) {
	if err := l.available(ctx); err != nil {
		return false, err
	}
	plist, err := l.Render(spec)
	if err != nil {
		return false, err
	}
	if err = os.MkdirAll(l.logDir, 0o700); err != nil {
		return false, fmt.Errorf("service: create %s: %w", l.logDir, err)
	}
	changed, err := writeIfChanged(l.path, plist)
	if err != nil || !changed {
		return changed, err
	}
	loaded, _, err := l.loaded(ctx)
	if err != nil {
		return true, err
	}
	if loaded {
		err = run(ctx, l.env.Run, "launchctl", "bootout", l.target())
	}
	return true, err
}

func (l *launchd) Uninstall(ctx context.Context) error {
	if !exists(l.path) {
		return ErrNotInstalled
	}
	if err := l.Stop(ctx); err != nil {
		return err
	}
	if err := os.Remove(l.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("service: remove %s: %w", l.path, err)
	}
	return nil
}

// Start loads the agent, which RunAtLoad starts, or kicks a loaded one.
func (l *launchd) Start(ctx context.Context) error {
	if !exists(l.path) {
		return ErrNotInstalled
	}
	loaded, _, err := l.loaded(ctx)
	if err != nil {
		return err
	}
	if loaded {
		return run(ctx, l.env.Run, "launchctl", "kickstart", l.target())
	}
	if err = l.available(ctx); err != nil {
		return err
	}
	return run(ctx, l.env.Run, "launchctl", "bootstrap", l.domain(), l.path)
}

// Stop unloads the agent: launchd sends SIGTERM, and KeepAlive has nothing
// left to restart. It is loaded again at the next login.
func (l *launchd) Stop(ctx context.Context) error {
	if !exists(l.path) {
		return ErrNotInstalled
	}
	loaded, _, err := l.loaded(ctx)
	if err != nil || !loaded {
		return err
	}
	return run(ctx, l.env.Run, "launchctl", "bootout", l.target())
}

// Restart kills and restarts a loaded agent, or loads one Install unloaded.
func (l *launchd) Restart(ctx context.Context) error {
	if !exists(l.path) {
		return ErrNotInstalled
	}
	loaded, _, err := l.loaded(ctx)
	if err != nil {
		return err
	}
	if !loaded {
		return l.Start(ctx)
	}
	return run(ctx, l.env.Run, "launchctl", "kickstart", "-k", l.target())
}

func (l *launchd) State(ctx context.Context) (State, error) {
	st := State{Installed: exists(l.path)}
	if !st.Installed {
		return st, nil
	}
	loaded, running, err := l.loaded(ctx)
	if err != nil {
		return st, err
	}
	st.Running = running
	switch {
	case running:
		st.Detail = "running"
	case loaded:
		st.Detail = "loaded"
	default:
		st.Detail = "not loaded"
	}
	return st, nil
}
