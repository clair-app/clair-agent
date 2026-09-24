package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// systemd is a systemd user unit: it runs while the user has a session,
// which is when Claude Code does, and journald keeps its log.
type systemd struct {
	env  Env
	path string
}

func newSystemd(env Env) *systemd {
	base := env.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		base = filepath.Join(env.Home, ".config")
	}
	return &systemd{env: env, path: filepath.Join(base, "systemd", "user", Name+".service")}
}

const unitName = Name + ".service"

func (*systemd) Kind() string    { return "systemd user unit" }
func (s *systemd) Path() string  { return s.path }
func (*systemd) LogFile() string { return "" }
func (*systemd) Logs() string    { return "journalctl --user -u " + Name }

// Render writes the unit. Restart=on-failure brings a crashed daemon back;
// a clean exit (a stop through the control surface) stays down.
func (*systemd) Render(spec Spec) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString("# Installed by `clair service install`; `clair service uninstall` removes it.\n")
	b.WriteString("[Unit]\n")
	b.WriteString("Description=Clair agent: Claude Code's hooks, tunnelled to your phone\n")
	b.WriteString("\n[Service]\n")
	b.WriteString("Type=simple\n")
	b.WriteString("ExecStart=")
	for i, arg := range append([]string{spec.Exe}, spec.Args...) {
		word, err := systemdWord(arg, true)
		if err != nil {
			return nil, err
		}
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(word)
	}
	b.WriteByte('\n')
	for _, kv := range spec.Env {
		word, err := systemdQuote(kv, false)
		if err != nil {
			return nil, err
		}
		b.WriteString("Environment=" + word + "\n")
	}
	b.WriteString("Restart=on-failure\n")
	b.WriteString("RestartSec=5\n")
	b.WriteString("\n[Install]\n")
	b.WriteString("WantedBy=default.target\n")
	return b.Bytes(), nil
}

// systemdWord is one ExecStart word: bare when it is plainly safe, quoted
// otherwise. `%` is a specifier everywhere and `$` a variable in ExecStart,
// so both are doubled.
func systemdWord(s string, exec bool) (string, error) {
	if s != "" && strings.IndexFunc(s, func(r rune) bool { return !systemdPlain(r) }) < 0 {
		return s, nil
	}
	return systemdQuote(s, exec)
}

// systemdPlain is a rune that needs no quoting in a unit.
func systemdPlain(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/._:=@+,-", r)
}

// systemdQuote double-quotes s with the escapes systemd.syntax(7) reads. In
// Environment= `$` means nothing, so it is doubled only for ExecStart.
func systemdQuote(s string, exec bool) (string, error) {
	if strings.ContainsAny(s, "\n\r\x00") {
		return "", fmt.Errorf("service: %q cannot go in a systemd unit", s)
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '\\' || r == '"':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '%':
			b.WriteString("%%")
		case r == '$' && exec:
			b.WriteString("$$")
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String(), nil
}

// available checks for a user manager this session can talk to.
func (s *systemd) available(ctx context.Context) error {
	res, err := s.env.Run(ctx, "systemctl", "--user", "show", "--property=Version")
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNoManager, err)
	}
	if res.Code != 0 {
		return fmt.Errorf("%w: systemctl --user: %s", ErrNoManager, bytes.TrimSpace(res.Out))
	}
	return nil
}

func (s *systemd) systemctl(ctx context.Context, args ...string) error {
	return run(ctx, s.env.Run, "systemctl", append([]string{"--user"}, args...)...)
}

func (s *systemd) Install(ctx context.Context, spec Spec) (bool, error) {
	if err := s.available(ctx); err != nil {
		return false, err
	}
	unit, err := s.Render(spec)
	if err != nil {
		return false, err
	}
	changed, err := writeIfChanged(s.path, unit)
	if err != nil {
		return false, err
	}
	if changed {
		if err := s.systemctl(ctx, "daemon-reload"); err != nil {
			return true, err
		}
	}
	return changed, s.systemctl(ctx, "enable", unitName)
}

func (s *systemd) Uninstall(ctx context.Context) error {
	if !exists(s.path) {
		return ErrNotInstalled
	}
	if err := s.available(ctx); err != nil {
		return err
	}
	if err := s.systemctl(ctx, "disable", "--now", unitName); err != nil {
		return err
	}
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("service: remove %s: %w", s.path, err)
	}
	// A unit that failed stays listed until its failure is forgotten.
	_, _ = s.env.Run(ctx, "systemctl", "--user", "reset-failed", unitName)
	return s.systemctl(ctx, "daemon-reload")
}

func (s *systemd) Start(ctx context.Context) error   { return s.act(ctx, "start") }
func (s *systemd) Stop(ctx context.Context) error    { return s.act(ctx, "stop") }
func (s *systemd) Restart(ctx context.Context) error { return s.act(ctx, "restart") }

func (s *systemd) act(ctx context.Context, verb string) error {
	if !exists(s.path) {
		return ErrNotInstalled
	}
	return s.systemctl(ctx, verb, unitName)
}

// State reads is-active, whose exit code says running and whose one word is
// systemd's own (active, activating, failed, inactive).
func (s *systemd) State(ctx context.Context) (State, error) {
	st := State{Installed: exists(s.path)}
	if !st.Installed {
		return st, nil
	}
	res, err := s.env.Run(ctx, "systemctl", "--user", "is-active", unitName)
	if err != nil {
		return st, err
	}
	st.Running = res.Code == 0
	st.Detail = string(bytes.TrimSpace(res.Out))
	return st, nil
}
