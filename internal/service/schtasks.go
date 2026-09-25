package service

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
)

// taskScheduler is a Scheduled Task that starts at the user's logon, in the
// user's desktop session: a Windows service runs in session 0, where
// GetLastInputInfo sees no input (ADR 2026-09.ahq8). The daemon is a console
// program, so the task runs it under `conhost --headless`, which gives it a
// console and never shows a window.
type taskScheduler struct {
	env Env
	dir string
}

func newTaskScheduler(env Env) *taskScheduler {
	base := env.Getenv("LOCALAPPDATA")
	if base == "" {
		base = filepath.Join(env.Home, "AppData", "Local")
	}
	return &taskScheduler{env: env, dir: filepath.Join(base, "clair")}
}

// conhost is the console host; Task Scheduler expands the variable.
const conhost = `%SystemRoot%\System32\conhost.exe`

// stopWait bounds how long Stop waits for the daemon to let go of its
// listener after asking it to stop: its own drain is 2 s.
const stopWait = 5 * time.Second

func (*taskScheduler) Kind() string      { return "scheduled task" }
func (*taskScheduler) Path() string      { return `\` + Name }
func (t *taskScheduler) LogFile() string { return filepath.Join(t.dir, "daemon.log") }

// RestartsOnCrash is false: the task runs conhost --headless, which exits 0
// whatever the daemon does, so RestartOnFailure only ever sees a success. It
// covers a launch that fails, nothing more (ADR 2026-09.pz5g).
func (*taskScheduler) RestartsOnCrash() bool { return false }
func (t *taskScheduler) Logs() string        { return t.LogFile() }

// xmlPath keeps the XML the task was registered from, so an unchanged
// install registers nothing.
func (t *taskScheduler) xmlPath() string { return filepath.Join(t.dir, "clair-task.xml") }

// task is the Task Scheduler 1.2 schema, the parts of it this task sets.
type task struct {
	XMLName  xml.Name `xml:"http://schemas.microsoft.com/windows/2004/02/mit/task Task"`
	Version  string   `xml:"version,attr"`
	Info     taskInfo `xml:"RegistrationInfo"`
	Triggers struct {
		Logon struct {
			Enabled bool   `xml:"Enabled"`
			UserID  string `xml:"UserId"`
		} `xml:"LogonTrigger"`
	} `xml:"Triggers"`
	Principals struct {
		Principal struct {
			ID        string `xml:"id,attr"`
			UserID    string `xml:"UserId"`
			LogonType string `xml:"LogonType"`
			RunLevel  string `xml:"RunLevel"`
		} `xml:"Principal"`
	} `xml:"Principals"`
	Settings taskSettings `xml:"Settings"`
	Actions  struct {
		Context string `xml:"Context,attr"`
		Exec    struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Exec"`
	} `xml:"Actions"`
}

type taskInfo struct {
	Description string `xml:"Description"`
	URI         string `xml:"URI"`
}

type taskSettings struct {
	MultipleInstancesPolicy    string `xml:"MultipleInstancesPolicy"`
	DisallowStartIfOnBatteries bool   `xml:"DisallowStartIfOnBatteries"`
	StopIfGoingOnBatteries     bool   `xml:"StopIfGoingOnBatteries"`
	AllowHardTerminate         bool   `xml:"AllowHardTerminate"`
	StartWhenAvailable         bool   `xml:"StartWhenAvailable"`
	RunOnlyIfNetworkAvailable  bool   `xml:"RunOnlyIfNetworkAvailable"`
	IdleSettings               struct {
		StopOnIdleEnd bool `xml:"StopOnIdleEnd"`
		RestartOnIdle bool `xml:"RestartOnIdle"`
	} `xml:"IdleSettings"`
	AllowStartOnDemand bool   `xml:"AllowStartOnDemand"`
	Enabled            bool   `xml:"Enabled"`
	Hidden             bool   `xml:"Hidden"`
	RunOnlyIfIdle      bool   `xml:"RunOnlyIfIdle"`
	WakeToRun          bool   `xml:"WakeToRun"`
	ExecutionTimeLimit string `xml:"ExecutionTimeLimit"`
	Priority           int    `xml:"Priority"`
	RestartOnFailure   struct {
		Interval string `xml:"Interval"`
		Count    int    `xml:"Count"`
	} `xml:"RestartOnFailure"`
}

// Render writes the task's XML as UTF-8 text; Install registers it as the
// UTF-16 schtasks reads. The environment is not in it: a task cannot set one
// (MissingFromUserEnv).
func (t *taskScheduler) Render(spec Spec) ([]byte, error) {
	return renderTask(spec, t.env.SID)
}

func renderTask(spec Spec, sid string) ([]byte, error) {
	var t task
	t.Version = "1.2"
	t.Info = taskInfo{
		Description: "Clair agent: Claude Code's hooks, tunnelled to your phone. Installed by `clair service install`; `clair service uninstall` removes it.",
		URI:         `\` + Name,
	}
	t.Triggers.Logon.Enabled = true
	t.Triggers.Logon.UserID = sid
	p := &t.Principals.Principal
	p.ID, p.UserID, p.LogonType, p.RunLevel = "Author", sid, "InteractiveToken", "LeastPrivilege"
	s := &t.Settings
	s.MultipleInstancesPolicy = "IgnoreNew"
	s.AllowHardTerminate = true
	s.AllowStartOnDemand = true
	s.Enabled = true
	// The default limit stops a task after 72 hours; PT0S is none.
	s.ExecutionTimeLimit = "PT0S"
	// The default, 7, is below normal: a held decide should not wait on it.
	s.Priority = 5
	s.RestartOnFailure.Interval = "PT1M"
	s.RestartOnFailure.Count = 999
	t.Actions.Context = "Author"
	t.Actions.Exec.Command = conhost
	args := make([]string, 0, len(spec.Args)+2)
	args = append(args, "--headless", windowsArg(spec.Exe))
	for _, a := range spec.Args {
		args = append(args, windowsArg(a))
	}
	t.Actions.Exec.Arguments = strings.Join(args, " ")

	body, err := xml.MarshalIndent(t, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("service: task XML: %w", err)
	}
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-16"?>` + "\n")
	b.Write(body)
	b.WriteByte('\n')
	return b.Bytes(), nil
}

// utf16LE encodes text as UTF-16 little-endian with a byte-order mark, the
// form schtasks /XML reads.
func utf16LE(text []byte) []byte {
	units := utf16.Encode([]rune(string(text)))
	out := make([]byte, 2, 2+2*len(units))
	binary.LittleEndian.PutUint16(out, 0xFEFF)
	for _, u := range units {
		out = binary.LittleEndian.AppendUint16(out, u)
	}
	return out
}

// windowsArg quotes one argument the way CommandLineToArgvW reads it back
// (syscall.EscapeArg, which exists only on Windows builds).
func windowsArg(s string) string {
	if s == "" {
		return `""`
	}
	if !strings.ContainsAny(s, "\"\\ \t") {
		return s
	}
	hasSpace := strings.ContainsAny(s, " \t")
	if !strings.ContainsAny(s, `"\`) {
		return `"` + s + `"`
	}
	var b strings.Builder
	if hasSpace {
		b.WriteByte('"')
	}
	slashes := 0
	for i := range len(s) {
		c := s[i]
		switch c {
		case '\\':
			slashes++
		case '"':
			b.WriteString(strings.Repeat(`\`, slashes+1))
			slashes = 0
		default:
			slashes = 0
		}
		b.WriteByte(c)
	}
	if hasSpace {
		b.WriteString(strings.Repeat(`\`, slashes))
		b.WriteByte('"')
	}
	return b.String()
}

func (t *taskScheduler) schtasks(ctx context.Context, args ...string) error {
	return run(ctx, t.env.Run, "schtasks", args...)
}

// registered asks for the task by name; the exit code is the answer, since
// schtasks' text is localised.
func (t *taskScheduler) registered(ctx context.Context) (bool, error) {
	res, err := t.env.Run(ctx, "schtasks", "/Query", "/TN", Name)
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrNoManager, err)
	}
	return res.Code == 0, nil
}

func (t *taskScheduler) Install(ctx context.Context, spec Spec) (bool, error) {
	if t.env.SID == "" {
		return false, errors.New("service: the task needs the user's SID")
	}
	text, err := t.Render(spec)
	if err != nil {
		return false, err
	}
	changed, err := writeIfChanged(t.xmlPath(), utf16LE(text))
	if err != nil {
		return false, err
	}
	registered, err := t.registered(ctx)
	if err != nil {
		return false, err
	}
	if !changed && registered {
		return false, nil
	}
	if err := t.schtasks(ctx, "/Create", "/TN", Name, "/XML", t.xmlPath(), "/F"); err != nil {
		// Leave no copy claiming a registration that did not happen.
		_ = os.Remove(t.xmlPath())
		return false, err
	}
	return true, nil
}

func (t *taskScheduler) Uninstall(ctx context.Context) error {
	registered, err := t.registered(ctx)
	if err != nil {
		return err
	}
	if !registered {
		return ErrNotInstalled
	}
	if err := t.Stop(ctx); err != nil {
		return err
	}
	if err := t.schtasks(ctx, "/Delete", "/TN", Name, "/F"); err != nil {
		return err
	}
	if err := os.Remove(t.xmlPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("service: remove %s: %w", t.xmlPath(), err)
	}
	return nil
}

func (t *taskScheduler) Start(ctx context.Context) error {
	registered, err := t.registered(ctx)
	if err != nil {
		return err
	}
	if !registered {
		return ErrNotInstalled
	}
	return t.schtasks(ctx, "/Run", "/TN", Name)
}

// Stop asks the daemon to stop through its control surface and waits for it
// to go, then ends the task: schtasks /End is TerminateProcess, which answers
// no held decide, sends no cancel and leaves the stream for the relay to age
// out (ADR 2026-09.hu4b), so it only mops up.
func (t *taskScheduler) Stop(ctx context.Context) error {
	registered, err := t.registered(ctx)
	if err != nil {
		return err
	}
	if !registered {
		return ErrNotInstalled
	}
	if t.env.Daemon != nil && t.env.Daemon.Stop(ctx) == nil {
		t.waitGone(ctx)
	}
	// Nothing left to end is the usual answer, and not a failure.
	_, err = t.env.Run(ctx, "schtasks", "/End", "/TN", Name)
	return err
}

// waitGone polls until the daemon stops answering, or stopWait.
func (t *taskScheduler) waitGone(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, stopWait)
	defer cancel()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := t.env.Daemon.Status(ctx); err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (t *taskScheduler) Restart(ctx context.Context) error {
	if err := t.Stop(ctx); err != nil {
		return err
	}
	return t.schtasks(ctx, "/Run", "/TN", Name)
}

// State is the task's registration and, for running, the daemon answering.
func (t *taskScheduler) State(ctx context.Context) (State, error) {
	registered, err := t.registered(ctx)
	if err != nil {
		return State{}, err
	}
	st := State{Installed: registered}
	if registered && t.env.Daemon != nil {
		if _, err := t.env.Daemon.Status(ctx); err == nil {
			st.Running = true
		}
	}
	return st, nil
}
