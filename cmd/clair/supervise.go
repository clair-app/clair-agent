package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"

	"claircode.app/clair-agent/internal/state"
	"claircode.app/clair-agent/internal/supervisor"
)

// superviseDaemon is `clair daemon -supervise`: this binary runs the daemon
// as its child, with the same flags but this one, and starts it again when it
// exits abnormally (ADR 2026-09.pz5g). The Windows scheduled task runs it,
// because Task Scheduler cannot tell a crash from a clean stop.
func superviseDaemon(ctx context.Context, d deps, fs *flag.FlagSet, configDir, logFile string, stderr io.Writer) int {
	exe, err := d.exe()
	if err != nil {
		fmt.Fprintf(stderr, "clair daemon: locate this binary: %v\n", err)
		return exitError
	}
	// Nobody reads a scheduled task's stderr. With a log file, the
	// supervisor's lines and the daemon's stderr (a panic) are appended to it
	// a write at a time, since the daemon holds and rotates the same file.
	out := stderr
	if logFile != "" {
		out = appendFile{path: logFile}
	}
	spawn := d.spawn
	if spawn == nil {
		spawn = spawnExec
	}
	args := childArgs(fs)
	return supervisor.Run(ctx, supervisor.Options{
		Start: func() (supervisor.Child, error) { return spawn(ctx, exe, args, out) },
		Stop: func(ctx context.Context) error {
			path := configDir
			if path == "" {
				if path, err = state.DefaultDir(d.getenv); err != nil {
					return err
				}
			}
			agent, ok := readAgent(path)
			if !ok {
				return errors.New("no agent.json to find the daemon by")
			}
			return controlClient(agent).Stop(ctx)
		},
		Logger: slog.New(slog.NewTextHandler(out, nil)),
		Now:    d.now,
	})
}

// childArgs is the daemon's command line: every flag this one was given,
// except -supervise.
func childArgs(fs *flag.FlagSet) []string {
	args := []string{"daemon"}
	fs.Visit(func(f *flag.Flag) {
		if f.Name != "supervise" {
			args = append(args, "-"+f.Name+"="+f.Value.String())
		}
	})
	return args
}

// spawnExec starts this binary. Its context never ends it: a stop is the
// supervisor's to ask for, through the control surface.
func spawnExec(ctx context.Context, exe string, args []string, stderr io.Writer) (supervisor.Child, error) {
	cmd := exec.CommandContext(context.WithoutCancel(ctx), exe, args...) //nolint:gosec // this binary, with the flags it was started with
	cmd.Stdout, cmd.Stderr = stderr, stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", exe, err)
	}
	return execChild{cmd}, nil
}

// execChild is a started daemon process.
type execChild struct{ cmd *exec.Cmd }

func (c execChild) Wait() (int, error) {
	err := c.cmd.Wait()
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		return exitErr.ExitCode(), nil
	}
	if err != nil {
		return -1, err
	}
	return 0, nil
}

func (c execChild) Kill() error { return c.cmd.Process.Kill() }

// appendFile writes each p to the end of path, opening and closing it every
// time, so another process can hold and rotate the same file.
type appendFile struct{ path string }

func (a appendFile) Write(p []byte) (int, error) {
	if err := os.MkdirAll(filepath.Dir(a.path), 0o700); err != nil {
		return 0, err
	}
	f, err := os.OpenFile(a.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return 0, err
	}
	n, err := f.Write(p)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return n, err
}
