package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"claircode.app/clair-agent/internal/supervisor"
)

// exitChild is a daemon that has already exited with code.
type exitChild struct{ code int }

func (c exitChild) Wait() (int, error) { return c.code, nil }
func (exitChild) Kill() error          { return nil }

// The supervisor starts this binary with every flag it was given but its own,
// and ends when the daemon stops cleanly.
func TestSuperviseRunsTheDaemonWithItsFlags(t *testing.T) {
	t.Parallel()

	d := testDeps(nil)
	var got [][]string
	d.spawn = func(_ context.Context, exe string, args []string, _ io.Writer) (supervisor.Child, error) {
		if exe != "/opt/clair/clair" {
			t.Errorf("spawned %q, want this binary", exe)
		}
		got = append(got, args)
		return exitChild{0}, nil
	}
	logFile := filepath.Join(t.TempDir(), "logs", "daemon.log")
	var stderr bytes.Buffer
	args := []string{"daemon", "-supervise", "-config-dir", "/cfg", "-listen", "127.0.0.1:7417", "-log-file", logFile}
	if code := runWith(t.Context(), d, args, &bytes.Buffer{}, &stderr); code != exitOK {
		t.Fatalf("daemon -supervise = %d: %s", code, stderr.String())
	}
	want := []string{"daemon", "-config-dir=/cfg", "-listen=127.0.0.1:7417", "-log-file=" + logFile}
	if len(got) != 1 || !slices.Equal(got[0], want) {
		t.Fatalf("spawned %q, want once with %q", got, want)
	}
	// The supervisor writes its lines to the daemon's log, never holding it.
	data, err := os.ReadFile(logFile)
	if err != nil || !strings.Contains(string(data), "daemon stopped cleanly") {
		t.Errorf("log = %q, %v; want the supervisor's line", data, err)
	}
}
