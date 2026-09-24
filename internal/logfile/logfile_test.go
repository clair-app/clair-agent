package logfile_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"claircode.app/clair-agent/internal/logfile"
)

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func TestRotatesPastTheLimitKeepingOneGeneration(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "logs", "daemon.log")
	l, err := logfile.Open(path, 10)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for _, line := range []string{"aaaa\n", "bbbb\n", "cccc\n", "dddd\n", "eeee\n"} {
		if _, err := l.Write([]byte(line)); err != nil {
			t.Fatalf("Write %q: %v", line, err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got, want := read(t, path), "eeee\n"; got != want {
		t.Errorf("current = %q, want %q", got, want)
	}
	if got, want := read(t, path+".1"), "cccc\ndddd\n"; got != want {
		t.Errorf("previous = %q, want %q (one generation kept)", got, want)
	}
	if _, err := os.Stat(path + ".2"); !os.IsNotExist(err) {
		t.Errorf("a second generation exists: %v", err)
	}
}

func TestOpenAppendsAndRotatesAnOversizedFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.log")
	if err := os.WriteFile(path, []byte("abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := logfile.Open(path, 100)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_, _ = l.Write([]byte("def\n"))
	_ = l.Close()
	if got, want := read(t, path), "abc\ndef\n"; got != want {
		t.Errorf("under the limit: %q, want %q appended", got, want)
	}

	if err = os.WriteFile(path, bytes.Repeat([]byte("x"), 100), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err = logfile.Open(path, 100)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_ = l.Close()
	if got := read(t, path); got != "" {
		t.Errorf("an oversized file was not rotated on open: %d bytes left", len(got))
	}
	if got := read(t, path+".1"); len(got) != 100 {
		t.Errorf("rotated generation = %d bytes, want 100", len(got))
	}
}

func TestAWriteLargerThanTheLimitLandsWhole(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "daemon.log")
	l, err := logfile.Open(path, 4)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := l.Write([]byte("0123456789\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = l.Close()
	if got := read(t, path); got != "0123456789\n" {
		t.Errorf("current = %q, want the whole line", got)
	}
	if _, err := l.Write([]byte("x")); err == nil {
		t.Error("Write after Close succeeded")
	}
}
