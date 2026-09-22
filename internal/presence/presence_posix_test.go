//go:build unix

package presence

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestPtysNewestAccessTime drives the enumeration with regular files in a
// temporary directory: the nodes' names, owners and access times are all
// the sampler looks at.
func TestPtysNewestAccessTime(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	now := time.Date(2026, 9, 22, 6, 0, 0, 0, time.UTC)
	touch := func(name string, atime time.Time) {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, atime, atime); err != nil {
			t.Fatal(err)
		}
	}
	touch("0", now.Add(-time.Hour))
	touch("7", now.Add(-42*time.Second))
	touch("12", now.Add(-10*time.Minute))
	touch("ptmx", now) // not a slave: ignored by name
	sampler := ptys{dir: dir, match: digits, uid: mine(), stat: unix.Stat, now: func() time.Time { return now }}
	if s := sampler.Sample(); !s.Known || s.Idle != 42*time.Second || s.Source != "pty" {
		t.Errorf("Sample() = %+v, want 42s from the newest node", s)
	}

	// Another user's terminals do not count; with none of ours there is no reading.
	other := ptys{dir: dir, match: digits, uid: mine() + 1, stat: unix.Stat, now: func() time.Time { return now }}
	if s := other.Sample(); s.Known {
		t.Errorf("Sample() over another user's nodes = %+v, want unknown", s)
	}
	empty := ptys{dir: filepath.Join(dir, "missing"), match: digits, uid: mine(), stat: unix.Stat, now: func() time.Time { return now }}
	if s := empty.Sample(); s.Known {
		t.Errorf("Sample() over a missing directory = %+v, want unknown", s)
	}

	// A clock behind the node's atime (the 8 s granularity can put it ahead) reads as zero idle.
	early := ptys{dir: dir, match: digits, uid: mine(), stat: unix.Stat, now: func() time.Time { return now.Add(-time.Minute) }}
	if s := early.Sample(); !s.Known || s.Idle != 0 {
		t.Errorf("Sample() with the clock behind = %+v, want zero idle", s)
	}
}

func TestDigits(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]bool{"0": true, "17": true, "": false, "ptmx": false, "1a": false, "ttys001": false} {
		if got := digits(name); got != want {
			t.Errorf("digits(%q) = %v, want %v", name, got, want)
		}
	}
}
