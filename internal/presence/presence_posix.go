//go:build unix

package presence

import (
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// ptys reads the newest access time over this user's pseudo-terminal slave
// nodes. The kernel sets a pty's atime when the process on it *reads* input
// — on Linux `tty_update_time`, at 8-second granularity — so the newest one
// is the moment a keystroke was last consumed at any terminal of ours: what
// `w(1)` shows as IDLE, with the same blind spots (a resize or a terminal's
// reply to a query counts as input; a program that is not reading does not
// consume keystrokes until it does).
type ptys struct {
	// dir holds the nodes; match picks them by name.
	dir   string
	match func(name string) bool
	// uid keeps other users' terminals out of the reading.
	uid  uint32
	stat func(path string, st *unix.Stat_t) error
	now  func() time.Time
}

// Sample stats every matching node; an unreadable one is skipped.
func (p ptys) Sample() Sample {
	entries, err := os.ReadDir(p.dir)
	if err != nil {
		return Sample{}
	}
	var newest time.Time
	found := false
	for _, e := range entries {
		if !p.match(e.Name()) {
			continue
		}
		var st unix.Stat_t
		if err := p.stat(filepath.Join(p.dir, e.Name()), &st); err != nil || st.Uid != p.uid {
			continue
		}
		at := time.Unix(st.Atim.Unix())
		if !found || at.After(newest) {
			newest, found = at, true
		}
	}
	if !found {
		return Sample{}
	}
	return Sample{Idle: max(p.now().Sub(newest), 0), Known: true, Source: "pty"}
}

// digits reports a name made of decimal digits only, such as /dev/pts/N.
func digits(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// mine is the calling user's uid, as the kernel reports it on the nodes.
func mine() uint32 {
	return uint32(os.Getuid()) //nolint:gosec // Getuid is non-negative on Unix
}
