package presence

import (
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// local reads /dev/ttysNNN, where macOS allocates every pseudo-terminal
// slave; `w(1)` there reads its IDLE column from the same nodes.
func host() Sampler {
	return ptys{dir: "/dev", match: ttys, uid: mine(), stat: unix.Stat, now: time.Now}
}

func ttys(name string) bool {
	rest, ok := strings.CutPrefix(name, "ttys")
	return ok && digits(rest)
}
