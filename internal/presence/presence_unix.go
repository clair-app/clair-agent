//go:build unix && !darwin

package presence

import (
	"time"

	"golang.org/x/sys/unix"
)

// local reads /dev/pts/N: Linux and the BSDs allocate every slave there.
func host() Sampler {
	return ptys{dir: "/dev/pts", match: digits, uid: mine(), stat: unix.Stat, now: time.Now}
}
