//go:build !windows

package claudecfg

import (
	"os"
	"syscall"
)

// lockFile blocks until f holds an exclusive advisory lock. Flock locks
// belong to the open file, so two opens in one process exclude each other
// as two processes do.
func lockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}

func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
