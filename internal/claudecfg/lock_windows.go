//go:build windows

package claudecfg

import (
	"os"

	"golang.org/x/sys/windows"
)

// lockFile blocks until f holds an exclusive lock on its first byte. Locks
// belong to the handle, so two opens in one process exclude each other as
// two processes do.
func lockFile(f *os.File) error {
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, new(windows.Overlapped))
}

func unlockFile(f *os.File) error {
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, new(windows.Overlapped))
}
