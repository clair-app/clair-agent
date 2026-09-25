//go:build !windows

package update

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// swap renames the new build over the binary. The rename makes a new inode
// (a new vnode on macOS, with its own code signature); the running process
// keeps the old one until it exits.
func swap(tmp, target string, _ io.Reader) error {
	if err := os.Rename(tmp, target); err != nil {
		return fmt.Errorf("update: put the new build in place: %w", err)
	}
	return nil
}

// textBusy is exec's refusal of a file some process still has open for writing.
func textBusy(err error) bool {
	return errors.Is(err, syscall.ETXTBSY)
}
