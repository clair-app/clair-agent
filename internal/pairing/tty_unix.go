//go:build !windows

package pairing

import "os"

// openTTY opens the controlling terminal.
func openTTY() (*os.File, error) {
	return os.OpenFile("/dev/tty", os.O_RDWR, 0)
}
