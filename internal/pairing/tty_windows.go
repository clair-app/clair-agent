//go:build windows

package pairing

import "os"

// openTTY opens the console. CONIN$ reads the console input whatever stdin
// is; writes to it go to the attached console too.
func openTTY() (*os.File, error) {
	return os.OpenFile("CONIN$", os.O_RDWR, 0)
}
