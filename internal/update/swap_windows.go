package update

import (
	"errors"
	"io"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// swap moves the running binary aside and the new build into its place.
func swap(tmp, target string, entropy io.Reader) error {
	aside, err := asideName(target, entropy)
	if err != nil {
		return err
	}
	return renameAside(fileOps{
		rename:    os.Rename,
		remove:    os.Remove,
		sleep:     time.Sleep,
		transient: sharingViolation,
	}, tmp, target, aside)
}

// sharingViolation is another process holding the file for a moment; a scan
// can surface as a denied access too.
func sharingViolation(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_ACCESS_DENIED)
}

// textBusy has no Windows counterpart.
func textBusy(error) bool { return false }
