package update

import (
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
	"time"
)

// Windows will not replace or delete a running executable, but it will
// rename one. So the running binary is moved aside to a unique name first —
// a fixed name would still be the running image at a second update before a
// restart — and the new build takes its place. For the moment between the
// two renames the path is empty; a hook started then fails once.
const (
	swapRetries = 20
	swapBackoff = 100 * time.Millisecond
)

// fileOps are the calls a swap makes, so the Windows sequence can be tested
// on any host.
type fileOps struct {
	rename func(oldpath, newpath string) error
	remove func(path string) error
	sleep  func(time.Duration)
	// transient is an error worth retrying: another process — an antivirus
	// scan, an indexer — has the file open for a moment.
	transient func(error) bool
}

// asideName is a unique name beside target for the binary it replaces.
func asideName(target string, entropy io.Reader) (string, error) {
	var b [8]byte
	if _, err := io.ReadFull(entropy, b[:]); err != nil {
		return "", fmt.Errorf("update: aside name: %w", err)
	}
	return filepath.Join(filepath.Dir(target), asidePrefix+hex.EncodeToString(b[:])+".exe"), nil
}

// renameAside moves target to aside, then tmp to target; if the second
// rename keeps failing, target is moved back. The aside copy is removed when
// it can be; while it is the running image it cannot, and Sweep takes it at
// the next start.
func renameAside(ops fileOps, tmp, target, aside string) error {
	if err := retry(ops, func() error { return ops.rename(target, aside) }); err != nil {
		return fmt.Errorf("update: move %s aside: %w", target, err)
	}
	if err := retry(ops, func() error { return ops.rename(tmp, target) }); err != nil {
		if backErr := retry(ops, func() error { return ops.rename(aside, target) }); backErr != nil {
			return fmt.Errorf("update: put the new build in place: %w; and put the old one back: %w", err, backErr)
		}
		return fmt.Errorf("update: put the new build in place: %w", err)
	}
	_ = ops.remove(aside)
	return nil
}

func retry(ops fileOps, do func() error) error {
	var err error
	for range swapRetries {
		if err = do(); err == nil || !ops.transient(err) {
			return err
		}
		ops.sleep(swapBackoff)
	}
	return err
}
