package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	// A download in progress beside the binary. The name ends in ".exe" on
	// every OS, since Windows runs nothing without an extension it knows.
	tempPattern = ".clair-update-*.exe"
	// A Windows binary moved out of the way while it runs.
	asidePrefix = ".clair-old-"
	// How long `<new> version` may take. The first run of a new binary on
	// macOS can wait seconds on the system's malware scan.
	versionTimeout = 30 * time.Second
	// Sweep spares a download younger than this: another process may still
	// be writing it.
	sweepAge = 10 * time.Minute
)

// stage downloads asset beside the binary, checks it against want, makes
// sure it runs and reports version, and swaps it in. Nothing is ever written
// into the running binary: macOS kills a process whose signed pages change.
func (u *Updater) stage(ctx context.Context, src *fetcher, asset string, want [sizeSHA256]byte, version string) (err error) {
	dir := filepath.Dir(u.opts.Exe)
	tmp, err := os.CreateTemp(dir, tempPattern)
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("%w: %s", ErrUnwritable, dir)
	}
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		if tmp != nil {
			_ = tmp.Close()
		}
		if err != nil {
			_ = os.Remove(tmpPath)
		}
	}()

	h := sha256.New()
	if _, err = src.download(ctx, version+"/"+asset, io.MultiWriter(tmp, h)); err != nil {
		return err
	}
	if got := h.Sum(nil); !equal32(got, want) {
		return fmt.Errorf("update: %s hashes to %s, not the signed %s", asset, hex.EncodeToString(got), hex.EncodeToString(want[:]))
	}
	if err = tmp.Chmod(0o755); err != nil {
		return fmt.Errorf("update: %w", err)
	}
	// Closed before it runs: exec of a file open for writing fails (ETXTBSY).
	err = tmp.Close()
	tmp = nil
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}

	// A build that cannot say its own version — the wrong architecture, a
	// darwin build whose signature the kernel refuses, a truncated file — is
	// never swapped in.
	out, err := u.opts.RunVersion(ctx, tmpPath)
	if err != nil {
		return fmt.Errorf("update: the new build does not run: %w", err)
	}
	if got, _ := VersionOf(out); got != version {
		return fmt.Errorf("update: the new build says %q, not %s", strings.TrimSpace(firstLine(out)), version)
	}
	return swap(tmpPath, u.opts.Exe, u.opts.Entropy)
}

func equal32(got []byte, want [sizeSHA256]byte) bool {
	return len(got) == sizeSHA256 && [sizeSHA256]byte(got) == want
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

// runVersion runs `<path> version`. A fork elsewhere in the process can hold
// the just-closed file open for a moment (golang/go#22315), so a busy text
// file is retried.
func runVersion(ctx context.Context, path string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, versionTimeout)
	defer cancel()
	var lastErr error
	for attempt := range 5 {
		out, err := exec.CommandContext(ctx, path, "version").Output()
		if err == nil {
			return string(out), nil
		}
		lastErr = err
		if !textBusy(err) {
			break
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 50 * time.Millisecond):
		}
	}
	return "", lastErr
}

// Sweep removes what earlier updates left beside the binary: Windows' aside
// copies of binaries that were running, and downloads cut short. One still
// in use cannot be removed and is left for the next start.
func (u *Updater) Sweep() {
	dir := filepath.Dir(u.opts.Exe)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	now := u.now()
	for _, e := range entries {
		name := e.Name()
		stale := strings.HasPrefix(name, asidePrefix) && strings.HasSuffix(name, ".exe")
		if strings.HasPrefix(name, ".clair-update-") && strings.HasSuffix(name, ".exe") {
			info, infoErr := e.Info()
			stale = infoErr == nil && now.Sub(info.ModTime()) > sweepAge
		}
		if !stale || e.IsDir() {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err == nil {
			u.log.Debug("removed a leftover of an earlier update", "file", name)
		}
	}
}
