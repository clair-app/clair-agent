// Package logfile is the daemon's log when no service manager keeps one:
// launchd and Task Scheduler throw a process's stderr away or grow a file
// forever, so `clair daemon -log-file` writes here instead. One file, capped,
// with one older generation beside it. The log holds ids, sizes and paths,
// never a hook body, so it is written 0600 only because the directory is the
// user's own.
package logfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// MaxBytes is the size at which the file is rotated: at 10 MiB the daemon's
// info-level log holds weeks of hooks.
const MaxBytes = 10 << 20

// File is an append-only log that rotates to "<path>.1" when a write would
// take it past its limit. It is safe for concurrent use.
type File struct {
	path  string
	limit int64

	mu   sync.Mutex
	f    *os.File
	size int64
}

// Open opens path for appending, creating its directory (0700) and the file
// (0600). A file already over the limit is rotated first. A limit of zero or
// less is MaxBytes.
func Open(path string, limit int64) (*File, error) {
	if limit <= 0 {
		limit = MaxBytes
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("logfile: create %s: %w", filepath.Dir(path), err)
	}
	l := &File{path: path, limit: limit}
	if err := l.open(); err != nil {
		return nil, err
	}
	if l.size >= limit {
		if err := l.rotate(); err != nil {
			_ = l.f.Close()
			return nil, err
		}
	}
	return l, nil
}

// Write appends p, rotating first when p would take the file past its
// limit. A single write larger than the limit still lands whole.
func (l *File) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return 0, os.ErrClosed
	}
	if l.size > 0 && l.size+int64(len(p)) > l.limit {
		if err := l.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := l.f.Write(p)
	l.size += int64(n)
	if err != nil {
		return n, fmt.Errorf("logfile: write: %w", err)
	}
	return n, nil
}

// Close closes the file.
func (l *File) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

func (l *File) open() error {
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("logfile: open: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("logfile: stat: %w", err)
	}
	l.f, l.size = f, info.Size()
	return nil
}

// rotate closes the file, moves it to "<path>.1" (replacing the older one)
// and starts an empty one. Windows cannot rename over an existing file that
// is open elsewhere, so the old generation is removed first.
func (l *File) rotate() error {
	if err := l.f.Close(); err != nil {
		return fmt.Errorf("logfile: close for rotation: %w", err)
	}
	l.f = nil
	old := l.path + ".1"
	if err := os.Remove(old); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("logfile: remove %s: %w", old, err)
	}
	if err := os.Rename(l.path, old); err != nil {
		return fmt.Errorf("logfile: rotate: %w", err)
	}
	return l.open()
}
