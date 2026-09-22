//go:build windows

package state

import (
	"os"
	"testing"
)

// assertMode only checks existence on Windows, where mode bits are advisory
// and the profile directory's ACL is the guard.
func assertMode(t *testing.T, path string, _ os.FileMode) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
}
