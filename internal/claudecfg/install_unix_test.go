//go:build !windows

package claudecfg

import (
	"os"
	"path/filepath"
	"testing"
)

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s mode = %o, want %o", filepath.Base(path), got, want)
	}
}

// settings.json holds the hook bearer: a rewrite keeps the mode the user
// gave it, and one the agent creates is private (AG-7).
func TestInstallKeepsTheFileMode(t *testing.T) {
	t.Parallel()

	in := fixture(t, `{"permissions":{}}`)
	if err := os.Chmod(in.SettingsPath, 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := in.Install(defaultHooks())
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	assertMode(t, in.SettingsPath, 0o600)
	assertMode(t, report.Backup, 0o600)
	assertMode(t, in.originalPath(), 0o600)

	fresh := fixture(t, "")
	if _, err := fresh.Install(defaultHooks()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	assertMode(t, fresh.SettingsPath, 0o600)

	loose := fixture(t, `{}`)
	if err := os.Chmod(loose.SettingsPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loose.Install(defaultHooks()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	assertMode(t, loose.SettingsPath, 0o644)
}

// A symlinked settings.json (a dotfiles repo) is written through, and a
// file or link planted at a temp name is never written to.
func TestInstallWritesThroughASymlinkAndNotThroughAPlantedOne(t *testing.T) {
	t.Parallel()

	in := fixture(t, "")
	dotfile := filepath.Join(t.TempDir(), "dotfiles-settings.json")
	if err := os.WriteFile(dotfile, []byte(`{"permissions":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dotfile, in.SettingsPath); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, in.SettingsPath+".tmp"); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Install(defaultHooks()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	info, err := os.Lstat(in.SettingsPath)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("settings.json is no longer a symlink: %v, %v", info, err)
	}
	if _, ok := readSettings(t, in).Get("hooks"); !ok {
		t.Error("the symlink's target has no hooks")
	}
	assertMode(t, dotfile, 0o600)
	if data, err := os.ReadFile(victim); err != nil || string(data) != "untouched" {
		t.Errorf("the planted link's target = %q, %v; want untouched", data, err)
	}
}
