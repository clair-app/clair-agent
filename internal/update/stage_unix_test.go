//go:build !windows

package update

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"runtime"
	"testing"
)

// script is a stand-in binary that answers `version` like clair does.
func script(version string) []byte {
	return []byte("#!/bin/sh\necho 'clair " + version + " (script, 2026-09-24T00:00:00Z)'\n")
}

// TestStageRunsTheBuild goes through the real exec: the download is closed,
// made executable and run before it replaces the binary, and the binary on
// disk is asked its version the same way.
func TestStageRunsTheBuild(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	exe := installed(t, dir, script("v0.1.0"))
	rs := newReleaseServer(t, "v0.2.0", map[string]release{"v0.2.0": {build: script("v0.2.0")}})
	u, err := New(Options{
		Current:  "v0.1.0",
		Exe:      exe,
		Releases: rs.URL,
		Keys:     []ed25519.PublicKey{publicOf(signer)},
		GOOS:     runtime.GOOS,
		GOARCH:   runtime.GOARCH,
		Entropy:  rand.Reader,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := u.Check(t.Context(), Request{Stage: true})
	if err != nil || res.Outcome != Staged {
		t.Fatalf("Check = %+v, %v; want Staged", res, err)
	}
	out, err := exec.CommandContext(t.Context(), exe, "version").Output()
	if err != nil || !bytes.HasPrefix(out, []byte("clair v0.2.0 ")) {
		t.Fatalf("%s version = %q, %v; want v0.2.0", exe, out, err)
	}
	info, err := os.Stat(exe)
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Errorf("mode = %v, %v; want 0755", info.Mode(), err)
	}
	if extra := leftovers(t, dir); len(extra) > 0 {
		t.Errorf("left beside the binary: %v", extra)
	}
}

func TestStageRefusesABuildThatFails(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	exe := installed(t, dir, script("v0.1.0"))
	broken := []byte("#!/bin/sh\nexit 3\n")
	rs := newReleaseServer(t, "v0.2.0", map[string]release{"v0.2.0": {build: broken}})
	u, err := New(Options{
		Current: "v0.1.0", Exe: exe, Releases: rs.URL,
		Keys: []ed25519.PublicKey{publicOf(signer)}, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Entropy: rand.Reader,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := u.Check(t.Context(), Request{Stage: true}); err == nil {
		t.Fatal("Check staged a build whose version fails")
	}
	if got, _ := os.ReadFile(exe); !bytes.Equal(got, script("v0.1.0")) {
		t.Errorf("binary on disk changed to %q", got)
	}
	if extra := leftovers(t, dir); len(extra) > 0 {
		t.Errorf("left beside the binary: %v", extra)
	}
}
