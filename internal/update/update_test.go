package update

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	signer   = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	stranger = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
)

// fakeBuild is what a "binary" holds in these tests: exactly what its
// `version` prints, so fakeRunVersion can answer for it without an exec.
func fakeBuild(version string) []byte {
	return []byte("clair " + version + " (fake, 2026-09-24T00:00:00Z)\n")
}

// fakeRunVersion "runs" a fake build by reading it.
func fakeRunVersion(_ context.Context, path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// release is one version on the fake server; the zero overrides serve a
// correct, signed release.
type release struct {
	build []byte // this host's build; nil means fakeBuild(version)
	serve []byte // what is served for it instead, when set
	sums  []byte // replaces the generated SHA256SUMS.txt
	sig   []byte // replaces the signature by signer
	key   ed25519.PrivateKey
	noOwn bool // the release has no build for this host
}

// releaseServer serves latest.txt and signed releases the way clair-web's
// `stage` lays them out.
type releaseServer struct {
	*httptest.Server

	mu       sync.Mutex
	latest   string
	releases map[string]release
	gets     []string
}

func newReleaseServer(t *testing.T, latest string, releases map[string]release) *releaseServer {
	t.Helper()
	rs := &releaseServer{latest: latest, releases: releases}
	rs.Server = httptest.NewServer(http.HandlerFunc(rs.serve))
	t.Cleanup(rs.Close)
	return rs
}

func (rs *releaseServer) serve(w http.ResponseWriter, r *http.Request) {
	rs.mu.Lock()
	rs.gets = append(rs.gets, r.URL.Path)
	latest := rs.latest
	rs.mu.Unlock()
	if r.URL.Path == "/latest.txt" {
		fmt.Fprintln(w, latest)
		return
	}
	version, file, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	rel, known := rs.releases[version]
	if !ok || !known {
		http.NotFound(w, r)
		return
	}
	own := AssetName(version, runtime.GOOS, runtime.GOARCH)
	build := rel.build
	if build == nil {
		build = fakeBuild(version)
	}
	switch file {
	case "SHA256SUMS.txt":
		_, _ = w.Write(rs.sumsFor(version, rel, build))
	case "SHA256SUMS.txt.sig":
		if rel.sig != nil {
			_, _ = w.Write(rel.sig)
			return
		}
		key := rel.key
		if key == nil {
			key = signer
		}
		fmt.Fprintln(w, Sign(key, rs.sumsFor(version, rel, build)))
	case own:
		if rel.serve != nil {
			_, _ = w.Write(rel.serve)
			return
		}
		_, _ = w.Write(build)
	default:
		http.NotFound(w, r)
	}
}

func (*releaseServer) sumsFor(version string, rel release, build []byte) []byte {
	if rel.sums != nil {
		return rel.sums
	}
	var lines []string
	for _, p := range []string{"darwin-amd64", "darwin-arm64", "linux-amd64", "linux-arm64", "windows-amd64.exe", "windows-arm64.exe"} {
		name := "clair-" + version + "-" + p
		sum := sha256.Sum256([]byte("another build " + name))
		lines = append(lines, hex.EncodeToString(sum[:])+"  "+name)
	}
	own := AssetName(version, runtime.GOOS, runtime.GOARCH)
	lines = slices.DeleteFunc(lines, func(l string) bool { return strings.HasSuffix(l, "  "+own) })
	if !rel.noOwn {
		sum := sha256.Sum256(build)
		lines = append(lines, hex.EncodeToString(sum[:])+"  "+own)
	}
	slices.Sort(lines)
	return []byte(strings.Join(lines, "\n") + "\n")
}

func (rs *releaseServer) fetched(path string) bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return slices.Contains(rs.gets, path)
}

// installed writes a fake build at dir/clair and returns its path.
func installed(t *testing.T, dir string, content []byte) string {
	t.Helper()
	exe := filepath.Join(dir, "clair")
	if err := os.WriteFile(exe, content, 0o755); err != nil {
		t.Fatalf("write %s: %v", exe, err)
	}
	return exe
}

func newUpdater(t *testing.T, current, exe, releases string) *Updater {
	t.Helper()
	u, err := New(Options{
		Current:    current,
		Exe:        exe,
		Releases:   releases,
		Keys:       []ed25519.PublicKey{publicOf(signer)},
		GOOS:       runtime.GOOS,
		GOARCH:     runtime.GOARCH,
		RunVersion: fakeRunVersion,
		Entropy:    rand.Reader,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return u
}

// leftovers lists the files beside the binary other than the binary.
func leftovers(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var names []string
	for _, e := range entries {
		if e.Name() != "clair" {
			names = append(names, e.Name())
		}
	}
	return names
}

func TestCheck(t *testing.T) {
	t.Parallel()

	v2 := map[string]release{"v0.2.0": {}}
	tests := []struct {
		name     string
		current  string
		onDisk   []byte
		latest   string
		releases map[string]release
		stage    bool
		want     Outcome
		wantErr  error  // errors.Is target; nil with errText empty means success
		errText  string // substring of the error
		wantDisk []byte // nil means unchanged
		note     string // substring of Result.Note
	}{
		{name: "the running version is the latest", current: "v0.2.0", latest: "v0.2.0", releases: v2, stage: true, want: UpToDate},
		{name: "the running version is newer than the latest", current: "v0.3.0", latest: "v0.2.0", releases: v2, stage: true, want: UpToDate},
		{name: "a newer release is staged", current: "v0.1.0", latest: "v0.2.0", releases: v2, stage: true, want: Staged, wantDisk: fakeBuild("v0.2.0")},
		{name: "a check only reports", current: "v0.1.0", latest: "v0.2.0", releases: v2, want: Available},
		{name: "the disk already holds the latest", current: "v0.1.0", onDisk: fakeBuild("v0.2.0"), latest: "v0.2.0", releases: v2, stage: true, want: AlreadyStaged},
		{name: "an older staged release is replaced", current: "v0.1.0", onDisk: fakeBuild("v0.1.5"), latest: "v0.2.0", releases: v2, stage: true, want: Staged, wantDisk: fakeBuild("v0.2.0")},
		{name: "a newer binary on disk is never downgraded", current: "v0.1.0", onDisk: fakeBuild("v0.3.0"), latest: "v0.2.0", releases: v2, stage: true, want: LeftAlone, note: "already v0.3.0"},
		{name: "a local build of the same version is left alone", current: "v0.1.0", onDisk: []byte("clair v0.2.0 (mine, now)\n"), latest: "v0.2.0", releases: v2, stage: true, want: LeftAlone, note: "already v0.2.0"},
		{name: "a development build on disk is left alone", current: "v0.1.0", onDisk: fakeBuild("v0.2.0-3-gabc1234"), latest: "v0.2.0", releases: v2, stage: true, want: LeftAlone, note: "not a release"},
		{name: "a signature by another key", current: "v0.1.0", latest: "v0.2.0", releases: map[string]release{"v0.2.0": {key: stranger}}, stage: true, wantErr: ErrBadSignature},
		{name: "checksums changed after signing", current: "v0.1.0", latest: "v0.2.0", releases: map[string]release{"v0.2.0": {sig: []byte(Sign(signer, []byte("other sums\n")))}}, stage: true, wantErr: ErrBadSignature},
		{name: "a build that does not match its checksum", current: "v0.1.0", latest: "v0.2.0", releases: map[string]release{"v0.2.0": {serve: fakeBuild("v0.9.9")}}, stage: true, errText: "not the signed"},
		{name: "a build that reports another version", current: "v0.1.0", latest: "v0.2.0", releases: map[string]release{"v0.2.0": {build: fakeBuild("v0.1.9")}}, stage: true, errText: "says"},
		{name: "a build that does not run", current: "v0.1.0", latest: "v0.2.0", releases: map[string]release{"v0.2.0": {build: []byte("\x7fELF garbage")}}, stage: true, errText: "says"},
		{name: "a release without this host's build", current: "v0.1.0", latest: "v0.2.0", releases: map[string]release{"v0.2.0": {noOwn: true}}, stage: true, wantErr: ErrNoAsset},
		{name: "a pre-release named latest", current: "v0.1.0", latest: "v0.2.0-rc.1", releases: v2, stage: true, errText: "not a release"},
		{name: "a release the server does not have", current: "v0.1.0", latest: "v0.4.0", releases: v2, stage: true, errText: "404"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			onDisk := tt.onDisk
			if onDisk == nil {
				onDisk = fakeBuild(tt.current)
			}
			exe := installed(t, dir, onDisk)
			rs := newReleaseServer(t, tt.latest, tt.releases)
			u := newUpdater(t, tt.current, exe, rs.URL)

			res, err := u.Check(t.Context(), Request{Stage: tt.stage})
			switch {
			case tt.wantErr != nil && !errors.Is(err, tt.wantErr):
				t.Fatalf("Check error = %v, want %v", err, tt.wantErr)
			case tt.errText != "" && (err == nil || !strings.Contains(err.Error(), tt.errText)):
				t.Fatalf("Check error = %v, want one mentioning %q", err, tt.errText)
			case tt.wantErr == nil && tt.errText == "" && err != nil:
				t.Fatalf("Check: %v", err)
			case err == nil && res.Outcome != tt.want:
				t.Fatalf("Outcome = %q (note %q), want %q", res.Outcome, res.Note, tt.want)
			}
			if !strings.Contains(res.Note, tt.note) {
				t.Errorf("Note = %q, want it to mention %q", res.Note, tt.note)
			}
			want := tt.wantDisk
			if want == nil {
				want = onDisk
			}
			got, readErr := os.ReadFile(exe)
			if readErr != nil || !bytes.Equal(got, want) {
				t.Errorf("binary on disk = %q (%v), want %q", got, readErr, want)
			}
			if extra := leftovers(t, dir); len(extra) > 0 {
				t.Errorf("left beside the binary: %v", extra)
			}
			if res.Outcome == UpToDate && rs.fetched("/"+tt.latest+"/SHA256SUMS.txt") {
				t.Error("an up-to-date check fetched the checksums")
			}
		})
	}
}

func TestCheckStatus(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	exe := installed(t, dir, fakeBuild("v0.1.0"))
	rs := newReleaseServer(t, "v0.2.0", map[string]release{"v0.2.0": {key: stranger}, "v0.3.0": {}})
	u := newUpdater(t, "v0.1.0", exe, rs.URL)

	if _, err := u.Check(t.Context(), Request{Stage: true}); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("Check = %v, want ErrBadSignature", err)
	}
	st := u.Status()
	if st.Err == "" || st.CheckedAt.IsZero() || st.Staged != "" || !st.Enabled {
		t.Fatalf("after a failure: %+v", st)
	}

	rs.mu.Lock()
	rs.latest = "v0.3.0"
	rs.mu.Unlock()
	if _, err := u.Check(t.Context(), Request{Stage: true}); err != nil {
		t.Fatalf("Check: %v", err)
	}
	st = u.Status()
	if st.Err != "" || st.Latest != "v0.3.0" || st.Staged != "v0.3.0" {
		t.Fatalf("after staging: %+v", st)
	}
	// Staged again before a restart: the disk already holds it.
	res, err := u.Check(t.Context(), Request{Stage: true})
	if err != nil || res.Outcome != AlreadyStaged || u.Status().Staged != "v0.3.0" {
		t.Fatalf("second check = %+v, %v; status %+v", res, err, u.Status())
	}
}

func TestCheckRefusesSources(t *testing.T) {
	t.Parallel()

	exe := installed(t, t.TempDir(), fakeBuild("v0.1.0"))
	redirect := httptest.NewServer(http.RedirectHandler("http://example.invalid/latest.txt", http.StatusFound))
	t.Cleanup(redirect.Close)
	huge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("v"), maxLatestBytes+1))
	}))
	t.Cleanup(huge.Close)

	tests := []struct {
		name, releases, want string
	}{
		{name: "plain http beyond this machine", releases: "http://claircode.app/releases", want: "want https"},
		{name: "another scheme", releases: "file:///tmp/releases", want: "want https"},
		{name: "a redirect off https", releases: redirect.URL, want: "redirected to http://example.invalid"},
		{name: "an oversize latest.txt", releases: huge.URL, want: "cap"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			u := newUpdater(t, "v0.1.0", exe, tt.releases)
			if _, err := u.Check(t.Context(), Request{Stage: true}); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Check = %v, want an error mentioning %q", err, tt.want)
			}
		})
	}
}

func TestCheckRequestOverridesReleases(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	exe := installed(t, dir, fakeBuild("v0.1.0"))
	rs := newReleaseServer(t, "v0.2.0", map[string]release{"v0.2.0": {}})
	u := newUpdater(t, "v0.1.0", exe, "https://releases.invalid")
	res, err := u.Check(t.Context(), Request{Releases: rs.URL})
	if err != nil || res.Outcome != Available {
		t.Fatalf("Check = %+v, %v; want Available", res, err)
	}
}

func TestCheckUnwritable(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("directory modes do not stop this user here")
	}

	dir := t.TempDir()
	exe := installed(t, dir, fakeBuild("v0.1.0"))
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	rs := newReleaseServer(t, "v0.2.0", map[string]release{"v0.2.0": {}})
	u := newUpdater(t, "v0.1.0", exe, rs.URL)
	if _, err := u.Check(t.Context(), Request{Stage: true}); !errors.Is(err, ErrUnwritable) {
		t.Fatalf("Check = %v, want ErrUnwritable", err)
	}
}

func TestCheckBinaryGone(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	rs := newReleaseServer(t, "v0.2.0", map[string]release{"v0.2.0": {}})
	u := newUpdater(t, "v0.1.0", filepath.Join(dir, "clair"), rs.URL)
	res, err := u.Check(t.Context(), Request{Stage: true})
	if err != nil || res.Outcome != LeftAlone {
		t.Fatalf("Check = %+v, %v; want LeftAlone", res, err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "clair")); statErr == nil {
		t.Error("a removed binary was put back")
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	for _, v := range []string{"dev", "v0.1.0-3-gabc1234", "v0.1.0-dirty", "v0.2.0-rc.1", ""} {
		if _, err := New(Options{Current: v, Exe: someExe(), Entropy: rand.Reader}); !errors.Is(err, ErrNotRelease) {
			t.Errorf("New(Current %q) = %v, want ErrNotRelease", v, err)
		}
	}
	if _, err := New(Options{Current: "v0.1.0", Exe: "clair", Entropy: rand.Reader}); err == nil {
		t.Error("New accepted a relative path")
	}
}

func TestSweep(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	exe := installed(t, dir, fakeBuild("v0.1.0"))
	now := time.Now()
	files := map[string]time.Time{
		".clair-old-0011223344556677.exe": now,                   // an aside: always swept
		".clair-update-1.exe":             now.Add(-time.Hour),   // an abandoned download
		".clair-update-2.exe":             now.Add(-time.Minute), // one that may be in progress
		"notes.txt":                       now.Add(-time.Hour),
	}
	for name, mtime := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		if err := os.Chtimes(path, mtime, mtime); err != nil {
			t.Fatalf("chtimes %s: %v", name, err)
		}
	}
	u := newUpdater(t, "v0.1.0", exe, "https://releases.invalid")
	u.Sweep()
	got := leftovers(t, dir)
	want := []string{".clair-update-2.exe", "notes.txt"}
	if !slices.Equal(got, want) {
		t.Fatalf("after Sweep: %v, want %v", got, want)
	}
}

// someExe is an absolute path on this OS; nothing reads it.
func someExe() string {
	if runtime.GOOS == "windows" {
		return `C:\clair\clair.exe`
	}
	return "/opt/clair/clair"
}
