// Package update keeps the agent current: it reads the newest release from
// claircode.app, checks its signature against the keys built into this
// binary, and swaps the new build onto disk where this one is. The running
// daemon keeps its image; the new binary runs from the next start, whatever
// starts it — a login, a crash restart, `clair service restart`, install.sh.
// Nothing here restarts anything.
//
// Only a release build (a strict vX.Y.Z stamped by the linker) updates, and
// only forward: a binary on disk that is newer, or not a release, is left
// alone. The service registration and the hooks keep naming the same path,
// so they need no change.
package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DefaultReleasesURL is where install.sh and install.ps1 download from too.
const DefaultReleasesURL = "https://claircode.app/releases"

const sizeSHA256 = sha256.Size

// Errors a caller can test with errors.Is.
var (
	// ErrNotRelease is a build that does not update itself: a development
	// build, a pre-release, or anything `go build` stamped.
	ErrNotRelease = errors.New("update: not a release build")
	// ErrBadSignature is a release no built-in key signed.
	ErrBadSignature = errors.New("update: bad release signature")
	// ErrNoAsset is a release without a build for this OS and architecture.
	ErrNoAsset = errors.New("update: no build for this system")
	// ErrUnwritable is a binary whose directory this user cannot write.
	ErrUnwritable = errors.New("update: cannot write beside the binary")
)

// Outcome is what a check found or did.
type Outcome string

// Outcomes of Check.
const (
	// UpToDate: the running version is the latest, or newer.
	UpToDate Outcome = "up-to-date"
	// Available: a newer release exists; a check without staging stops here.
	Available Outcome = "available"
	// Staged: the newer release was verified and swapped onto disk.
	Staged Outcome = "staged"
	// AlreadyStaged: the binary on disk already is the latest release.
	AlreadyStaged Outcome = "already-staged"
	// LeftAlone: the binary on disk is newer, or not a release; Result.Note says which.
	LeftAlone Outcome = "left-alone"
)

// Request is one check.
type Request struct {
	// Stage swaps a newer release onto disk; false only looks.
	Stage bool
	// Releases overrides Options.Releases for this check.
	Releases string
}

// Result is a finished check.
type Result struct {
	Outcome Outcome
	// Latest is the version latest.txt names.
	Latest string
	// Path is the binary checked or replaced.
	Path string
	// Note says why the binary was left alone.
	Note string
}

// Status is what the updater last saw, for `clair status`.
type Status struct {
	// Enabled is false when the background check is turned off (agent.json's
	// autoUpdate); a check on request still runs.
	Enabled bool
	// CheckedAt is when the last check finished, successful or not.
	CheckedAt time.Time
	// Latest is latest.txt at the last successful check.
	Latest string
	// Staged is a release swapped onto disk that this process is not running.
	Staged string
	// Note says why the last check left the binary alone.
	Note string
	// Err is the last check's failure; "" after a success.
	Err string
}

// Options configure an Updater.
type Options struct {
	// Current is this build's linker-stamped version; it must be a release.
	Current string
	// Exe is the binary to replace: absolute, symlinks resolved.
	Exe string
	// Releases is the release server's base URL; "" is DefaultReleasesURL.
	Releases string
	// Keys verify a release; nil means ReleaseKeys.
	Keys []ed25519.PublicKey
	// GOOS and GOARCH pick the build (runtime's, in production).
	GOOS, GOARCH string
	// RunVersion runs `<path> version` and returns what it printed; nil runs it.
	RunVersion func(ctx context.Context, path string) (string, error)
	// HTTP overrides the release client (tests); nil builds one.
	HTTP *http.Client
	// Enabled says whether the background check may run, read before each
	// one; nil is always.
	Enabled func() bool
	Logger  *slog.Logger
	Now     func() time.Time
	// Entropy spreads the checks and names the aside files; required.
	Entropy io.Reader
}

// Updater checks and stages releases; its methods are safe for concurrent
// use, and checks run one at a time.
type Updater struct {
	opts    Options
	current Release
	log     *slog.Logger
	now     func() time.Time

	// checking serialises checks: the background loop and `clair update`
	// never download or swap at once.
	checking sync.Mutex

	mu     sync.Mutex
	status Status
}

// New builds an Updater; ErrNotRelease when Current is not a release.
func New(o Options) (*Updater, error) {
	current, ok := ParseRelease(o.Current)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotRelease, o.Current)
	}
	if o.Exe == "" || !filepath.IsAbs(o.Exe) {
		return nil, fmt.Errorf("update: the binary's path must be absolute, not %q", o.Exe)
	}
	if o.Entropy == nil {
		return nil, errors.New("update: an entropy source is required")
	}
	u := &Updater{opts: o, current: current, log: o.Logger, now: o.Now}
	if u.opts.Keys == nil {
		u.opts.Keys = ReleaseKeys()
	}
	if u.opts.Releases == "" {
		u.opts.Releases = DefaultReleasesURL
	}
	if u.opts.RunVersion == nil {
		u.opts.RunVersion = runVersion
	}
	if u.log == nil {
		u.log = slog.New(slog.DiscardHandler)
	}
	if u.now == nil {
		u.now = time.Now
	}
	return u, nil
}

// Path is the binary this updater replaces.
func (u *Updater) Path() string { return u.opts.Exe }

// Status reports the last check.
func (u *Updater) Status() Status {
	u.mu.Lock()
	st := u.status
	u.mu.Unlock()
	st.Enabled = u.opts.Enabled == nil || u.opts.Enabled()
	return st
}

// Check reads the latest release and, when req.Stage is set and it is newer
// than the binary on disk, verifies it and swaps it in.
func (u *Updater) Check(ctx context.Context, req Request) (Result, error) {
	u.checking.Lock()
	defer u.checking.Unlock()
	res, err := u.look(ctx, req)
	u.record(res, err)
	return res, err
}

func (u *Updater) record(res Result, err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.status.CheckedAt = u.now()
	if err != nil {
		u.status.Err = err.Error()
		return
	}
	u.status.Err = ""
	u.status.Latest = res.Latest
	u.status.Note = res.Note
	switch res.Outcome {
	case Staged, AlreadyStaged:
		u.status.Staged = res.Latest
	case UpToDate, Available, LeftAlone:
	}
}

// look is Check without the lock and the record.
func (u *Updater) look(ctx context.Context, req Request) (Result, error) {
	res := Result{Path: u.opts.Exe}
	base := req.Releases
	if base == "" {
		base = u.opts.Releases
	}
	src, err := newFetcher(base, u.userAgent(), u.opts.HTTP)
	if err != nil {
		return res, err
	}
	raw, err := src.text(ctx, "latest.txt", maxLatestBytes)
	if err != nil {
		return res, err
	}
	latest, ok := ParseRelease(strings.TrimSpace(string(raw)))
	if !ok {
		return res, fmt.Errorf("update: latest.txt names %q, not a release", strings.TrimSpace(string(raw)))
	}
	res.Latest = latest.String()
	if latest.Compare(u.current) <= 0 {
		res.Outcome = UpToDate
		return res, nil
	}

	// The signature covers the checksums, and the checksums the build.
	sums, err := src.text(ctx, res.Latest+"/SHA256SUMS.txt", maxSumsBytes)
	if err != nil {
		return res, err
	}
	sig, err := src.text(ctx, res.Latest+"/SHA256SUMS.txt.sig", maxSigBytes)
	if err != nil {
		return res, err
	}
	if err = Verify(u.opts.Keys, sums, sig); err != nil {
		return res, err
	}
	table, err := ParseSums(sums, res.Latest)
	if err != nil {
		return res, err
	}
	asset := AssetName(res.Latest, u.opts.GOOS, u.opts.GOARCH)
	want, ok := table[asset]
	if !ok {
		return res, fmt.Errorf("%w: %s lists no %s", ErrNoAsset, res.Latest, asset)
	}

	// What is on disk decides, not what is running: never replace a binary
	// that is already the latest, newer, or somebody's own build.
	have, err := hashFile(u.opts.Exe)
	if errors.Is(err, fs.ErrNotExist) {
		res.Outcome, res.Note = LeftAlone, u.opts.Exe+" is gone"
		return res, nil
	}
	if err != nil {
		return res, err
	}
	if have == want {
		res.Outcome = AlreadyStaged
		return res, nil
	}
	out, err := u.opts.RunVersion(ctx, u.opts.Exe)
	if err != nil {
		return res, fmt.Errorf("update: ask %s its version: %w", u.opts.Exe, err)
	}
	onDisk, _ := VersionOf(out)
	disk, ok := ParseRelease(onDisk)
	switch {
	case !ok:
		res.Outcome, res.Note = LeftAlone, fmt.Sprintf("%s is %q, not a release", u.opts.Exe, onDisk)
		return res, nil
	case disk.Compare(latest) >= 0:
		res.Outcome, res.Note = LeftAlone, fmt.Sprintf("%s is already %s", u.opts.Exe, onDisk)
		return res, nil
	}
	if !req.Stage {
		res.Outcome = Available
		return res, nil
	}
	if err = u.stage(ctx, src, asset, want, res.Latest); err != nil {
		return res, err
	}
	res.Outcome = Staged
	u.log.Info("update staged; it runs from the next start", "version", res.Latest, "path", u.opts.Exe)
	return res, nil
}

func (u *Updater) userAgent() string {
	return "clair-agent/" + u.current.String() + " (" + u.opts.GOOS + "/" + u.opts.GOARCH + ")"
}

// hashFile is the SHA-256 of the file at path.
func hashFile(path string) ([sizeSHA256]byte, error) {
	var sum [sizeSHA256]byte
	f, err := os.Open(path)
	if err != nil {
		return sum, fmt.Errorf("update: %w", err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxBinaryBytes+1)); err != nil {
		return sum, fmt.Errorf("update: hash %s: %w", path, err)
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}
