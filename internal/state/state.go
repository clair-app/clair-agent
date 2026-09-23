// Package state is the agent's config directory (RELAY.md §5.1):
//
//	<dir>/agent.json      the loopback bearer, the admin token, the relay URL
//	<dir>/host.key        the host's X25519 + Ed25519 seeds
//	<dir>/pairs/<id>.json one file per pair: keys, counters, the phone's name
//
// <dir> is $CLAIR_CONFIG_DIR, else os.UserConfigDir()/clair — ~/.config/clair
// on Linux, ~/Library/Application Support/clair on macOS, %AppData%\clair on
// Windows. Files are written 0600 through a temp file and a rename, so a
// crash leaves the old file or the new one, never half of either. Mode bits
// are advisory on Windows, where the profile directory's ACL is the guard.
//
// A pair file has one writer at a time: the daemon while the pair is loaded,
// the CLI otherwise; the handoff is the daemon's control surface.
package state

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"claircode.app/clair-agent/internal/envelope"
	"claircode.app/clair-agent/internal/identity"
)

const (
	// EnvConfigDir overrides the config directory.
	EnvConfigDir = "CLAIR_CONFIG_DIR"
	dirName      = "clair"
	agentFile    = "agent.json"
	hostKeyFile  = "host.key"
	pairsDir     = "pairs"
	fileVersion  = 1
	// The loopback bearer and the admin token are tokenBytes of randomness,
	// base64url without padding — the phone's own token is the same shape.
	tokenBytes = 32
	// Windows may refuse to replace a file another process has open for a
	// moment (an editor, an indexer); the rename is retried that many times.
	renameRetries = 3
	renameBackoff = 20 * time.Millisecond
	// A command that lost the race to create agent.json waits for the
	// winner's write to land: at most settleRetries × settleBackoff.
	settleRetries = 40
	settleBackoff = 5 * time.Millisecond
)

// ErrNotFound is a pair or file that is not there.
var ErrNotFound = errors.New("state: not found")

// Agent is agent.json.
type Agent struct {
	V int `json:"v"`
	// Listen is the loopback address the daemon binds.
	Listen string `json:"listen"`
	// Token is the hook bearer written into settings.json.
	Token string `json:"token"`
	// AdminToken guards the daemon's control surface; it never leaves this file.
	AdminToken string `json:"adminToken"`
	// Relay is the relay's base URL.
	Relay string `json:"relay"`
	// LogLevel is the daemon's default log level.
	LogLevel string `json:"logLevel"`
}

// Pair is pairs/<id>.json.
type Pair struct {
	V         int       `json:"v"`
	PairID    string    `json:"pairId"`
	Relay     string    `json:"relay"`
	PhonePub  string    `json:"phonePub"`
	PhoneName string    `json:"phoneName"`
	KH2P      string    `json:"kH2p"`
	KP2H      string    `json:"kP2h"`
	FP        string    `json:"fp"`
	CreatedAt time.Time `json:"createdAt"`
	// H2PNext is the sender counter's persisted limit: every n below it may
	// have been used (envelope.Counter).
	H2PNext uint64 `json:"h2pNext"`
	// P2HLast is the highest n accepted from the phone.
	P2HLast uint64 `json:"p2hLast"`
	// PendingHelloAck says `clair pair` could not upload the hello-ack; the
	// daemon sends it first.
	PendingHelloAck bool `json:"pendingHelloAck"`
	// IdleThresholdSec is the phone's presence threshold (RELAY.md §4.3),
	// from its hello and then its policy records; nil is the agent's default,
	// 0 switches the release of bubbled decides off.
	IdleThresholdSec *int `json:"idleThresholdSec,omitempty"`
	// RelayRevokedAt is when the relay first said, without a break since,
	// that this pair is gone (410 or 404). Unauthenticated, it only parks the
	// pair; it ends it once it has held for the grace period (ADR
	// 2026-09.9ufb).
	RelayRevokedAt *time.Time `json:"relayRevokedAt,omitempty"`
}

// Keys decodes the pair's traffic keys.
func (p *Pair) Keys() (*envelope.Keys, error) {
	var keys envelope.Keys
	for _, f := range []struct {
		name string
		src  string
		dst  []byte
	}{{"kH2p", p.KH2P, keys.H2P[:]}, {"kP2h", p.KP2H, keys.P2H[:]}, {"fp", p.FP, keys.FP[:]}} {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(f.src)
		if err != nil || len(raw) != len(f.dst) {
			return nil, fmt.Errorf("state: pair %s: bad %s", p.PairID, f.name)
		}
		copy(f.dst, raw)
	}
	return &keys, nil
}

// SetKeys stores the pair's traffic keys.
func (p *Pair) SetKeys(keys *envelope.Keys) {
	enc := base64.RawURLEncoding
	p.KH2P, p.KP2H, p.FP = enc.EncodeToString(keys.H2P[:]), enc.EncodeToString(keys.P2H[:]), enc.EncodeToString(keys.FP[:])
}

// DefaultDir resolves the config directory from the environment.
func DefaultDir(getenv func(string) string) (string, error) {
	if dir := getenv(EnvConfigDir); dir != "" {
		return dir, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("state: no config directory: %w", err)
	}
	return filepath.Join(base, dirName), nil
}

// Dir is an opened config directory.
type Dir struct {
	path string
	// mu serialises the read-modify-write cycles on pair files.
	mu sync.Mutex
}

// Open creates the directory (0700) if needed.
func Open(path string) (*Dir, error) {
	if err := os.MkdirAll(filepath.Join(path, pairsDir), 0o700); err != nil {
		return nil, fmt.Errorf("state: create %s: %w", path, err)
	}
	return &Dir{path: path}, nil
}

// Path is the directory.
func (d *Dir) Path() string { return d.path }

// NewToken mints a bearer: 32 random bytes, base64url without padding.
func NewToken(entropy io.Reader) (string, error) {
	var raw [tokenBytes]byte
	if _, err := io.ReadFull(entropy, raw[:]); err != nil {
		return "", fmt.Errorf("state: read token entropy: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// EnsureAgent loads agent.json or creates it from defaults with fresh tokens.
// Creation is exclusive, so two commands racing on a fresh directory end up
// with the same file. The created result reports which happened.
func (d *Dir) EnsureAgent(entropy io.Reader, defaults Agent) (a Agent, created bool, err error) {
	a, err = d.loadAgentSettled()
	if err == nil {
		return a, false, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return Agent{}, false, err
	}
	a = defaults
	a.V = fileVersion
	if a.Token, err = NewToken(entropy); err != nil {
		return Agent{}, false, err
	}
	if a.AdminToken, err = NewToken(entropy); err != nil {
		return Agent{}, false, err
	}
	data, err := marshal(a)
	if err != nil {
		return Agent{}, false, err
	}
	f, err := os.OpenFile(filepath.Join(d.path, agentFile), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		a, err = d.loadAgentSettled()
		return a, false, err
	}
	if err != nil {
		return Agent{}, false, fmt.Errorf("state: create agent.json: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return Agent{}, false, fmt.Errorf("state: write agent.json: %w", err)
	}
	if err := f.Close(); err != nil {
		return Agent{}, false, fmt.Errorf("state: write agent.json: %w", err)
	}
	return a, true, nil
}

// loadAgentSettled is LoadAgent for a file another command may be writing
// this instant: the exclusive create lands before its content, so an empty
// or truncated file is retried for a moment before it counts as corrupt.
func (d *Dir) loadAgentSettled() (Agent, error) {
	var a Agent
	var err error
	for attempt := range settleRetries {
		if a, err = d.LoadAgent(); err == nil || errors.Is(err, ErrNotFound) {
			return a, err
		}
		if attempt < settleRetries-1 {
			time.Sleep(settleBackoff)
		}
	}
	return a, err
}

// LoadAgent reads agent.json.
func (d *Dir) LoadAgent() (Agent, error) {
	var a Agent
	if err := d.load(agentFile, &a); err != nil {
		return Agent{}, err
	}
	if a.V != fileVersion {
		return Agent{}, fmt.Errorf("state: agent.json version %d, want %d", a.V, fileVersion)
	}
	return a, nil
}

// SaveAgent rewrites agent.json.
func (d *Dir) SaveAgent(a Agent) error {
	a.V = fileVersion
	data, err := marshal(a)
	if err != nil {
		return err
	}
	return d.write(agentFile, data)
}

// EnsureHostKey loads host.key or generates it.
func (d *Dir) EnsureHostKey(entropy io.Reader) (keys *identity.Keys, created bool, err error) {
	keys, err = d.LoadHostKey()
	if err == nil {
		return keys, false, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, false, err
	}
	keys, err = d.ReplaceHostKey(entropy)
	return keys, true, err
}

// LoadHostKey reads host.key.
func (d *Dir) LoadHostKey() (*identity.Keys, error) {
	data, err := os.ReadFile(filepath.Join(d.path, hostKeyFile))
	if err != nil {
		return nil, notFound(hostKeyFile, err)
	}
	keys, err := identity.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("state: %s: %w", hostKeyFile, err)
	}
	return keys, nil
}

// ReplaceHostKey generates a new host key pair (RELAY.md §6.6: a re-pair
// gets new keys on both sides).
func (d *Dir) ReplaceHostKey(entropy io.Reader) (*identity.Keys, error) {
	keys, err := identity.Generate(entropy)
	if err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	data, err := identity.Marshal(keys)
	if err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	if err := d.write(hostKeyFile, data); err != nil {
		return nil, err
	}
	return keys, nil
}

// DeleteHostKey removes host.key; a missing file is fine.
func (d *Dir) DeleteHostKey() error {
	return d.remove(hostKeyFile)
}

// ListPairs reads every pair file, sorted by name.
func (d *Dir) ListPairs() ([]Pair, error) {
	entries, err := os.ReadDir(filepath.Join(d.path, pairsDir))
	if err != nil {
		return nil, fmt.Errorf("state: list pairs: %w", err)
	}
	var pairs []Pair
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") || strings.Contains(name, ".tmp-") {
			continue
		}
		p, err := d.LoadPair(strings.TrimSuffix(name, ".json"))
		if err != nil {
			return nil, err
		}
		pairs = append(pairs, p)
	}
	return pairs, nil
}

// LoadPair reads one pair file.
func (d *Dir) LoadPair(id string) (Pair, error) {
	var p Pair
	if err := d.load(pairFile(id), &p); err != nil {
		return Pair{}, err
	}
	if p.V != fileVersion || p.PairID != id {
		return Pair{}, fmt.Errorf("state: pair file %s: version %d for pair %q", pairFile(id), p.V, p.PairID)
	}
	return p, nil
}

// SavePair writes a pair file.
func (d *Dir) SavePair(p Pair) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.savePairLocked(p)
}

func (d *Dir) savePairLocked(p Pair) error {
	if p.PairID == "" {
		return errors.New("state: pair without an id")
	}
	p.V = fileVersion
	data, err := marshal(p)
	if err != nil {
		return err
	}
	return d.write(pairFile(p.PairID), data)
}

// DeletePair removes a pair file; a missing file is fine. It takes the same
// lock as the counter updates, so a delete never races a read-modify-write
// into resurrecting the file.
func (d *Dir) DeletePair(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.remove(pairFile(id))
}

// ReserveH2P persists the sender counter's new limit before the daemon uses
// the block below it (envelope.Counter's reserve callback). It never lowers
// the limit.
func (d *Dir) ReserveH2P(id string, limit uint64) error {
	return d.updatePair(id, func(p *Pair) {
		p.H2PNext = max(p.H2PNext, limit)
	})
}

// SaveP2HLast persists the highest n accepted from the phone.
func (d *Dir) SaveP2HLast(id string, n uint64) error {
	return d.updatePair(id, func(p *Pair) {
		p.P2HLast = max(p.P2HLast, n)
	})
}

// ClearPendingHelloAck records that the hello-ack reached the relay.
func (d *Dir) ClearPendingHelloAck(id string) error {
	return d.updatePair(id, func(p *Pair) { p.PendingHelloAck = false })
}

// SetIdleThreshold records the phone's presence threshold; nil restores the
// agent's default.
func (d *Dir) SetIdleThreshold(id string, sec *int) error {
	return d.updatePair(id, func(p *Pair) { p.IdleThresholdSec = sec })
}

// SetRelayRevokedAt records when the relay began reporting a pair gone; the
// zero time clears it.
func (d *Dir) SetRelayRevokedAt(id string, at time.Time) error {
	return d.updatePair(id, func(p *Pair) {
		p.RelayRevokedAt = nil
		if !at.IsZero() {
			p.RelayRevokedAt = &at
		}
	})
}

func (d *Dir) updatePair(id string, fn func(*Pair)) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	p, err := d.LoadPair(id)
	if err != nil {
		return err
	}
	fn(&p)
	return d.savePairLocked(p)
}

func pairFile(id string) string {
	return filepath.Join(pairsDir, id+".json")
}

func marshal(v any) ([]byte, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("state: encode: %w", err)
	}
	return append(data, '\n'), nil
}

func (d *Dir) load(name string, v any) error {
	data, err := os.ReadFile(filepath.Join(d.path, name))
	if err != nil {
		return notFound(name, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("state: %s: %w", name, err)
	}
	return nil
}

func notFound(name string, err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return fmt.Errorf("state: read %s: %w", name, err)
}

// write replaces a file in the directory atomically, 0600.
func (d *Dir) write(name string, data []byte) error {
	return WriteFile(filepath.Join(d.path, name), data, 0o600)
}

// WriteFile replaces path atomically: a fresh random temp name in the same
// directory, created exclusively (so a planted file or symlink at a temp name
// is never followed), given perm whatever the umask, synced, then renamed
// over path. A symlink at path itself is replaced, not followed; resolve it
// first to write through it.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return fmt.Errorf("state: temp name: %w", err)
	}
	tmp := path + ".tmp-" + hex.EncodeToString(suffix[:])
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return fmt.Errorf("state: create %s: %w", tmp, err)
	}
	fail := func(what string, err error) error {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("state: %s %s: %w", what, path, err)
	}
	if err = f.Chmod(perm); err != nil {
		return fail("chmod", err)
	}
	if _, err = f.Write(data); err != nil {
		return fail("write", err)
	}
	if err = f.Sync(); err != nil {
		return fail("sync", err)
	}
	if err = f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("state: close %s: %w", path, err)
	}
	for attempt := range renameRetries {
		err = os.Rename(tmp, path)
		if err == nil || runtime.GOOS != "windows" || attempt == renameRetries-1 {
			break
		}
		time.Sleep(renameBackoff)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("state: replace %s: %w", path, err)
	}
	return nil
}

func (d *Dir) remove(name string) error {
	if err := os.Remove(filepath.Join(d.path, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("state: remove %s: %w", name, err)
	}
	return nil
}
