// Package envelope implements the relay envelope of RELAY.md §5: the traffic
// keys derived from a pairing, XChaCha20-Poly1305 sealing with the routing
// header bound as associated data, the ULID that names an envelope, and the
// per-direction replay counters. It seals opaque bytes and knows nothing about
// the records inside them.
//
// Everything here is a pure function of its inputs — entropy and time are
// parameters — so a vector test can pin every byte.
package envelope

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// Sizes and limits. The AEAD constants are RELAY.md §5.3; the caps follow from
// the relay's 4 MiB envelope cap (§5.4, and the relay's own plan, which puts
// the cap on the envelope JSON rather than the plaintext).
const (
	// Version is the envelope's `v`; a receiver refuses any other.
	Version = 1
	// KeySize is the length of a traffic key (§5.2).
	KeySize = chacha20poly1305.KeySize
	// NonceSize is the length of the random nonce prepended to `ct` (§5.3).
	NonceSize = chacha20poly1305.NonceSizeX
	// TagSize is the Poly1305 tag appended by the AEAD.
	TagSize = chacha20poly1305.Overhead
	// FingerprintSize is the length of the pair fingerprint `fp` (§5.2).
	FingerprintSize = 16
	// PairingSecretSize is the length of the pairing secret `k` (§6.1).
	PairingSecretSize = 16
	// IDLength is the length of a ULID.
	IDLength = 26
	// MaxEnvelopeJSON is the relay's cap on one envelope's JSON (§5.4).
	MaxEnvelopeJSON = 4 << 20
	// The JSON around `ct` — six header fields with a 22-character pair id, a
	// 26-character ULID and a five-digit ttlSec — measures 122 bytes; 128
	// leaves slack for a longer ttlSec.
	maxHeaderJSON = 128
	// MaxRecordBytes is the largest plaintext that seals into an envelope under
	// MaxEnvelopeJSON: base64url inflates by 4/3 and the AEAD adds nonce and tag.
	MaxRecordBytes = (MaxEnvelopeJSON-maxHeaderJSON)/4*3 - NonceSize - TagSize
	// CounterBlock is how many sender counters a Counter reserves at a time
	// (RELAY.md revision G1): a crash wastes at most this many values, and §5.4
	// allows gaps.
	CounterBlock = 4096
)

// aadPrefix opens the associated data (§5.3).
const aadPrefix = "clair-relay/1"

// Errors a caller can test with errors.Is.
var (
	// ErrTooLarge is a record longer than MaxRecordBytes.
	ErrTooLarge = errors.New("envelope: record too large")
	// ErrHeader is a header field the AAD could not bind: an empty pair, a bad
	// id, an unknown direction or wake hint, a non-positive ttl, or a NUL byte.
	ErrHeader = errors.New("envelope: invalid header")
	// ErrVersion is an envelope whose `v` is not Version.
	ErrVersion = errors.New("envelope: unsupported version")
	// ErrMalformed is a `ct` that does not decode to nonce, ciphertext and tag.
	ErrMalformed = errors.New("envelope: malformed ciphertext")
	// ErrAuth is a ciphertext that failed authentication: a wrong key, a
	// tampered `ct`, or a header the relay relabelled.
	ErrAuth = errors.New("envelope: authentication failed")
)

// Dir is the direction an envelope travels (§5.3).
type Dir string

// The two directions.
const (
	DirH2P Dir = "h2p" // host → phone
	DirP2H Dir = "p2h" // phone → host
)

// Valid reports whether d is one of the two directions.
func (d Dir) Valid() bool { return d == DirH2P || d == DirP2H }

// Opposite is the direction of the reply.
func (d Dir) Opposite() Dir {
	if d == DirH2P {
		return DirP2H
	}
	return DirH2P
}

// Wake is the push hint the relay reads when the phone is idle (§7.5): a
// push instruction, deliberately not a hook name (§10).
type Wake string

// The three hints.
const (
	WakeNow  Wake = "now"
	WakeSoon Wake = "soon"
	WakeNo   Wake = "no"
)

// Valid reports whether w is one of the three hints.
func (w Wake) Valid() bool { return w == WakeNow || w == WakeSoon || w == WakeNo }

// Header is the routing header the relay sees. Pair, ID, Dir and Wake are
// bound into the AAD so the relay cannot re-label, re-address or downgrade an
// envelope; TTLSec is outside it on purpose, so the relay may clamp it (§5.3).
type Header struct {
	Pair   string
	ID     string
	Dir    Dir
	Wake   Wake
	TTLSec int
}

// Validate reports whether the header can be bound as associated data.
func (h Header) Validate() error {
	switch {
	case h.Pair == "":
		return fmt.Errorf("%w: empty pair", ErrHeader)
	case !ValidID(h.ID):
		return fmt.Errorf("%w: id %q is not a ULID", ErrHeader, h.ID)
	case !h.Dir.Valid():
		return fmt.Errorf("%w: unknown dir %q", ErrHeader, h.Dir)
	case !h.Wake.Valid():
		return fmt.Errorf("%w: unknown wake %q", ErrHeader, h.Wake)
	case h.TTLSec <= 0:
		return fmt.Errorf("%w: ttlSec %d is not positive", ErrHeader, h.TTLSec)
	case strings.ContainsRune(h.Pair, 0):
		// NUL is the AAD separator; a pair id containing one could alias another header.
		return fmt.Errorf("%w: pair contains NUL", ErrHeader)
	}
	return nil
}

// Envelope is the wire object (§5.3). The field order is the JSON order.
type Envelope struct {
	V      int    `json:"v"`
	Pair   string `json:"pair"`
	ID     string `json:"id"`
	Dir    Dir    `json:"dir"`
	Wake   Wake   `json:"wake"`
	TTLSec int    `json:"ttlSec"`
	CT     string `json:"ct"`
}

// Header is the routing header of e.
func (e Envelope) Header() Header {
	return Header{Pair: e.Pair, ID: e.ID, Dir: e.Dir, Wake: e.Wake, TTLSec: e.TTLSec}
}

// Validate is the receiver's check before decrypting: the version, that the
// envelope is addressed to pair in direction dir, that the header is well
// formed, and that `ct` decodes to at least a nonce and a tag.
func (e Envelope) Validate(pair string, dir Dir) error {
	if e.V != Version {
		return fmt.Errorf("%w: v=%d", ErrVersion, e.V)
	}
	if e.Pair != pair {
		return fmt.Errorf("%w: pair %q, want %q", ErrHeader, e.Pair, pair)
	}
	if e.Dir != dir {
		return fmt.Errorf("%w: dir %q, want %q", ErrHeader, e.Dir, dir)
	}
	if err := e.Header().Validate(); err != nil {
		return err
	}
	if _, err := decodeCT(e.CT); err != nil {
		return err
	}
	return nil
}

// AAD is the associated data for h (§5.3):
// "clair-relay/1" ‖ 0 ‖ pair ‖ 0 ‖ id ‖ 0 ‖ dir ‖ 0 ‖ wake, UTF-8.
func AAD(h Header) []byte {
	parts := []string{aadPrefix, h.Pair, h.ID, string(h.Dir), string(h.Wake)}
	return []byte(strings.Join(parts, "\x00"))
}

// Seal encrypts record under key for the header h. It reads exactly NonceSize
// bytes from nonce — crypto/rand.Reader in production, a fixed reader in a
// vector test — and returns the envelope with
// ct = base64url(nonce ‖ XChaCha20-Poly1305(key, nonce, record, AAD(h))).
func Seal(key []byte, h Header, record []byte, nonce io.Reader) (Envelope, error) {
	if len(record) > MaxRecordBytes {
		return Envelope{}, fmt.Errorf("%w: %d bytes, max %d", ErrTooLarge, len(record), MaxRecordBytes)
	}
	if err := h.Validate(); err != nil {
		return Envelope{}, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return Envelope{}, fmt.Errorf("envelope: key: %w", err)
	}
	ct := make([]byte, NonceSize, NonceSize+len(record)+TagSize)
	if _, err := io.ReadFull(nonce, ct); err != nil {
		return Envelope{}, fmt.Errorf("envelope: read nonce: %w", err)
	}
	ct = aead.Seal(ct, ct[:NonceSize], record, AAD(h))
	return Envelope{
		V:      Version,
		Pair:   h.Pair,
		ID:     h.ID,
		Dir:    h.Dir,
		Wake:   h.Wake,
		TTLSec: h.TTLSec,
		CT:     base64.RawURLEncoding.EncodeToString(ct),
	}, nil
}

// Open decrypts e under key, verifying the AAD built from e's own header: an
// envelope the relay relabelled fails with ErrAuth.
func Open(key []byte, e Envelope) ([]byte, error) {
	if e.V != Version {
		return nil, fmt.Errorf("%w: v=%d", ErrVersion, e.V)
	}
	h := e.Header()
	if err := h.Validate(); err != nil {
		return nil, err
	}
	ct, err := decodeCT(e.CT)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("envelope: key: %w", err)
	}
	record, err := aead.Open(nil, ct[:NonceSize], ct[NonceSize:], AAD(h))
	if err != nil {
		return nil, ErrAuth
	}
	return record, nil
}

// decodeCT decodes the strict, unpadded base64url of `ct` and checks it holds
// at least a nonce and a tag.
func decodeCT(s string) ([]byte, error) {
	ct, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if len(ct) < NonceSize+TagSize {
		return nil, fmt.Errorf("%w: %d bytes, need at least %d", ErrMalformed, len(ct), NonceSize+TagSize)
	}
	return ct, nil
}
