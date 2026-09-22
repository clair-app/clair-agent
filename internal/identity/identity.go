// Package identity holds a device's long-lived key material: an X25519 key
// for agreement and an Ed25519 key for authenticating to the relay
// (RELAY.md §5.1). The host is one such device; tools/phonesim is another.
//
// Both keys are derived from raw 32-byte seeds read from an injected entropy
// source rather than from the curve's own generator, so a test can pin a key
// pair by handing in fixed bytes.
package identity

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// SeedSize is the length of each raw seed: the X25519 scalar and the Ed25519
// seed are both 32 bytes.
const SeedSize = 32

// fileVersion is the `v` of the JSON form; a reader refuses any other.
const fileVersion = 1

// ErrMalformed is returned for key material of the wrong shape.
var ErrMalformed = errors.New("identity: malformed key material")

// Keys is one device's key pair set.
type Keys struct {
	agreement *ecdh.PrivateKey
	auth      ed25519.PrivateKey
}

// Generate reads 2×[SeedSize] bytes from entropy — the X25519 scalar, then the
// Ed25519 seed — and builds the keys from them.
func Generate(entropy io.Reader) (*Keys, error) {
	var seeds [2 * SeedSize]byte
	if _, err := io.ReadFull(entropy, seeds[:]); err != nil {
		return nil, fmt.Errorf("read key entropy: %w", err)
	}
	return FromSeeds(seeds[:SeedSize], seeds[SeedSize:])
}

// FromSeeds builds the keys from their raw seeds. It is the entry point for a
// vector test with pinned keys.
func FromSeeds(x25519Scalar, ed25519Seed []byte) (*Keys, error) {
	if len(x25519Scalar) != SeedSize {
		return nil, fmt.Errorf("%w: x25519 scalar is %d bytes, want %d", ErrMalformed, len(x25519Scalar), SeedSize)
	}
	if len(ed25519Seed) != SeedSize {
		return nil, fmt.Errorf("%w: ed25519 seed is %d bytes, want %d", ErrMalformed, len(ed25519Seed), SeedSize)
	}
	agreement, err := ecdh.X25519().NewPrivateKey(x25519Scalar)
	if err != nil {
		return nil, fmt.Errorf("%w: x25519 scalar: %w", ErrMalformed, err)
	}
	return &Keys{agreement: agreement, auth: ed25519.NewKeyFromSeed(ed25519Seed)}, nil
}

// Agreement is the X25519 private key (RELAY.md §5.2 key agreement).
func (k *Keys) Agreement() *ecdh.PrivateKey { return k.agreement }

// AgreementPublic is the 32-byte X25519 public key: the QR's `hostPub`, or the
// `phonePub` a phone sends to complete a pairing.
func (k *Keys) AgreementPublic() []byte { return k.agreement.PublicKey().Bytes() }

// Auth is the Ed25519 private key that signs relay requests (RELAY.md §7.3).
func (k *Keys) Auth() ed25519.PrivateKey { return k.auth }

// AuthPublic is the 32-byte Ed25519 public key the relay registers.
func (k *Keys) AuthPublic() ed25519.PublicKey {
	pub, ok := k.auth.Public().(ed25519.PublicKey)
	if !ok {
		// ed25519.PrivateKey.Public always returns an ed25519.PublicKey.
		panic("identity: ed25519 public key has an unexpected type")
	}
	return pub
}

// file is the on-disk form: both seeds, base64url without padding.
type file struct {
	V       int    `json:"v"`
	X25519  string `json:"x25519"`
	Ed25519 string `json:"ed25519"`
}

// Marshal encodes the keys as the JSON the config directory stores.
func Marshal(k *Keys) ([]byte, error) {
	enc := base64.RawURLEncoding
	data, err := json.Marshal(file{
		V:       fileVersion,
		X25519:  enc.EncodeToString(k.agreement.Bytes()),
		Ed25519: enc.EncodeToString(k.auth.Seed()),
	})
	if err != nil {
		return nil, fmt.Errorf("encode identity: %w", err)
	}
	return append(data, '\n'), nil
}

// Parse decodes what [Marshal] wrote.
func Parse(data []byte) (*Keys, error) {
	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if f.V != fileVersion {
		return nil, fmt.Errorf("%w: version %d, want %d", ErrMalformed, f.V, fileVersion)
	}
	dec := base64.RawURLEncoding.Strict()
	scalar, err := dec.DecodeString(f.X25519)
	if err != nil {
		return nil, fmt.Errorf("%w: x25519: %w", ErrMalformed, err)
	}
	seed, err := dec.DecodeString(f.Ed25519)
	if err != nil {
		return nil, fmt.Errorf("%w: ed25519: %w", ErrMalformed, err)
	}
	return FromSeeds(scalar, seed)
}
