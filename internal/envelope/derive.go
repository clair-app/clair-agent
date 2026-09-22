package envelope

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// HKDF info strings (RELAY.md §5.2).
const (
	infoH2P = "clair-relay/1/h2p"
	infoP2H = "clair-relay/1/p2h"
	infoFP  = "clair-relay/1/fp"
)

// Keys are a pair's traffic keys and fingerprint (§5.2). Both ends derive the
// same values, so possession is authentication.
type Keys struct {
	H2P [KeySize]byte
	P2H [KeySize]byte
	FP  [FingerprintSize]byte
}

// Key is the traffic key for envelopes travelling in direction dir.
func (k *Keys) Key(dir Dir) []byte {
	if dir == DirP2H {
		return k.P2H[:]
	}
	return k.H2P[:]
}

// Fingerprint renders `fp` for display: lowercase hex in groups of four,
// the form `clair status` and the phone show for an out-of-band check (§6.4).
func (k *Keys) Fingerprint() string {
	h := hex.EncodeToString(k.FP[:])
	groups := make([]string, 0, len(h)/4)
	for i := 0; i < len(h); i += 4 {
		groups = append(groups, h[i:i+4])
	}
	return strings.Join(groups, " ")
}

// Derive runs the key schedule of §5.2 from our X25519 private key, the peer's
// public key and the pairing secret k:
//
//	ss    = X25519(mine, theirPub)
//	prk   = HKDF-SHA256-Extract(salt = k, ikm = ss)
//	k_h2p = HKDF-SHA256-Expand(prk, "clair-relay/1/h2p", 32)
//	k_p2h = HKDF-SHA256-Expand(prk, "clair-relay/1/p2h", 32)
//	fp    = HKDF-SHA256-Expand(prk, "clair-relay/1/fp", 16)
//
// crypto/ecdh rejects a low-order peer key (an all-zero shared secret) itself.
func Derive(mine *ecdh.PrivateKey, theirPub, k []byte) (*Keys, error) {
	if len(k) != PairingSecretSize {
		return nil, fmt.Errorf("envelope: pairing secret is %d bytes, want %d", len(k), PairingSecretSize)
	}
	pub, err := ecdh.X25519().NewPublicKey(theirPub)
	if err != nil {
		return nil, fmt.Errorf("envelope: peer public key: %w", err)
	}
	ss, err := mine.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("envelope: x25519: %w", err)
	}
	prk, err := hkdf.Extract(sha256.New, ss, k)
	if err != nil {
		return nil, fmt.Errorf("envelope: hkdf extract: %w", err)
	}
	var keys Keys
	for _, out := range []struct {
		dst  []byte
		info string
	}{
		{keys.H2P[:], infoH2P},
		{keys.P2H[:], infoP2H},
		{keys.FP[:], infoFP},
	} {
		okm, err := hkdf.Expand(sha256.New, prk, out.info, len(out.dst))
		if err != nil {
			return nil, fmt.Errorf("envelope: hkdf expand %s: %w", out.info, err)
		}
		copy(out.dst, okm)
	}
	return &keys, nil
}
