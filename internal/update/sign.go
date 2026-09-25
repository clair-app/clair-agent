package update

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
)

// Context separates a release signature from anything else the same key
// could ever sign. The signed message is Context followed by the exact bytes
// of the release's SHA256SUMS.txt; the published names carry the version, so
// one signature binds a version to the hash of every build.
const Context = "clair-release-v1\n"

// sigTextLen is a 64-byte Ed25519 signature in padded standard base64.
const sigTextLen = 88

// Message is what a release key signs for sums.
func Message(sums []byte) []byte {
	return append([]byte(Context), sums...)
}

// Sign signs sums and returns the text of SHA256SUMS.txt.sig, without its
// trailing newline. Releases are signed in clair-web (`agent-release.mjs
// pin`); this is for tools/releasesign and the tests.
func Sign(key ed25519.PrivateKey, sums []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, Message(sums)))
}

// Verify checks SHA256SUMS.txt.sig against sums: one base64 signature,
// optionally followed by a newline, by any of keys.
func Verify(keys []ed25519.PublicKey, sums, sigText []byte) error {
	text := strings.TrimSuffix(string(sigText), "\n")
	if len(text) != sigTextLen {
		return fmt.Errorf("%w: SHA256SUMS.txt.sig is not one base64 signature", ErrBadSignature)
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: SHA256SUMS.txt.sig is not one base64 signature", ErrBadSignature)
	}
	msg := Message(sums)
	for _, k := range keys {
		if len(k) == ed25519.PublicKeySize && ed25519.Verify(k, msg, sig) {
			return nil
		}
	}
	return fmt.Errorf("%w: no release key built into this agent signed it", ErrBadSignature)
}

// ParseKey reads a public key: 32 bytes in standard base64.
func ParseKey(text string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(text))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("update: %q is not a base64 Ed25519 public key", text)
	}
	return ed25519.PublicKey(raw), nil
}
