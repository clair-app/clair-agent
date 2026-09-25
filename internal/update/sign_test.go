package update

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// signingVector is testdata/release-signing-vector.json. Releases are signed
// in Node by clair-web's scripts/agent-release.mjs, which checks itself
// against a copy of the same file (scripts/testdata/release-signing-vector.json):
// Ed25519 is deterministic, so both must produce these bytes.
type signingVector struct {
	Context   string `json:"context"`
	Seed      string `json:"seed"`
	PublicKey string `json:"publicKey"`
	Version   string `json:"version"`
	Sums      string `json:"sums"`
	Signature string `json:"signature"`
}

func loadVector(t *testing.T) (signingVector, ed25519.PrivateKey) {
	t.Helper()
	data, err := os.ReadFile("testdata/release-signing-vector.json")
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v signingVector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("decode vector: %v", err)
	}
	seed, decodeErr := base64.StdEncoding.DecodeString(v.Seed)
	if decodeErr != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("vector seed: %v (%d bytes)", decodeErr, len(seed))
	}
	return v, ed25519.NewKeyFromSeed(seed)
}

func TestSigningVector(t *testing.T) {
	t.Parallel()

	v, key := loadVector(t)
	if v.Context != Context {
		t.Fatalf("vector context %q, want %q", v.Context, Context)
	}
	pub, err := ParseKey(v.PublicKey)
	if err != nil {
		t.Fatalf("ParseKey: %v", err)
	}
	if !bytes.Equal(pub, publicOf(key)) {
		t.Fatalf("public key %x, want the seed's %x", pub, publicOf(key))
	}
	sig := Sign(key, []byte(v.Sums))
	if sig != v.Signature {
		t.Fatalf("Sign = %s, want %s", sig, v.Signature)
	}
	if err := Verify([]ed25519.PublicKey{pub}, []byte(v.Sums), []byte(v.Signature+"\n")); err != nil {
		t.Fatalf("Verify(vector): %v", err)
	}
	sums, parseErr := ParseSums([]byte(v.Sums), v.Version)
	if parseErr != nil || len(sums) != 6 {
		t.Fatalf("ParseSums(vector) = %d entries, %v; want 6", len(sums), parseErr)
	}
}

func TestVerifyRefuses(t *testing.T) {
	t.Parallel()

	v, key := loadVector(t)
	pub := publicOf(key)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	withoutContext := base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(v.Sums)))
	tampered := []byte(v.Sums)
	tampered[0] ^= 1

	tests := []struct {
		name string
		keys []ed25519.PublicKey
		sums []byte
		sig  string
	}{
		{name: "a changed checksum", keys: []ed25519.PublicKey{pub}, sums: tampered, sig: v.Signature},
		{name: "another key", keys: []ed25519.PublicKey{publicOf(other)}, sums: []byte(v.Sums), sig: v.Signature},
		{name: "no keys at all", keys: nil, sums: []byte(v.Sums), sig: v.Signature},
		{name: "a signature without the context", keys: []ed25519.PublicKey{pub}, sums: []byte(v.Sums), sig: withoutContext},
		{name: "unpadded", keys: []ed25519.PublicKey{pub}, sums: []byte(v.Sums), sig: v.Signature[:86]},
		{name: "two newlines", keys: []ed25519.PublicKey{pub}, sums: []byte(v.Sums), sig: v.Signature + "\n\n"},
		{name: "CRLF", keys: []ed25519.PublicKey{pub}, sums: []byte(v.Sums), sig: v.Signature + "\r\n"},
		{name: "empty", keys: []ed25519.PublicKey{pub}, sums: []byte(v.Sums), sig: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := Verify(tt.keys, tt.sums, []byte(tt.sig)); !errors.Is(err, ErrBadSignature) {
				t.Fatalf("Verify = %v, want ErrBadSignature", err)
			}
		})
	}
	// The second of two keys is tried too: a release the backup signs verifies.
	if err := Verify([]ed25519.PublicKey{publicOf(other), pub}, []byte(v.Sums), []byte(v.Signature)); err != nil {
		t.Errorf("Verify with the signer second: %v", err)
	}
}

func TestParseKey(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{"", "AAAA", base64.StdEncoding.EncodeToString(make([]byte, 31)), base64.RawStdEncoding.EncodeToString(make([]byte, 32))} {
		if _, err := ParseKey(bad); err == nil {
			t.Errorf("ParseKey(%q) accepted", bad)
		}
	}
}

func TestReleaseKeys(t *testing.T) {
	t.Parallel()

	// ReleaseKeys panics on a malformed built-in key; this is the test that
	// says so before a release does.
	keys := ReleaseKeys()
	if len(keys) < 2 {
		t.Fatalf("%d release keys are built in, want a primary and a backup", len(keys))
	}
	for i, k := range keys {
		if len(k) != ed25519.PublicKeySize {
			t.Errorf("key %d is %d bytes", i, len(k))
		}
	}
	seen := make(map[string]bool)
	for _, k := range keys {
		if seen[string(k)] {
			t.Errorf("key %x is listed twice", k)
		}
		seen[string(k)] = true
	}
}

// publicOf is the public half of an Ed25519 private key (seed ‖ public).
func publicOf(k ed25519.PrivateKey) ed25519.PublicKey {
	return ed25519.PublicKey(k[ed25519.SeedSize:])
}
