package identity

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"strings"
	"testing"
)

// sequence is deterministic entropy: byte i is i.
func sequence(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func TestGenerateReadsTheScalarThenTheSeed(t *testing.T) {
	t.Parallel()

	seq := sequence(2 * SeedSize)
	generated, err := Generate(bytes.NewReader(seq))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	pinned, err := FromSeeds(seq[:SeedSize], seq[SeedSize:])
	if err != nil {
		t.Fatalf("FromSeeds: %v", err)
	}
	if got, want := generated.AgreementPublic(), pinned.AgreementPublic(); !bytes.Equal(got, want) {
		t.Errorf("agreement public key = %x, want %x", got, want)
	}
	if got, want := generated.AuthPublic(), pinned.AuthPublic(); !bytes.Equal(got, want) {
		t.Errorf("auth public key = %x, want %x", got, want)
	}
	if got := generated.Agreement().Bytes(); !bytes.Equal(got, seq[:SeedSize]) {
		t.Errorf("agreement scalar = %x, want the first %d entropy bytes", got, SeedSize)
	}
	if got := generated.Auth().Seed(); !bytes.Equal(got, seq[SeedSize:]) {
		t.Errorf("auth seed = %x, want the last %d entropy bytes", got, SeedSize)
	}
}

func TestGenerateFailsOnShortEntropy(t *testing.T) {
	t.Parallel()

	_, err := Generate(bytes.NewReader(sequence(2*SeedSize - 1)))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Generate with short entropy: err = %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestFromSeedsRejectsWrongLengths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		scalar, seed []byte
	}{
		{name: "short scalar", scalar: sequence(SeedSize - 1), seed: sequence(SeedSize)},
		{name: "long scalar", scalar: sequence(SeedSize + 1), seed: sequence(SeedSize)},
		{name: "short seed", scalar: sequence(SeedSize), seed: sequence(SeedSize - 1)},
		{name: "empty seed", scalar: sequence(SeedSize), seed: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := FromSeeds(tt.scalar, tt.seed)
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("FromSeeds: err = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestAuthKeySigns(t *testing.T) {
	t.Parallel()

	keys, err := FromSeeds(sequence(SeedSize), sequence(SeedSize))
	if err != nil {
		t.Fatalf("FromSeeds: %v", err)
	}
	msg := []byte("clair")
	sig := ed25519.Sign(keys.Auth(), msg)
	if !ed25519.Verify(keys.AuthPublic(), msg, sig) {
		t.Fatal("signature by Auth() does not verify under AuthPublic()")
	}
}

func TestMarshalParseRoundTrip(t *testing.T) {
	t.Parallel()

	keys, err := Generate(bytes.NewReader(sequence(2 * SeedSize)))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	data, err := Marshal(keys)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.HasSuffix(data, []byte("}\n")) {
		t.Errorf("Marshal output = %q, want a single JSON object ending in a newline", data)
	}
	for _, field := range []string{`"v":1`, `"x25519":"`, `"ed25519":"`} {
		if !bytes.Contains(data, []byte(field)) {
			t.Errorf("Marshal output = %s, want it to contain %s", data, field)
		}
	}
	if bytes.Contains(data, []byte("=")) {
		t.Errorf("Marshal output = %s, want base64url without padding", data)
	}

	parsed, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := parsed.AgreementPublic(), keys.AgreementPublic(); !bytes.Equal(got, want) {
		t.Errorf("parsed agreement public key = %x, want %x", got, want)
	}
	if got, want := parsed.AuthPublic(), keys.AuthPublic(); !bytes.Equal(got, want) {
		t.Errorf("parsed auth public key = %x, want %x", got, want)
	}
}

func TestParseRejectsMalformedFiles(t *testing.T) {
	t.Parallel()

	good, err := Marshal(mustKeys(t))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	tests := []struct {
		name string
		data string
	}{
		{name: "not json", data: "nope"},
		{name: "wrong version", data: strings.Replace(string(good), `"v":1`, `"v":2`, 1)},
		{name: "padded base64", data: strings.Replace(string(good), `"x25519":"`, `"x25519":"==`, 1)},
		{name: "short seed", data: strings.Replace(string(good), `"ed25519":"`, `"ed25519":"AAAA`, 1)},
		{name: "missing field", data: `{"v":1,"x25519":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse([]byte(tt.data))
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("Parse(%q): err = %v, want ErrMalformed", tt.data, err)
			}
		})
	}
}

func mustKeys(t *testing.T) *Keys {
	t.Helper()
	keys, err := Generate(bytes.NewReader(sequence(2 * SeedSize)))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return keys
}
