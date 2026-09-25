package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"claircode.app/clair-agent/internal/update"
)

func TestKeygenSignVerify(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "k.pem")
	var out, errOut bytes.Buffer
	if code := run([]string{"keygen", "-out", keyPath}, &out, &errOut); code != 0 {
		t.Fatalf("keygen = %d: %s", code, errOut.String())
	}
	pub, err := update.ParseKey(out.String())
	if err != nil {
		t.Fatalf("keygen printed %q: %v", out.String(), err)
	}
	if info, statErr := os.Stat(keyPath); statErr != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %v, %v; want 0600", info.Mode(), statErr)
	}
	if code := run([]string{"keygen", "-out", keyPath}, &out, &errOut); code != 1 {
		t.Errorf("keygen over an existing key = %d, want 1", code)
	}

	out.Reset()
	if code := run([]string{"pubkey", "-key", keyPath}, &out, &errOut); code != 0 || strings.TrimSpace(out.String()) != base64.StdEncoding.EncodeToString(pub) {
		t.Fatalf("pubkey = %d %q, want %s", code, out.String(), base64.StdEncoding.EncodeToString(pub))
	}

	sums := []byte("0000000000000000000000000000000000000000000000000000000000000000  clair-v0.0.1-linux-amd64\n")
	if writeErr := os.WriteFile(filepath.Join(dir, "SHA256SUMS.txt"), sums, 0o644); writeErr != nil {
		t.Fatal(writeErr)
	}
	if code := run([]string{"sign", "-key", keyPath, dir}, &out, &errOut); code != 0 {
		t.Fatalf("sign = %d: %s", code, errOut.String())
	}
	sig, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS.txt.sig"))
	if err != nil {
		t.Fatal(err)
	}
	if err := update.Verify([]ed25519.PublicKey{pub}, sums, sig); err != nil {
		t.Fatalf("Verify(the tool's signature): %v", err)
	}
}

func TestBuiltin(t *testing.T) {
	t.Parallel()

	var out, errOut bytes.Buffer
	code := run([]string{"builtin"}, &out, &errOut)
	keys := update.ReleaseKeys()
	if want := map[bool]int{true: 0, false: 1}[len(keys) >= minBuiltinKeys]; code != want {
		t.Fatalf("builtin = %d with %d keys, want %d: %s", code, len(keys), want, errOut.String())
	}
	if lines := strings.Count(out.String(), "\n"); lines != len(keys) {
		t.Errorf("builtin printed %d keys, want %d", lines, len(keys))
	}
}

func TestUsage(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{nil, {"keygen"}, {"sign", "-key", "k.pem"}, {"frobnicate"}} {
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "usage") {
			t.Errorf("run(%q) = %d %q, want 2 and the usage", args, code, errOut.String())
		}
	}
}
