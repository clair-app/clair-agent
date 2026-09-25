package update

import (
	"encoding/hex"
	"strings"
	"testing"
)

const (
	hashA = "561ceed66acb332152cf7a017728dc71678fcb96047893d6509ff98fdb53c763"
	hashB = "e5ae4dccd40243d72d33a821ecf76d50ec504ecd8d34549c4f80c6796afea1e3"
)

func TestAssetName(t *testing.T) {
	t.Parallel()

	if got := AssetName("v0.2.0", "linux", "arm64"); got != "clair-v0.2.0-linux-arm64" {
		t.Errorf("linux: %q", got)
	}
	if got := AssetName("v0.2.0", "windows", "amd64"); got != "clair-v0.2.0-windows-amd64.exe" {
		t.Errorf("windows: %q", got)
	}
}

func TestParseSums(t *testing.T) {
	t.Parallel()

	good := hashA + "  clair-v0.2.0-linux-amd64\n" + hashB + "  clair-v0.2.0-windows-amd64.exe\n"
	sums, err := ParseSums([]byte(good), "v0.2.0")
	if err != nil {
		t.Fatalf("ParseSums(good): %v", err)
	}
	if len(sums) != 2 {
		t.Fatalf("got %d entries, want 2", len(sums))
	}
	if got := sums["clair-v0.2.0-linux-amd64"]; hex.EncodeToString(got[:]) != hashA {
		t.Errorf("linux-amd64 = %x, want %s", got, hashA)
	}

	refused := map[string]string{
		"empty":                     "",
		"no final newline":          hashA + "  clair-v0.2.0-linux-amd64",
		"blank line":                hashA + "  clair-v0.2.0-linux-amd64\n\n",
		"CRLF":                      hashA + "  clair-v0.2.0-linux-amd64\r\n",
		"binary-mode star":          hashA + " *clair-v0.2.0-linux-amd64\n",
		"one space":                 hashA + " clair-v0.2.0-linux-amd64\n",
		"another version":           hashA + "  clair-v0.1.0-linux-amd64\n",
		"unversioned build name":    hashA + "  clair-linux-amd64\n",
		"a version that only looks": hashA + "  clair-v0.2.0.1-linux-amd64\n",
		"a path":                    hashA + "  ../clair-v0.2.0-linux-amd64\n",
		"uppercase hex":             strings.ToUpper(hashA) + "  clair-v0.2.0-linux-amd64\n",
		"short digest":              hashA[:62] + "  clair-v0.2.0-linux-amd64\n",
		"not hex":                   strings.Repeat("g", 64) + "  clair-v0.2.0-linux-amd64\n",
		"duplicate":                 hashA + "  clair-v0.2.0-linux-amd64\n" + hashB + "  clair-v0.2.0-linux-amd64\n",
	}
	for name, text := range refused {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got, err := ParseSums([]byte(text), "v0.2.0"); err == nil {
				t.Fatalf("ParseSums(%q) = %v, want an error", text, got)
			}
		})
	}
}
