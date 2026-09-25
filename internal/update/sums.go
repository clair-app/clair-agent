package update

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// AssetName is the name claircode.app publishes a build under, with the
// version in it: clair-v0.2.0-linux-amd64, clair-v0.2.0-windows-arm64.exe
// (clair-web's scripts/agent-release.mjs, publishedName).
func AssetName(version, goos, goarch string) string {
	name := "clair-" + version + "-" + goos + "-" + goarch
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

// ParseSums reads a release's SHA256SUMS.txt: one "<64 hex>  <name>\n" line
// per build, every name carrying version. It is strict — no blank line, no
// CR, no binary-mode "*", no duplicate — because the bytes are what the
// signature covers and one spelling leaves nothing to argue about.
func ParseSums(data []byte, version string) (map[string][sizeSHA256]byte, error) {
	text := string(data)
	if text == "" || !strings.HasSuffix(text, "\n") {
		return nil, errors.New("update: SHA256SUMS.txt must be lines ending in a newline")
	}
	sums := make(map[string][sizeSHA256]byte)
	marker := "-" + version + "-"
	for line := range strings.SplitSeq(strings.TrimSuffix(text, "\n"), "\n") {
		digest, name, ok := strings.Cut(line, "  ")
		if !ok || len(digest) != 2*sizeSHA256 || name == "" || strings.ContainsAny(name, " \t\r*/\\") {
			return nil, fmt.Errorf("update: SHA256SUMS.txt: malformed line %q", line)
		}
		if !strings.HasPrefix(name, "clair"+marker) {
			return nil, fmt.Errorf("update: SHA256SUMS.txt: %s is not a %s build", name, version)
		}
		var sum [sizeSHA256]byte
		if _, err := hex.Decode(sum[:], []byte(digest)); err != nil || strings.ToLower(digest) != digest {
			return nil, fmt.Errorf("update: SHA256SUMS.txt: %s: not a lowercase hex digest", name)
		}
		if _, dup := sums[name]; dup {
			return nil, fmt.Errorf("update: SHA256SUMS.txt: %s listed twice", name)
		}
		sums[name] = sum
	}
	return sums, nil
}
