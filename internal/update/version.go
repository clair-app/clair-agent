package update

import (
	"cmp"
	"fmt"
	"strconv"
	"strings"
)

// Release is a strict release version, vMAJOR.MINOR.PATCH. Pre-releases,
// `git describe` suffixes and "-dirty" are not releases: they never update
// themselves and are never updated to.
type Release struct {
	Major, Minor, Patch int
}

// ParseRelease reads a strict vX.Y.Z; ok is false for anything else.
func ParseRelease(s string) (r Release, ok bool) {
	rest, found := strings.CutPrefix(s, "v")
	if !found {
		return Release{}, false
	}
	parts := strings.Split(rest, ".")
	if len(parts) != 3 {
		return Release{}, false
	}
	var nums [3]int
	for i, p := range parts {
		// Digits only, no sign and no leading zero, so one version has one
		// spelling; nine digits keep the number far from overflow.
		if p == "" || len(p) > 9 || (len(p) > 1 && p[0] == '0') || strings.Trim(p, "0123456789") != "" {
			return Release{}, false
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return Release{}, false
		}
		nums[i] = n
	}
	return Release{Major: nums[0], Minor: nums[1], Patch: nums[2]}, true
}

// IsRelease reports whether s is a strict release version.
func IsRelease(s string) bool {
	_, ok := ParseRelease(s)
	return ok
}

// Compare returns -1, 0 or 1 as r is older than, the same as, or newer than o.
func (r Release) Compare(o Release) int {
	switch {
	case r.Major != o.Major:
		return cmp.Compare(r.Major, o.Major)
	case r.Minor != o.Minor:
		return cmp.Compare(r.Minor, o.Minor)
	default:
		return cmp.Compare(r.Patch, o.Patch)
	}
}

func (r Release) String() string {
	return fmt.Sprintf("v%d.%d.%d", r.Major, r.Minor, r.Patch)
}

// VersionOf reads the version from the first line `clair version` prints:
// "clair v0.2.0 (abc1234, 2026-09-24T12:00:00Z)".
func VersionOf(out string) (string, bool) {
	line, _, _ := strings.Cut(out, "\n")
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "clair" {
		return "", false
	}
	return fields[1], true
}
