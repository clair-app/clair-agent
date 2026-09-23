// Package hostname names the machine the way the phone's installer does:
// the first label of the hostname, reduced to the characters a hook header
// and a shell may carry.
package hostname

import (
	"os"
	"strings"
)

// Unknown is the name for a machine that has none.
const Unknown = "unknown"

// maxLen bounds a name: Linux's HOST_NAME_MAX, and more than a DNS label.
const maxLen = 64

// Sanitise keeps the label before the first dot and, of that, only
// `[A-Za-z0-9._-]` — the installer's `hostname -s | tr -cd 'A-Za-z0-9._-'`.
func Sanitise(h string) string {
	label, _, _ := strings.Cut(strings.TrimSpace(h), ".")
	var b strings.Builder
	for _, r := range label {
		if allowed(r) {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return Unknown
	}
	return b.String()
}

// Valid reports whether h is a name Sanitise could have produced: one to
// 64 characters of `[A-Za-z0-9._-]`.
func Valid(h string) bool {
	if h == "" || len(h) > maxLen {
		return false
	}
	for _, r := range h {
		if !allowed(r) {
			return false
		}
	}
	return true
}

func allowed(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-'
}

// Local is this machine's sanitised name.
func Local() string {
	h, err := os.Hostname()
	if err != nil {
		return Unknown
	}
	return Sanitise(h)
}
