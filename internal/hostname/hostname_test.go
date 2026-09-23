package hostname

import (
	"strings"
	"testing"
)

func TestSanitise(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"walter-laptop":             "walter-laptop",
		"walter-laptop.local":       "walter-laptop",
		"  Walter_Laptop.home.arpa": "Walter_Laptop",
		"héllo wörld":               "hllowrld",
		"":                          Unknown,
		"...":                       Unknown,
		".hidden":                   Unknown,
	}
	for in, want := range tests {
		if got := Sanitise(in); got != want {
			t.Errorf("Sanitise(%q) = %q, want %q", in, got, want)
		}
	}
	if Local() == "" {
		t.Error("Local() is empty")
	}
}

func TestValid(t *testing.T) {
	t.Parallel()

	tests := map[string]bool{
		"walter-laptop":         true,
		"Walter_Laptop.2":       true,
		strings.Repeat("a", 64): true,
		strings.Repeat("a", 65): false,
		"":                      false,
		"walter laptop":         false,
		"$AWS_SECRET":           false,
		"a/b":                   false,
		"héllo":                 false,
	}
	for in, want := range tests {
		if got := Valid(in); got != want {
			t.Errorf("Valid(%q) = %v, want %v", in, got, want)
		}
	}
}
