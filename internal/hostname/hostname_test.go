package hostname

import "testing"

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
