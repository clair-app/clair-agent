package update

import "testing"

func TestParseRelease(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want Release
		ok   bool
	}{
		{in: "v0.1.0", want: Release{0, 1, 0}, ok: true},
		{in: "v12.345.6789", want: Release{12, 345, 6789}, ok: true},
		{in: "0.1.0"},
		{in: "v0.1"},
		{in: "v0.1.0.1"},
		{in: "v0.1.0-rc.1"},
		{in: "v0.1.0-3-gabc1234"},
		{in: "v0.1.0-dirty"},
		{in: "v01.1.0"},
		{in: "v+1.1.0"},
		{in: "v1..0"},
		{in: "v1234567890.0.0"},
		{in: "dev"},
		{in: ""},
		{in: "V0.1.0"},
		{in: " v0.1.0"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			got, ok := ParseRelease(tt.in)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("ParseRelease(%q) = %v, %v; want %v, %v", tt.in, got, ok, tt.want, tt.ok)
			}
			if ok && got.String() != tt.in {
				t.Errorf("String() = %q, want %q", got.String(), tt.in)
			}
		})
	}
}

func TestCompare(t *testing.T) {
	t.Parallel()

	tests := []struct {
		a, b string
		want int
	}{
		{"v0.1.0", "v0.1.0", 0},
		{"v0.1.0", "v0.1.1", -1},
		{"v0.2.0", "v0.1.9", 1},
		{"v1.0.0", "v0.99.99", 1},
		{"v0.10.0", "v0.9.0", 1}, // numeric, not lexical
	}
	for _, tt := range tests {
		a, _ := ParseRelease(tt.a)
		b, _ := ParseRelease(tt.b)
		if got := a.Compare(b); got != tt.want {
			t.Errorf("%s.Compare(%s) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
		if got := b.Compare(a); got != -tt.want {
			t.Errorf("%s.Compare(%s) = %d, want %d", tt.b, tt.a, got, -tt.want)
		}
	}
}

func TestVersionOf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		out, want string
		ok        bool
	}{
		{out: "clair v0.2.0 (abc1234, 2026-09-24T12:00:00Z)\n", want: "v0.2.0", ok: true},
		{out: "clair v0.2.0 (abc1234, 2026-09-24T12:00:00Z)\nbuilt with a release test key\n", want: "v0.2.0", ok: true},
		{out: "clair dev (none, unknown)\n", want: "dev", ok: true},
		{out: "something else v0.2.0\n"},
		{out: ""},
	}
	for _, tt := range tests {
		got, ok := VersionOf(tt.out)
		if got != tt.want || ok != tt.ok {
			t.Errorf("VersionOf(%q) = %q, %v; want %q, %v", tt.out, got, ok, tt.want, tt.ok)
		}
	}
}
