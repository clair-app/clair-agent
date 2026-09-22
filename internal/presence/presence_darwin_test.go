package presence

import "testing"

func TestTtys(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]bool{"ttys000": true, "ttys012": true, "ttys": false, "tty": false, "ptmx": false, "ttysa": false} {
		if got := ttys(name); got != want {
			t.Errorf("ttys(%q) = %v, want %v", name, got, want)
		}
	}
}
