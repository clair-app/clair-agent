//go:build !windows

package claudecfg

import (
	"bytes"
	"strings"
	"testing"
)

func TestStatusLineCommandQuoting(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"/opt/clair/clair":         "/opt/clair/clair statusline",
		"/opt/my tools/clair":      "'/opt/my tools/clair' statusline",
		"/opt/it's/clair":          `'/opt/it'"'"'s/clair' statusline`,
		"/home/w/.local/bin/clair": "/home/w/.local/bin/clair statusline",
	}
	for exe, want := range tests {
		if got := StatusLineCommand(exe); got != want {
			t.Errorf("StatusLineCommand(%q) = %q, want %q", exe, got, want)
		}
		if !IsOurStatusLine(StatusLineCommand(exe)) {
			t.Errorf("IsOurStatusLine does not recognise %q", StatusLineCommand(exe))
		}
	}
}

func TestRunShellPassesStdinAndExitCode(t *testing.T) {
	t.Parallel()

	var out, errOut bytes.Buffer
	code, err := runShell(t.Context(), `printf "got %s" "$(cat)"; exit 4`, []byte("input"), &out, &errOut)
	if err != nil || code != 4 || out.String() != "got input" {
		t.Errorf("runShell = %d, %v, %q", code, err, out.String())
	}
	if code, err := runShell(t.Context(), "true", nil, &out, &errOut); err != nil || code != 0 {
		t.Errorf("runShell(true) = %d, %v", code, err)
	}
	if _, err := runShell(t.Context(), strings.Repeat("x", 10), nil, &out, &errOut); err != nil {
		t.Errorf("a failing command is an exit code, not an error: %v", err)
	}
}
