//go:build windows

package claudecfg

import "testing"

func TestStatusLineCommandQuoting(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		`C:\Users\w\clair.exe`:       "C:/Users/w/clair.exe statusline",
		`C:\Program Files\clair.exe`: `"C:/Program Files/clair.exe" statusline`,
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

// Windows quotes a path with a space with double quotes: the phone's
// snippet for C:\Program Files must still be valid JSON and accepted.
func TestPhoneSnippetForAWindowsPathWithASpace(t *testing.T) {
	t.Parallel()

	checkPhoneSnippetFor(t, `C:\Program Files\clair\clair.exe`)
}
