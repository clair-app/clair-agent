//go:build !windows

package claudecfg

import (
	"context"
	"os/exec"
	"strings"
)

// shellCommand runs command through sh, as the LAN shim did.
func shellCommand(ctx context.Context, command string) *exec.Cmd {
	return exec.CommandContext(ctx, "sh", "-c", command) //nolint:gosec // running the user's own statusLine command is the point
}

// safeChars is what shlex.quote leaves bare.
const safeChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-"

// quoteForShell is shlex.quote: bare when safe, single-quoted otherwise.
func quoteForShell(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		if !strings.ContainsRune(safeChars, r) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}
