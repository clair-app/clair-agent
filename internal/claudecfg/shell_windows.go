//go:build windows

package claudecfg

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
)

// shellCommand runs command through Git Bash when it is on PATH — Claude
// Code on Windows leans on it too — and PowerShell otherwise.
func shellCommand(ctx context.Context, command string) *exec.Cmd {
	if bash, err := exec.LookPath("bash"); err == nil {
		return exec.CommandContext(ctx, bash, "-c", command)
	}
	return exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", command)
}

// quoteForShell uses forward slashes, which every Windows shell accepts and
// bash does not eat, and quotes only when there is whitespace.
func quoteForShell(s string) string {
	s = filepath.ToSlash(s)
	if strings.ContainsAny(s, " \t") {
		return `"` + s + `"`
	}
	return s
}
