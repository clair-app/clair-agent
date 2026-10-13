package usage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// ErrNoClaude is a host where no `claude` could be found.
var ErrNoClaude = errors.New("usage: claude not found")

// args run Claude Code headless, with nothing of the user's but the login: no
// user settings (so no hooks of Clair's or anyone's, no plugins), no MCP
// servers, and no transcript. The empty working directory has no project
// settings either.
var args = []string{
	"-p",
	"--input-format", "stream-json",
	"--output-format", "stream-json",
	"--verbose",
	"--setting-sources", "project",
	"--settings", `{"disableAllHooks":true}`,
	"--strict-mcp-config",
	"--no-session-persistence",
}

// FindClaude is `claude` on PATH, else where Claude Code's installers put it
// under home. The daemon runs as a login service whose PATH may lack the
// user's own directories.
func FindClaude(home string) (string, error) {
	if path, err := exec.LookPath("claude" + exeSuffix); err == nil {
		return path, nil
	}
	if home != "" {
		for _, dir := range []string{filepath.Join(home, ".local", "bin"), filepath.Join(home, ".claude", "local")} {
			if path, err := exec.LookPath(filepath.Join(dir, "claude"+exeSuffix)); err == nil {
				return path, nil
			}
		}
	}
	return "", ErrNoClaude
}

// Claude is the Runner that runs the `claude` FindClaude finds, found again on
// every run so an install after the daemon started is picked up.
func Claude() Runner {
	return func(ctx context.Context, stdin []byte) ([]byte, error) {
		home, _ := os.UserHomeDir()
		path, err := FindClaude(home)
		if err != nil {
			return nil, err
		}
		dir, err := os.MkdirTemp("", "clair-usage-")
		if err != nil {
			return nil, fmt.Errorf("usage: work dir: %w", err)
		}
		defer func() { _ = os.RemoveAll(dir) }()
		cmd := exec.CommandContext(ctx, path, args...) //nolint:gosec // the user's own Claude Code, with fixed arguments
		cmd.Dir = dir
		cmd.Stdin = bytes.NewReader(stdin)
		out, err := cmd.Output()
		if err != nil {
			return out, fmt.Errorf("claude: %w", err)
		}
		return out, nil
	}
}
