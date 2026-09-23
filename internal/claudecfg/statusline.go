package claudecfg

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"claircode.app/clair-agent/internal/record"
)

const (
	// The shim forwards Claude Code's statusline JSON at most every
	// statuslineInterval (the LAN shim's 30 s) and gives the POST
	// statuslinePostTimeout; the input is capped at maxStatuslineInput.
	statuslineInterval    = 30 * time.Second
	statuslinePostTimeout = 2 * time.Second
	maxStatuslineInput    = 4 << 20
	// EnvStatuslineNested is set for the user's original statusline command.
	// A `clair statusline` that finds it set is running inside another one,
	// so it runs no original of its own: whatever the saved original turned
	// out to be, the chain ends there (AG-6).
	EnvStatuslineNested = "CLAIR_STATUSLINE_NESTED"
)

// StatuslineOptions configure one run of `clair statusline`.
type StatuslineOptions struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// SettingsPath locates the saved original statusLine beside it.
	SettingsPath string
	// Exe is this binary's path: an original that runs its statusline is
	// never run.
	Exe string
	// Nested says EnvStatuslineNested was set: this run is some statusline's
	// original, and runs no original and posts nothing.
	Nested bool
	// AgentURL is the daemon's loopback origin; empty skips the POST.
	AgentURL string
	Token    string
	Host     string
	// TempDir holds the throttle stamp; empty means os.TempDir().
	TempDir string
	Now     func() time.Time
	// Interval overrides statuslineInterval; 0 keeps it.
	Interval time.Duration
	HTTP     *http.Client
	// RunOriginal runs the user's own statusline command with the same
	// stdin; nil means the platform shell.
	RunOriginal func(ctx context.Context, command string, stdin []byte, stdout, stderr io.Writer) (int, error)
}

// RunStatusline is the statusLine command Claude Code runs: it reads the
// statusline JSON once, posts it to the daemon when the throttle allows —
// concurrently, so the user's statusline never waits for the network — and
// runs the user's original command with the same input, passing its output
// and exit status through. It prints nothing of its own.
func RunStatusline(ctx context.Context, o StatuslineOptions) int {
	if o.Nested {
		return 0
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	interval := o.Interval
	if interval <= 0 {
		interval = statuslineInterval
	}
	tempDir := o.TempDir
	if tempDir == "" {
		tempDir = os.TempDir()
	}
	if o.Stdout == nil {
		o.Stdout = io.Discard
	}
	if o.Stderr == nil {
		o.Stderr = io.Discard
	}
	input, err := io.ReadAll(io.LimitReader(o.Stdin, maxStatuslineInput))
	if err != nil {
		fmt.Fprintf(o.Stderr, "clair statusline: read stdin: %v\n", err)
		return 1
	}

	var posted chan struct{}
	if o.AgentURL != "" && due(tempDir, now(), interval) {
		posted = make(chan struct{})
		go func() {
			defer close(posted)
			post(ctx, o, input)
		}()
	}

	code := 0
	if command := commandOf(Installer{SettingsPath: o.SettingsPath, ClairExe: o.Exe}.loadOriginal()); command != "" {
		run := o.RunOriginal
		if run == nil {
			run = runShell
		}
		var runErr error
		code, runErr = run(ctx, command, input, o.Stdout, o.Stderr)
		if runErr != nil {
			fmt.Fprintf(o.Stderr, "clair statusline: original statusline: %v\n", runErr)
			if code == 0 {
				code = 1
			}
		}
	}
	if posted != nil {
		<-posted
	}
	return code
}

// due reads and refreshes the throttle stamp; it reports whether enough time
// has passed since the last POST. A missing or unreadable stamp is "due".
func due(tempDir string, now time.Time, interval time.Duration) bool {
	uid := strconv.Itoa(os.Getuid())
	if uid == "-1" {
		uid = "user"
	}
	stamp := filepath.Join(tempDir, "clair-statusline-"+uid+".stamp")
	if data, err := os.ReadFile(stamp); err == nil {
		if last, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); err == nil && now.Unix()-last < int64(interval/time.Second) {
			return false
		}
	}
	_ = os.WriteFile(stamp, []byte(strconv.FormatInt(now.Unix(), 10)+"\n"), 0o600)
	return true
}

// post forwards the statusline JSON to the daemon; failures are silent, as
// the LAN shim's were.
func post(ctx context.Context, o StatuslineOptions, input []byte) {
	if !bytes.HasPrefix(bytes.TrimSpace(input), []byte("{")) {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, statuslinePostTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(o.AgentURL, "/")+record.PathStatusline, bytes.NewReader(input))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+o.Token)
	req.Header.Set("Content-Type", "application/json")
	if o.Host != "" {
		req.Header.Set(record.HostHeader, o.Host)
	}
	client := o.HTTP
	if client == nil {
		client = &http.Client{Timeout: statuslinePostTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

// runShell runs a command through the platform shell with stdin bytes and
// returns its exit status.
func runShell(ctx context.Context, command string, stdin []byte, stdout, stderr io.Writer) (int, error) {
	cmd := shellCommand(ctx, command)
	cmd.Env = append(os.Environ(), EnvStatuslineNested+"=1")
	cmd.Stdin = bytes.NewReader(stdin)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if err == nil {
		return 0, nil
	}
	if exit, ok := errors.AsType[*exec.ExitError](err); ok {
		return exit.ExitCode(), nil
	}
	return 1, err
}

// StatusLineCommand is the statusLine command for this binary: its absolute
// path, quoted for the platform's shell, followed by `statusline`.
func StatusLineCommand(exe string) string {
	return quoteForShell(exe) + " statusline"
}
