package claudecfg

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"claircode.app/clair-agent/internal/record"
)

// hookEventTimeout is the LAN installer's `curl -m 2`: a missing agent costs
// a session start at most this much.
const hookEventTimeout = 2 * time.Second

// HookEventOptions configure one run of `clair hook-event <path>`.
type HookEventOptions struct {
	Stdin io.Reader
	// Path is the loopback path to post to; anything outside /clair/v1/ is refused.
	Path string
	// AgentURL is the daemon's loopback origin; empty means nobody to tell.
	AgentURL string
	Token    string
	Host     string
	HTTP     *http.Client
}

// RunHookEvent is the `command` hook Claude Code runs for SessionStart, which
// it refuses to send as an http hook (2.1.278): it forwards stdin to the
// daemon and never fails the hook — the LAN installer's `curl … || true`.
func RunHookEvent(ctx context.Context, o HookEventOptions) int {
	if o.AgentURL == "" || !strings.HasPrefix(o.Path, record.Marker) {
		return 0
	}
	body, err := io.ReadAll(io.LimitReader(o.Stdin, maxStatuslineInput))
	if err != nil || !bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) {
		return 0
	}
	ctx, cancel := context.WithTimeout(ctx, hookEventTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(o.AgentURL, "/")+o.Path, bytes.NewReader(body))
	if err != nil {
		return 0
	}
	req.Header.Set("Authorization", "Bearer "+o.Token)
	req.Header.Set("Content-Type", "application/json")
	if o.Host != "" {
		req.Header.Set(record.HostHeader, o.Host)
	}
	client := o.HTTP
	if client == nil {
		client = &http.Client{Timeout: hookEventTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return 0
}
