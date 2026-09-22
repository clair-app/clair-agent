package record

import (
	"net/url"
	"testing"
	"time"

	"claircode.app/clair-agent/internal/envelope"
)

func TestWake(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path  string
		event string
		held  bool
		want  envelope.Wake
	}{
		{path: PathDecide, event: "PermissionRequest", want: envelope.WakeNow},
		{path: PathDecide, event: "", want: envelope.WakeNow},
		{path: PathStatusline, event: "", want: envelope.WakeSoon},
		{path: PathPing, event: "", want: envelope.WakeSoon},
		{path: PathPresence, event: "", held: true, want: envelope.WakeNow},
		{path: PathEvent, event: "SessionStart", want: envelope.WakeSoon},
		{path: PathEvent, event: "SessionEnd", want: envelope.WakeSoon},
		{path: PathEvent, event: "UserPromptSubmit", want: envelope.WakeSoon},
		{path: PathEvent, event: "Stop", want: envelope.WakeSoon},
		{path: PathEvent, event: "Notification", want: envelope.WakeSoon},
		{path: PathEvent, event: "PreCompact", want: envelope.WakeSoon},
		{path: PathEvent, event: "PostToolUse", held: true, want: envelope.WakeSoon},
		{path: PathEvent, event: "PostToolUseFailure", held: true, want: envelope.WakeSoon},
		{path: PathEvent, event: "PostToolUse", held: false, want: envelope.WakeNo},
		{path: PathEvent, event: "PostToolUseFailure", held: false, want: envelope.WakeNo},
		{path: PathEvent, event: "PreToolUse", held: true, want: envelope.WakeNo},
		{path: PathEvent, event: "PreToolUse", held: false, want: envelope.WakeNo},
		{path: PathEvent, event: "SubagentStop", want: envelope.WakeNo},
		{path: PathEvent, event: "PermissionDenied", want: envelope.WakeNo},
		{path: PathEvent, event: "PermissionRequest", want: envelope.WakeNo},
		{path: PathEvent, event: "SomethingNew", want: envelope.WakeNo},
		{path: PathEvent, event: "", want: envelope.WakeNo},
	}
	for _, tt := range tests {
		if got := Wake(tt.path, tt.event, tt.held); got != tt.want {
			t.Errorf("Wake(%q, %q, held=%v) = %q, want %q", tt.path, tt.event, tt.held, got, tt.want)
		}
	}
}

func TestTTL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		wake    envelope.Wake
		timeout time.Duration
		want    int
	}{
		{wake: envelope.WakeNow, timeout: 600 * time.Second, want: 600},
		{wake: envelope.WakeNow, timeout: 0, want: 1},
		{wake: envelope.WakeSoon, timeout: 600 * time.Second, want: 86400},
		{wake: envelope.WakeNo, timeout: 600 * time.Second, want: 3600},
	}
	for _, tt := range tests {
		if got := TTL(tt.wake, tt.timeout); got != tt.want {
			t.Errorf("TTL(%q, %v) = %d, want %d", tt.wake, tt.timeout, got, tt.want)
		}
	}
}

func TestDecideTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		query string
		want  time.Duration
	}{
		{query: "", want: 86400 * time.Second},
		{query: "timeout=", want: 86400 * time.Second},
		{query: "timeout=abc", want: 86400 * time.Second},
		{query: "timeout=1.5", want: 86400 * time.Second},
		{query: "timeout=0", want: 5 * time.Second},
		{query: "timeout=-9", want: 5 * time.Second},
		{query: "timeout=1", want: 5 * time.Second},
		{query: "timeout=5", want: 5 * time.Second},
		{query: "timeout=600", want: 600 * time.Second},
		{query: "timeout=86400", want: 86400 * time.Second},
		{query: "timeout=99999999", want: 86400 * time.Second},
		{query: "timeout=300&timeout=600", want: 300 * time.Second},
		{query: "other=1", want: 86400 * time.Second},
	}
	for _, tt := range tests {
		q, err := url.ParseQuery(tt.query)
		if err != nil {
			t.Fatalf("ParseQuery(%q): %v", tt.query, err)
		}
		if got := DecideTimeout(q); got != tt.want {
			t.Errorf("DecideTimeout(%q) = %v, want %v", tt.query, got, tt.want)
		}
	}
}
