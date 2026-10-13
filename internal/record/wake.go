package record

import (
	"net/url"
	"strconv"
	"time"

	"claircode.app/clair-agent/internal/envelope"
)

// Decide timeouts: the phone's HookServer clamps `?timeout=` to [5, 86400]
// seconds and defaults to 86400 when it is missing or unparsable.
const (
	MinDecideTimeout     = 5 * time.Second
	MaxDecideTimeout     = 86400 * time.Second
	DefaultDecideTimeout = MaxDecideTimeout
)

// Envelope lifetimes by hint (RELAY.md §7.5, *draft*): a `now` envelope lives
// as long as the decide it carries; the other two are fixed.
const (
	TTLSoon = 24 * time.Hour
	TTLNo   = time.Hour
)

// Claude Code hook event names the wake table branches on. Anything else,
// including events this agent has never heard of, is churn.
const (
	eventSessionStart       = "SessionStart"
	eventSessionEnd         = "SessionEnd"
	eventUserPromptSubmit   = "UserPromptSubmit"
	eventStop               = "Stop"
	eventNotification       = "Notification"
	eventPreCompact         = "PreCompact"
	eventPostToolUse        = "PostToolUse"
	eventPostToolUseFailure = "PostToolUseFailure"
)

// EventPostToolBatch is the hook Claude Code fires after every tool batch
// whose turn goes on. It is the only one that says a prompt was refused at the
// terminal with feedback, and the agent hooks it itself (ADR 2026-10.ukr9).
const EventPostToolBatch = "PostToolBatch"

// EventStopFailure is the hook Claude Code fires in place of Stop when a turn
// ends on an API error — a usage limit among them. The agent hooks it itself,
// and it is a turn boundary like Stop (ADR 2026-10.6cm3).
const EventStopFailure = "StopFailure"

// Wake is the hint for a request record (RELAY.md §7.5, ADR 029's tiers one
// hop earlier). The path decides first: a decide is `now`, and so is a
// presence change — it is only sent while a decide is held, and it is the
// moment a prompt delivered quietly must start to buzz (§4.3); the
// statusline, the agent's usage report and the installer's ping are `soon`. Then the event name: turn
// boundaries, a turn ended by an API error included, are `soon`; tool churn
// is `no`, except that the PostToolUse or PostToolBatch which closes an action
// answered in the terminal is `soon` while a decide is held.
func Wake(path, hookEventName string, decideHeld bool) envelope.Wake {
	switch path {
	case PathDecide, PathPresence:
		return envelope.WakeNow
	case PathStatusline, PathUsage, PathPing:
		return envelope.WakeSoon
	}
	switch hookEventName {
	case eventSessionStart, eventSessionEnd, eventUserPromptSubmit, eventStop, EventStopFailure, eventNotification, eventPreCompact:
		return envelope.WakeSoon
	case eventPostToolUse, eventPostToolUseFailure, EventPostToolBatch:
		if decideHeld {
			return envelope.WakeSoon
		}
		return envelope.WakeNo
	default:
		return envelope.WakeNo
	}
}

// Forwarded reports whether a fire-and-forget hook goes to the phone at all.
// A PostToolBatch does only while a decide is held: it repeats every call's
// tool_response, the relay limits uploads by bytes, and the phone needs it
// only to close a prompt it still has open (ADR 2026-10.ukr9). The hook is
// answered 204 either way.
func Forwarded(hookEventName string, decideHeld bool) bool {
	return hookEventName != EventPostToolBatch || decideHeld
}

// TTL is the envelope's ttlSec for a hint; decideTimeout is the held request's
// deadline and only matters for `now`.
func TTL(w envelope.Wake, decideTimeout time.Duration) int {
	var d time.Duration
	switch w {
	case envelope.WakeNow:
		d = max(decideTimeout, time.Second)
	case envelope.WakeSoon:
		d = TTLSoon
	default:
		d = TTLNo
	}
	return int(d / time.Second)
}

// DecideTimeout reads `?timeout=<seconds>` the way the phone does: missing or
// unparsable → the default, otherwise clamped to [MinDecideTimeout, MaxDecideTimeout].
func DecideTimeout(q url.Values) time.Duration {
	raw := q.Get(TimeoutQuery)
	if raw == "" {
		return DefaultDecideTimeout
	}
	secs, err := strconv.Atoi(raw)
	if err != nil {
		return DefaultDecideTimeout
	}
	return min(max(time.Duration(secs)*time.Second, MinDecideTimeout), MaxDecideTimeout)
}
