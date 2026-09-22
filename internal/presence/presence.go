// Package presence answers one question for the daemon: is someone at a
// terminal on this host right now? (RELAY.md §4.3.) A permission prompt from
// a background subagent draws in the terminal only once the agent lets go of
// the hook, so the agent releases such a prompt at once while someone is
// there and holds it for the watch while nobody is. The signal is terminal
// input idle time — the reading `w(1)` prints in its IDLE column — because
// it measures attention to the terminal, not to the machine: it works over
// SSH, inside tmux, on Wayland and on a headless box, needs no permission,
// no helper and no dependency, and is sampled only when a decide arrives or
// is held. Windows has no pseudo-terminal node to stat, so there the reading
// is the session's last input instead (`GetLastInputInfo`).
package presence

import "time"

// DefaultThreshold is the idle time under which someone counts as present
// until the phone says otherwise (`hello` / `policy`, RELAY.md §4.3; draft).
const DefaultThreshold = 120 * time.Second

// Sample is one reading.
type Sample struct {
	// Idle is the time since a terminal of this user's last read input.
	Idle time.Duration
	// Known is false when the host offers no signal: no terminal of this
	// user's, a Windows session without a desktop, or no sampler at all.
	Known bool
	// Source names where the reading came from: "pty" or "console".
	Source string
}

// Present reports whether s says someone is at a terminal: a known reading
// under threshold. A zero threshold means the notion is switched off.
func (s Sample) Present(threshold time.Duration) bool {
	return threshold > 0 && s.Known && s.Idle < threshold
}

// Sampler takes readings. The tunnel samples once per hook it forwards and
// every few seconds while a decide is held; tests inject a fake.
type Sampler interface {
	Sample() Sample
}

// Func adapts a function to Sampler.
type Func func() Sample

// Sample calls f.
func (f Func) Sample() Sample { return f() }

// Local is this host's sampler.
func Local() Sampler { return host() }
