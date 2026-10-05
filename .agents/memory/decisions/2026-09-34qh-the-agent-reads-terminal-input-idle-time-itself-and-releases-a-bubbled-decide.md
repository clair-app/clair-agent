---
id: "2026-09.34qh"
slug: the-agent-reads-terminal-input-idle-time-itself-and-releases-a-bubbled-decide
title: "The agent reads terminal input idle time itself and releases a bubbled decide to the terminal while someone is at it"
date: 2026-09-21
topics: [presence, hooks, tunnel]
---

# ADR 2026-09.34qh — The agent reads terminal input idle time itself and releases a bubbled decide to the terminal while someone is at it

Status: Accepted (2026-09-21); its `bubble` marker is widened by ADR 2026-10.gw8w (a subagent's
`agent_id`, in an interactive session) · RELAY.md r3 §4.3 is the design; NOTES.md in the `clair`
repository (2026-09-21) holds the observation.

**What was observed.** On Claude Code 2.1.278 a background subagent's `PermissionRequest` runs the
hooks *first* and reaches the main session's dialog only if none returned a decision: while the
agent holds the hook open the terminal shows nothing, for the whole `timeout` — 300 s on the LAN
install where it was seen, 24 h with the relay's default. The main agent's own prompts race dialog
against hook and are unaffected. The phone repository's fix proposal put presence sampling into a
`command` shim (`xprintidle`, `loginctl`, `ioreg`) because the LAN installer had nothing else on the
host; this agent is a resident process, and that shim would have been a second hook type, three
platform-specific helpers, and no Windows story.

**What changed.** `internal/presence` samples terminal input idle the way `w(1)` prints its IDLE
column: the newest access time over this user's pty slaves (`/dev/pts/*`, `/dev/ttys*` on macOS —
the kernel bumps a pty's atime when the process on it *reads* input, 8 s granularity on Linux), and
`GetLastInputInfo` on Windows, where a ConPTY has no node to stat. Verified on this host with a
pty pair (atime moves on the read, not on the write) and on a running session (seven minutes of
redraws and terminal queries moved mtime only). The tunnel stamps `X-Clair-Idle-Ms` into every
request record's `headers`, and in `Hold` reads a second top-level field, `permission_mode`: a
`bubble` decide while the idle is under the threshold is answered "no decision" at once, tunnelled as
`soon` and followed by `cancel {reason: "terminal"}`; one held while nobody was there is released the
same way when someone returns, by a watcher that samples every 10 s only while a decide is held and
also reports flips as `/hook/presence` requests (`now`). The threshold is the phone's — 120 s by
default, `hello.presence` / `policy` change it, 0 switches it off — and the phone applies the same
predicate to the same stamped input. The alternative a reader reaches for first, "present ⇒ short
hold for every decide, no `permission_mode`", breaks the case the product exists for: a main-agent
prompt fired as the user walked away, where holding costs nothing. The other alternative, letting
only the phone decide, costs a relay round trip (seconds from doze) and leaves the terminal blind
for the whole timeout when the phone is unreachable. An OS-level idle (X11, D-Bus, IOKit) was not
taken: it needs dependencies or permissions, has no Wayland answer, and measures the machine, not
the terminal — a user at the desk but in a browser is exactly who wants the watch prompt.

**What it costs.** The blind-tunnel rule now reads two fields instead of one (`rules/go.md`), and the
release rule is coupled to `bubble`, an undocumented value; if it is renamed the agent silently falls
back to holding, which is today's behaviour. Windows measures the session, not the terminal. A user
present at decide time who leaves within seconds has the prompt in the terminal and not on the watch
— the `Notification permission_prompt` card is the phone's mitigation. Traps: the tunnel must never
release a non-bubbled hold on presence, and the presence record must precede the release's cancel
(the shuffle found the other order). What keeps this true: `internal/presence` (pty enumeration with
a temporary directory; a real pty on Linux), `internal/tunnel/presence_test.go` (release at once,
release on return, flips only while held, rule off, policy), the daemon's
`TestBubbledDecideGoesToTheTerminalWhileSomeoneIsThere`, and `phonesim`'s `leftToTerminal`.
