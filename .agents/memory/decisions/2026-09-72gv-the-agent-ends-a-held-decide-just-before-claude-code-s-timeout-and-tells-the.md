---
id: "2026-09.72gv"
slug: the-agent-ends-a-held-decide-just-before-claude-code-s-timeout-and-tells-the
title: "The agent ends a held decide just before Claude Code's timeout and tells the phone it expired"
date: 2026-09-27
topics: [tunnel, hooks]
---

# ADR 2026-09.72gv — The agent ends a held decide just before Claude Code's timeout and tells the phone it expired

Status: Accepted (2026-09-27) · GitLab clair-agent#1; RELAY.md §4.1 names the new reason.

**What was observed.** On 2026-09-27 a two-question AskUserQuestion was held under
`decide?timeout=300` with `"timeout": 300`. Nobody finished answering it, and after 303 s the watch
showed "Handled in terminal" while the terminal dialog was still waiting. The hook's timeout runs
twice: Claude Code counts `"timeout"` from before the request reaches the agent, and the agent
counts `?timeout=` from when `Hold` starts. Claude Code's timer normally fires first. It closes the
socket, the agent takes the `ctx.Done()` branch and sends `cancel {reason: "client"}`, and the phone
reads that as answered in the terminal. When the agent's timer won, it sent no cancel at all, and
the phone kept the action until the envelope's TTL.

**What changed.** `Tunnel.Hold` ends a held decide `holdMargin` (2 s, draft) before its timeout,
answers `204` (what Claude Code would have done anyway), and sends `cancel {reason: "timeout"}`. The
phone closes the action as `Expired(HOOK_TIMEOUT)`. A socket closed before that is still `client`. The
alternative is to keep one timer and call a close "at or after about `timeout`" a timeout. It still
races Claude Code, it has to guess a window, and it misreports a real terminal answer in that window.
Ending first lets the agent know which case it is in instead of inferring it.

**What it costs.** Every held decide gets 2 s less of the phone's time. An older phone reads
`timeout` as `client`, which is the behaviour before this change, so no version gate is needed. It
does not cover a hand-edited hook whose `"timeout"` is shorter than its `?timeout=`: Claude Code
still closes first, and the cancel still says `client`. The installer and `rebuildHook` keep the two
equal. Trap: `record.TTL` for the `now` envelope stays on the full timeout, not the shortened one.
What keeps this true: `TestHoldExpiresAtTheDeadline` (returns at timeout − margin, last record is
`cancel (timeout)`) and `TestIdleIsStampedOnEveryRequestAndCancelsCarryTheirReason`.
