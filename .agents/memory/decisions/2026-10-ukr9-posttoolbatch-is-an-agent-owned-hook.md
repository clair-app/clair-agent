---
id: "2026-10.ukr9"
slug: posttoolbatch-is-an-agent-owned-hook
title: "PostToolBatch is an agent-owned hook, forwarded only while a decide is held"
date: 2026-10-10
topics: [hooks, claudecfg, tunnel, daemon]
---

# ADR 2026-10.ukr9 — PostToolBatch is an agent-owned hook, forwarded only while a decide is held

Status: Accepted (2026-10-10) · amends ADR 2026-10.sm5c (a refresh adds the agent's own events), ADR 2026-09.bckr
and ADR 2026-09.ut2g (a snippet with the decide hook gets them whether or not it lists them) · pairs with the phone's
ADR 2026-10.jnrt · RELAY.md r13

**What was observed.** On 2026-10-10 the phone showed three plan reviews for the `knit-spool` session when only
the newest was live. `ExitPlanMode` was called at 00:16:43, 00:19:47 and 00:26:29 PDT. The first two were rejected
at the terminal *with feedback*, and the model kept editing the plan in the same turn. `clair status` showed
`held decides: 3`, and the `claude` process held three connections to the loopback. The daemon had logged no
`decide cancelled by the client`. It looked like a hold that should have ended. It was a prompt that had been
answered, with nothing to say so.

The cause is in Claude Code 2.1.296 (the clair repository's `docs/NOTES.md` 2026-10-10):

- **The hook is never aborted when the terminal answers.** It runs under the turn's abort signal, and the dialog
  only ignores its answer. A plain reject aborts the turn, and with it the request: that's the `client` cancel. An
  approval runs the tool, and its `PostToolUse` closes the prompt on the phone. A reject with feedback does neither.
  The turn goes on, the request stays open for the hook's 86400 s, and the phone keeps the prompt until a `Stop` or
  a typed prompt.
- **`PostToolBatch` is the one hook that says so.** It fires after every tool batch whose turn goes on.
  `tool_calls` carries each call's `tool_name`, `tool_input`, `tool_use_id` and `tool_response`, a refused call
  included. Checked in a pty: after a plan rejected with feedback, it is the only hook before the next prompt.
- **The template has nothing to install it with.** Neither the agent's template nor the phone's had it.

A batch repeats the `tool_response` of every call in it, and `PostToolUse` already sends each of those. The
relay's `/envelopes` limit is a byte budget per client address, 16 MiB an hour by default. The maintainer's workstation has logged
1,864 `429 rate_limited` since 2026-10-05, but those are not that budget: the relay's log names the per-key
request rate (a bucket of 60 refilling 1 a second), and every one cleared on its first 1 s retry. They come from
the uploader posting each small batch as soon as it is queued, not from the bytes (paced since ADR
2026-10.rmej).

**What changed.**

- **The agent owns the hook.** `agentEvents` in `internal/claudecfg/hooks.go` lists `PostToolBatch` (an `http`
  hook to `/hook/event`, 2 s), and the phone's template does not. Every block with Clair's decide hook gets it,
  after the phone's events:
  - `RenderHooks` renders it last;
  - `ValidateSnippet` appends it to a snippet that has the decide hook and no group for it, so `clair pair` and a
    phone snippet both write it;
  - the start's refresh adds it to an installed block that has Clair's decide hook and lacks it. It goes after the
    user's own groups for the event, or under a new key at the end of `hooks`.

  This answers what ADR 2026-10.sm5c left open for "when the template first gains an event". The phone's snippet
  hash doesn't change, nothing is resent, and neither repository has to ship first. A snippet that does list the
  event shapes it like any other: timeout, status, matcher.
- **It is forwarded only while a decide is held.** `/hook/event` answers `204` as always. `Tunnel.Enqueue` queues
  a `PostToolBatch` for a pair only while that pair holds a decide (`record.Forwarded`), as `soon`
  (`record.Wake`), and drops it otherwise. The phone needs a batch only to close a prompt it still has open. Once
  it does, it answers the decide `204` and the hold ends, so a stale hold stops the batches by itself.
- **`clair pair` checks the running daemon first.** A newer CLI beside an older running daemon must not write a
  hook that daemon would forward ungated (sm5c's "a newer block must be harmless to an older daemon"). So `cmdPair`
  asks for `ctl.Status`, which now lists `agentEvents`, the events a daemon adds and gates. If a daemon answers
  without them, or answers an error that isn't "unreachable", it pairs with `OmitAgentEvents` and says so on
  stderr. With no daemon listening, the next one to start is this binary. The newer daemon's refresh adds them
  when it starts.
- **The refresh reports what it added.** `RefreshReport.Groups` counts groups rebuilt or added, so `clair status`
  shows the same count on every start. `Added` names the events, and the start's log line carries them.
- **`phonesim` renders its snippet with `OmitAgentEvents`,** like the phone's template.

The alternative a reader reaches for first is to forward every batch, like `PostToolUse`. The tunnel would stay
blind to one more event, but the tool churn's uploads would grow, against a per-key request rate the maintainer's workstation already
exceeds, for an event the phone ignores unless a prompt is open. The second was to add the event to the phone's template. Then the
snippet hash changes and every pair is resent, an older daemon trims the event and the phone marks it delivered,
and r12 item 5's rule comes back: the agent ships a release first, and it still doesn't close the gap. The third
was to have the agent end a stale hold itself, on the session's next hook. That needs `session_id`, and the agent
reads no such field (RELAY.md §4).

**What it costs.**

- **Removing it by hand doesn't stick.** While Clair's decide hook is installed, a `PostToolBatch` group removed by
  hand comes back at the next start. That is the one exception to the 0.4.0 changelog's "Clair hooks you removed
  aren't added back". Removing every Clair hook still sticks: nothing is added to a block without the decide hook.
- **The gate is per pair, not per session.** While any decide is held, every session's batches go out, subagents'
  included, and a stale hold can last until the phone sees a batch that closes it.
- **A read-only release isn't closed by a batch.** A prompt the phone released in read-only mode leaves no hold
  here, so no batch closes it on the phone: same as before.
- **Over-size batches fall back.** A batch over the 3,145,592-byte record cap is dropped at enqueue, and one over
  the loopback's 4 MiB gets a `413` before the gate. Either way the prompt closes as before.
- **A downgrade can forward every batch.** A downgraded daemon can't gate a group that's already installed. Its
  refresh skips the unknown event and leaves the group, so it forwards every batch as `no` until it is upgraded or
  the group is removed.
- **A hook on every batch.** Claude Code awaits each `PostToolBatch` before the next model call, which costs one
  loopback round trip, answered at once.

What keeps it true:

- `TestRenderHooksMatchesTheGolden`, whose `hooks-default.json` now ends with the group, and the phone's
  `RelayTemplateTest`, which holds its template to that golden less the agent's own parts.
- `TestValidateSnippetAddsTheAgentsEvents`, `TestRefreshHooksBringsAnOlderBlockToTheTemplate` (the r11 block gains
  the group; the next start writes nothing) and `TestRefreshHooksAddsTheAgentsEventsAfterTheUsers`.
- `TestEveryAgentEventIsGated`: an agent event the gate doesn't cover fails it.
- `TestPostToolBatchIsQueuedOnlyWhileADecideIsHeld`.
- `cmd/clair`'s `TestAgentEventsMissing` and `TestPairInstallsThePhonesHooks`.
- `internal/daemon`'s `TestStartRefreshesTheHooksOfAPairedHost` (`agentEvents` in the status).
