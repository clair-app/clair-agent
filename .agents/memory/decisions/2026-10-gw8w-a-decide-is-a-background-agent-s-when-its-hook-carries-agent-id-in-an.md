---
id: "2026-10.gw8w"
slug: a-decide-is-a-background-agent-s-when-its-hook-carries-agent-id-in-an
title: "A decide is a background agent's when its hook carries agent_id in an interactive session, as the decide hook's entrypoint header tells"
date: 2026-10-05
topics: [presence, hooks, tunnel]
---

# ADR 2026-10.gw8w — A decide is a background agent's when its hook carries agent_id in an interactive session, as the decide hook's entrypoint header tells

Status: Accepted (2026-10-05) · GitLab clair-agent#2; widens ADR 2026-09.34qh's `bubble` marker, and
gives the decide hook the one `allowedEnvVars` ADR 2026-09.ut2g had ruled out. RELAY.md r12 §4.3. Amended by
ADR 2026-10.sm5c: an existing install gets the header at the daemon's next start.

**What was observed.** On 2026-10-05 (the maintainer's Linux workstation, Claude Code 2.1.289, an auto-mode session) a background
`mesh-lab-reviewer` agent asked to run a `Bash` command. Its hook said `permission_mode: "auto"`, so
the agent held it as a main-agent prompt for the full 24 h hook timeout. Half an hour later `clair status`
showed it still held with terminal input idle 15 s, the terminal showed nothing, and the main session
sat waiting on the reviewer. Reading 2.1.289's bundled JS showed why `bubble` (ADR 2026-09.34qh, seen on
a fork in a plan-mode session on 2.1.278) is no longer the marker:

- An agent reports `bubble` only when its definition declares it (the fork, the coordinator worker),
  and only under a parent in `default` mode: `auto`, `acceptEdits` and `bypassPermissions` override a
  declared mode, and `plan` and `dontAsk` replace `bubble` with their own. Custom agents declare none
  and report the parent's mode.
- The hooks-first path does not depend on the mode at all. Every async agent in an interactive session,
  where a dialog can be requested, gets `awaitAutomatedChecksBeforeDialog`: the `PermissionRequest`
  hooks run, and the main session draws the dialog only if none decided. A foreground subagent races
  its hook against a dialog already on screen, like the main agent.
- `agent_id` is on the hooks of every subagent context (foreground, background, fork, in-process
  teammate, workflow agent) and never on the main thread's.
- In `claude -p` a hook that returns without a decision is a denial, for every request. Agents run in
  the background there too unless the model says otherwise, and they run their hooks, then deny. No field
  of any hook body says whether the session is interactive. Claude Code does write
  `CLAUDE_CODE_ENTRYPOINT` into its own environment at start: `cli` in an interactive terminal,
  `sdk-cli` under `-p`, `sdk-ts` / `sdk-py` under the Agent SDK, and a launcher's preset (such as
  `claude-vscode`) kept as it is. An http hook's header may interpolate it when `allowedEnvVars` lists it:
  a `claude -p` run with that hook (2026-10-05) sent `X-Clair-Entrypoint: sdk-cli` on both a subagent's
  decide (`agent_id` present, `permission_mode: "default"`) and the main agent's (no `agent_id`), and an
  unlisted `$HOME` in the same hook arrived empty.

**What changed.** A decide is bubbled (`record.Hook.Bubbled`) when its body carries an `agent_id` or
says `bubble`, unless its session is not an interactive terminal one. The agent's decide hook now
carries `X-Clair-Entrypoint: $CLAUDE_CODE_ENTRYPOINT` with `allowedEnvVars: ["CLAUDE_CODE_ENTRYPOINT"]`,
rendered by `httpHook` for `RenderHooks` and `rebuildHook` alike, so a phone snippet gets it too and can
set neither. The loopback reads the header on a decide and never forwards it: it is not hook body, and the
phone learns of a release from the `soon` wake and the `cancel {reason: "terminal"}` as before. Only `cli`
lets a subagent's decide through. Another value, `sdk-cli` above all, keeps it held for the phone. An
empty header means the hooks block predates this change (or a managed `httpHookAllowedEnvVars` blanks
the variable) and falls back to `agent_id` or `bubble`, so the auto-mode case is fixed by the daemon
update alone. Of `agent_id` only presence is read, as raw JSON, so its type can never fail a body.

The fix a reader reaches for first, `agent_id` alone, was the issue's proposal. It would release a
`claude -p` run's subagent prompt whenever someone is at a terminal, which denies the tool at once,
where until now it was held for the phone. The other first thought, releasing for any entrypoint but
`sdk-*`, would deny under a launcher whose preset hides a non-interactive run; allowing only `cli` costs
at worst today's hold, never a denial, which is ADR 2026-09.34qh's trap read the safe way round.
Telling the session apart through `SessionStart` was not taken: its `command` hook does see
`CLAUDE_CODE_SESSION_ATTENDED`, but the decide would then have to be matched to a session by its
`session_id`, which the tunnel never reads, and kept across daemon restarts.

**What it costs.** The tunnel reads a third body field (its presence only) and a header of its own,
and the decide hook gains its first `allowedEnvVars`, for one fixed, non-secret variable in a header
that stays on the host. `agent_id`, `CLAUDE_CODE_ENTRYPOINT` and its values are undocumented; if a
release stops setting either, the agent holds, which is the behaviour this ADR replaces, not a denial.
The `-p` guard reaches an existing install when the daemon next starts and rebuilds its hooks block from
this template (ADR 2026-10.sm5c). Where that rebuild is refused, or Claude Code reads another
`settings.json`, the install still releases a `-p` subagent's decide while someone is at a terminal. An interactive session launched with another preset
(an IDE that sets the variable) keeps today's hold. A foreground subagent's raced prompt is released
too, which costs only the watch's copy while someone is at the terminal. Internal forks (compaction,
memory extraction and the like) also carry an `agent_id`; whether any of them ever reaches
`PermissionRequest` is not established. What keeps this true: `TestHookBubbled` (the rule),
`TestHookFieldsForTheReleaseRule` (`agent_id` of any type, the header read and not forwarded),
`TestSubagentDecideIsReleasedWhateverItsMode` and
`TestNonInteractiveSubagentDecideIsHeldWhileSomeoneIsThere` in `internal/tunnel`,
`TestSubagentDecideInAutoModeGoesToTheTerminal` end to end, and `testdata/hooks-default.json` with
`TestValidateSnippetRebuildsEachHook` for the hook's shape.
