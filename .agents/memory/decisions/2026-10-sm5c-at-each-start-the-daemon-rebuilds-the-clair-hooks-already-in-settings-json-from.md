---
id: "2026-10.sm5c"
slug: at-each-start-the-daemon-rebuilds-the-clair-hooks-already-in-settings-json-from
title: "At each start the daemon rebuilds the Clair hooks already in settings.json from its own template"
date: 2026-10-05
topics: [hooks, claudecfg, daemon]
---

# ADR 2026-10.sm5c — At each start the daemon rebuilds the Clair hooks already in settings.json from its own template

Status: Accepted (2026-10-05) · implements, for the hooks block, ADR 2026-09.qk6v's "a release that changes the
hooks block must migrate it itself when it starts" · amends ADR 2026-10.gw8w (how an existing install gets the
entrypoint header) and ADR 2026-09.bckr (an edit that leaves a missing file empty writes nothing). RELAY.md r12
§6.5. · amended by ADR 2026-10.ukr9 (a refresh adds the agent's own events, `PostToolBatch`, to a block with Clair's
decide hook: the template's first new event, answering "Not covered" below)

**What was observed.** ADR 2026-10.gw8w gave the decide hook `X-Clair-Entrypoint: $CLAUDE_CODE_ENTRYPOINT` and its
one `allowedEnvVars`. The agent's template adds them (`httpHook`); the phone's template does not. A host's hooks
block is written only by `clair pair` (`InstallAtPairing`) and by a phone `snippet` (`InstallSnippet`). The phone
sends a snippet only when its own snippet hash changes (`HostSettings.snippetHash` against
`PairRecord.deliveredSnippetHash`), and a header the agent adds never changes that hash. So every paired host would
have kept the old block until a re-pair or a hook setting changed on the phone. Until then the agent would release a
`claude -p` subagent's decide on `agent_id` alone, which denies the tool. The updater only makes things worse: a new
template reaches a host as a binary that runs from the daemon's next start (ADR 2026-09.qk6v), and that ADR already
said a release changing the hooks block "must migrate them itself when it starts".

Claude Code does not need a restart to see such a rewrite. On 2026-10-05 (the maintainer's workstation, 2.1.289) an interactive session in
a pty had a project `settings.json` rewritten under it by temp file and rename, as `state.WriteFile` does. The next
hook carried the changed header, a newly listed `allowedEnvVars` filled `$CLAUDE_CODE_ENTRYPOINT` (empty before, `cli`
after), and a newly added `Stop` hook fired. The debug log showed `Detected change to …/settings.json` and `Settings
changed from projectSettings, updating app state` about 1 s after the rename, and listed `~/.claude/settings.json`
among the watched files. A rewrite of the user's own file mid-session was not exercised, to leave it untouched.

**What changed.**

- **When.** At start, after its pairs are loaded and only if at least one is, the daemon calls
  `SnippetInstaller.RefreshHooks` once, before the listener serves. It is one locked load-modify-save of one file
  (ADR 2026-09.y34x). A hook that arrives meanwhile waits in the accept queue. A snippet the stream delivers at the
  same moment is serialised by the same lock, and the two converge in either order because the rebuild is
  idempotent.
- **What.** Each Clair group (`isClair`: the `/clair/v1/` marker) under an event the template hooks is rebuilt where
  it stands by `rebuildGroup`, against the daemon's own `SnippetConfig`. That is the rebuild a phone snippet gets
  (ADR 2026-09.ut2g): the endpoint, timeout, `statusMessage` and matcher stay as the phone or the user left them. The
  origin, the bearer, `X-Clair-Host`, the decide hook's entrypoint header and `allowedEnvVars` come from the template.
- **What it leaves alone.** Nothing is added, removed or moved. The user's groups keep their places, and Clair groups
  under an event the template does not hook stay as they are. The statusLine is not read. With no Clair group,
  nothing is written, and a missing `settings.json` is not created: `edit` now treats a missing file left empty as
  unchanged, which also stops `clair unpair` creating `{}`. Unchanged JSON writes nothing and backs nothing up (ADR
  2026-09.bckr), so every start after the first one on a new template is a no-op.
- **What stops it.** A group the rebuild refuses — a Clair hook on another port, a user's hook inside a Clair group, a
  marker command that is not a Clair `hook-event` (the LAN installer's `curl`) — refuses the whole refresh. The file
  stays as it was, and the reason is logged at warn and shown by `clair status`.
- **One relaxation over a phone snippet.** The `SessionStart` command names whichever binary wrote it. The CLI that
  ran `clair pair` may be another spelling of the daemon's path, or a `go run` build. So a refresh accepts any
  `<binary> hook-event /clair/v1/hook/event` whose binary is a Clair one by name or is the same file (the statusLine
  ownership rule of ADR 2026-09.y34x), and writes the daemon's own. A phone snippet must still name exactly this
  binary (ADR 2026-09.3gre).
- **Who is asked.** Nobody (Jeff, 2026-10-05). The daemon already rewrites these groups unprompted when a phone snippet
  arrives, and pairing is the consent to them. The outcome goes to the daemon log, and to `ctl.Status.Hooks`
  (`rewritten`, `current`, `none` or `failed`, with the backup's path or the error). `clair status` prints that as a
  `hooks:` line. The field is new and nil from an older daemon (ADR 2026-09.66m4). The snippet log line no longer says
  to restart Claude Code.

The alternative a reader reaches for first is to let the phone resend: a template revision in `hello-ack`, or in a
new control, and the phone sends its snippet when the revision differs from the one it delivered against.
`hello-ack` goes out only at pairing, so this would need `reset` or a new record. It would mean a change in three
repositories, a revision stored per pair on the phone, and a phone that is online when the daemon starts. And the
snippet it sent would go through the same rebuild, against inputs that `settings.json` already holds: everything the
phone controls is there. Storing the phone's last raw snippet and reinstalling it at start was the second thought.
No existing host has one stored, which is the case at hand. And with an older daemon running beside a newer CLI, a
later snippet the old daemon installs never updates the stored copy, so the next start would reinstall a stale one
and undo a hook setting the user changed on the phone. Running the block through `InstallSnippet` was the third: its
merge moves Clair's groups to the end of each event and rewraps the statusLine, which would wrap again, at every
start, a statusLine the user replaced after pairing.

**What it costs.**

- **A background write.** The daemon writes `settings.json` without asking, once per template change. A hand edit to
  a Clair hook beyond its timeout, status and matcher (an `async`, an extra header) is undone, as a phone snippet
  would undo it.
- **The block follows the running daemon, both ways.** A downgrade to an older release that has this refresh
  rewrites the block to that release's template, which drops headers the older daemon does not read.
- **Two rules a template change must keep.** First, a newer block must be harmless to an older daemon, because
  `clair pair` from a newer CLI on disk writes it beside an older running one: ADR 2026-09.66m4, extended to the
  hooks block. Second, a daemon must still read an older block, because a refresh can be refused, and the Claude Code
  sessions may read another `settings.json` than the daemon does (`CLAUDE_CONFIG_DIR` is captured when the service is
  installed). ADR 2026-10.gw8w's fallback, `agent_id` or `bubble` alone without the header, stays for that.
- **Not covered: an event the phone hooked before this agent knew it.** That event was dropped (ADR 2026-09.bckr), so
  it is not in `settings.json`, and a refresh cannot bring it back. The drop is only a warning in the daemon's log
  (`snippet trimmed`); the phone marks the snippet delivered, and `clair status` does not show it. The event arrives
  with the phone's next snippet: a hook setting change, or a re-pair. Until something closes this, a new event ships
  in the agent first and in the phone a release later. That narrows the window without closing it, because a daemon
  can run its old image for weeks after the update is on disk (ADR 2026-09.66m4). When the template first gains an
  event, choose between a template revision in `reset` and a stored raw snippet tied to the block it produced.
- **Not exercised:** Claude Code reloading the user's own `settings.json`, rather than a project's, in an open
  session, and how far back that reload goes. `clair pair` and `clair unpair` still tell the user to restart Claude
  Code, which is harmless.
- **What keeps it true:** `TestRefreshHooksBringsAnOlderBlockToTheTemplate`, which takes `testdata/settings-installed-r11.json`
  to `testdata/settings-refreshed.json` byte for byte and then writes nothing; `TestRefreshHooksTakesThisBinaryUnderAnyName`;
  `TestRefreshHooksLeavesAHostWithoutClairHooksAlone`; `TestRefreshHooksRefusesWhatItCannotRebuild`;
  `internal/daemon`'s `TestHookRefreshOutcomes` and `TestStartRefreshesTheHooksOfAPairedHost`; and `cmd/clair`'s
  `TestPrintHooksStatus`. Checked once with real processes on 2026-10-05: relaysim, phonesim and scratch config
  directories. A block with the decide hook's header and `allowedEnvVars` removed got exactly those two back, with one
  backup, and `clair status` said so. The next start wrote nothing.
