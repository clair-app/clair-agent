---
id: "2026-09.bckr"
slug: a-phone-snippet-is-filled-in-as-json
title: "A phone snippet is filled in as JSON, matched on the agent's port, trimmed to known events, and replaced by the built-in block at pairing"
date: 2026-09-23
topics: [hooks, security, pairing]
---

# ADR 2026-09.bckr — A phone snippet is filled in as JSON, matched on the agent's port, trimmed to known events, and replaced by the built-in block at pairing

Status: Accepted (2026-09-23) · amends ADR 2026-09.3gre and 2026-09.ut2g · cross-repo fix D2 (2026-09-23)

**What was observed.** `claudecfg.Substitute` pasted shell-quoted values into the snippet's
raw JSON text. On Windows `quoteForShell` wraps a path with a space in double quotes, so
`C:\Program Files\clair\clair.exe` became `""C:/Program Files/clair/clair.exe" hook-event …"`
inside the SessionStart command: invalid JSON. On Unix a `'` or `"` in the path did the same
(`'/opt/it'"'"'s/clair'`). `ValidateSnippet` refused the snippet, and `clair pair` had no
fallback for a refused snippet — ADR 2026-09.3gre promised one, the code had it only for a
missing snippet — so it printed "Paired",
wrote **no hooks** and exited 0. `--listen localhost:7317` (or `[::1]:7317`) failed the same
way for another reason: the phone's template hard-codes `http://127.0.0.1:__PORT__`, and the
validator wanted the agent's own origin byte for byte. Separately, a snippet could name any
event key, and any key that was not `PermissionRequest` was pinned to `/hook/event` and
installed; and every install rewrote `settings.json` and left a new `.bak-*` even when nothing
changed, which matters now that the phone re-sends an unconfirmed snippet (fix D5).

**What changed.**
- Substitution escapes every value for the JSON string it lands in (`jsonEscape`, after
  `quoteForShell` for `__CLAIR_EXE__`). Parsing first and substituting in the parsed strings
  was the alternative; escaping keeps `Substitute`'s shape and gives the same result for the
  phone's template, whose placeholders all sit inside strings. A placeholder outside a string
  that needs escaping now makes invalid JSON and is refused, which is right.
- A hook URL may start with the agent's own origin or with the phone's canonical
  `http://127.0.0.1:<port>` for the agent's own port. What is written is still rebuilt from the
  agent's template with its real listen address (ADR 2026-09.ut2g stands); another port, a
  longer one, userinfo, or another loopback spelling the agent does not listen on is refused.
- An event the agent's template does not hook (anything but `PermissionRequest`, the eight
  event hooks and `SessionStart`) is dropped and named in a warning — `clair pair` prints it,
  the daemon logs it — and the rest is installed. Rejecting the whole snippet was the other
  choice; a phone one Claude Code release ahead would then lose every setting over one event.
  A snippet with no known event left, `{"hooks":{}}` included, is refused: installing it would
  remove every Clair hook.
- At pairing (`SnippetInstaller.InstallAtPairing`) a missing, `null` or refused snippet
  installs the built-in block, and a refused one prints a warning naming the offence. If even
  that cannot be written, `clair pair` keeps the saved pair, reloads the daemon, and exits 1
  with `ErrHooksNotWritten`, the cause, and the way back (`clair pair --replace`, or
  `clair unpair`). A snippet refused later, from a `snippet` record, still leaves what is
  installed (RELAY.md §6.5).
- `Installer.edit` compares the edited settings with what it read (`ojson.Equal`) and, when
  they are the same JSON, writes nothing and backs nothing up (`Report.Unchanged`); the saved
  statusLine original is rewritten only when its bytes change.

**What it costs.** A new Claude Code event is a change here before a phone can hook it, as a
new hook option already was (ADR 2026-09.ut2g). The no-op compares JSON, not bytes, so a file
the user reformatted by hand is not normalised by a repeat install. There is no command that
writes only the hooks, so the recovery from an unwritable `settings.json` is a re-pair.
What keeps this true: `TestSubstituteEscapesEveryValueForJSON` (both platforms' quoting on
any GOOS), `TestPhoneSnippetForAnAwkwardBinaryPath` and, on Windows,
`TestPhoneSnippetForAWindowsPathWithASpace` (the phone's real template),
`TestValidateSnippetAcceptsThePhonesLoopbackForTheAgentsPort`,
`TestValidateSnippetDropsEventsItDoesNotHook`, `TestValidateSnippetRejects`,
`TestInstallAtPairing`, `TestInstallSnippetTwiceWritesOnce`, `internal/pairing`'s
`TestPairReportsTheHooksOutcome`, `internal/daemon`'s `TestSnippetOutcomesAreLogged`, and
`cmd/clair`'s `TestPairInstallsThePhonesHooks`.
