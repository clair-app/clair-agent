---
id: "2026-09.y34x"
slug: settings-json-is-rewritten-under-a-file-lock
title: "settings.json is rewritten under a file lock, keeping its mode, and backed up by copy"
date: 2026-09-23
topics: [hooks, claudecfg]
---

# ADR 2026-09.y34x — settings.json is rewritten under a file lock, keeping its mode, and backed up by copy

Status: Accepted (2026-09-23)

**What was observed.** The production security review (2026-09-23, AG-6 and AG-7) found
that every rewrite of `settings.json` wrote a fixed `settings.json.tmp` at 0644 with
`os.WriteFile` and renamed it over the file. A user's `chmod 600` was silently undone, even
though the file holds the hook bearer and often `env` credentials. A symlinked
`settings.json` (a dotfiles checkout) became a regular file, and a file or link planted at
the fixed temp name was written through. The backup was a *rename* of the live file, so for a
moment there was no `settings.json` at all. Each phone snippet installed on its own goroutine
with no lock, so concurrent installs, or one racing `clair pair` or `clair unpair`, read that
gap as an empty file. The review's harness lost `permissions.deny` in 48, 115 and 132 of 2,000
rounds with 2, 3 and 4 concurrent installs, and with 4 it left the file missing or invalid in
10 rounds. Separately, `statusLine` ownership was a name regex (`clair(\.exe)?\s+statusline`),
but the Makefile's release artifacts are named `clair-<os>-<arch>`. A second install therefore
saved the agent's own command as the user's "original", and `clair statusline` ran itself:
about 70 processes every 0.2 s, still growing after the top one was killed.

**What changed.**
- Every `Install` and `Uninstall` is one load-modify-save under an advisory lock on
  `settings.json.lock` beside the file: `flock` on Unix, `LockFileEx` on Windows through
  `golang.org/x/sys/windows`. Both lock per open file, so the daemon's goroutines exclude each
  other just as two processes do.
- The daemon collapses snippets that arrive during an install into the newest one, which is
  installed next.
- The file is replaced through `state.WriteFile` (random temp name, `O_EXCL`, the old file's
  mode, fsync, rename), written through a symlink at `settings.json`. A new file is 0600.
- The backup is a *copy* made with `O_EXCL` and the old file's mode.
- A statusLine is ours when it is `<binary> statusline` and the binary either resolves
  (`os.SameFile`) to this executable or is named `clair` or `clair-`/`clair_`/`clair.`
  followed by anything. An original like that is never saved, run or restored.
- `clair statusline` sets `CLAIR_STATUSLINE_NESTED=1` for the original it runs and runs no
  original when it finds the variable set, so any cycle ends after one hop.

The alternative a reader reaches for first is an in-process mutex. It does not cover
`clair pair` or `clair unpair` running beside the daemon, which is the race that loses
settings. A lock file created with `O_EXCL` needs stale-lock recovery after a crash; an
advisory lock is released when the process dies.

**What it costs.** One more file beside `settings.json` (the lock, never deleted) and a direct
dependency on `golang.org/x/sys` for Windows, which was already in the module graph through
`x/crypto`. A symlink cycle, or one to a directory, fails the edit rather than being replaced.
The lock is advisory: Claude Code does not take it, so a user edit landing between our read
and our rename can still be overwritten. That was true before and is out of reach without
Claude Code's cooperation. What keeps this true: `TestConcurrentInstallsKeepTheUsersSettings`,
`TestInstallKeepsTheFileMode`, `TestInstallWritesThroughASymlinkAndNotThroughAPlantedOne`,
`TestSecondInstallNeverSavesOurOwnStatusLine`, `TestRunStatuslineNeverRunsItself` and
`internal/daemon`'s `TestSnippetsInstallOneAtATimeLatestLast`.
