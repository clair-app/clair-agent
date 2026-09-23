---
id: "2026-09.evep"
slug: the-agent-edits-settings-json-through-an-order-preserving-json-object-and
title: "The agent edits settings.json through an order-preserving JSON object and installs clair statusline in place of the shell shim"
date: 2026-09-21
topics: [hooks, claudecfg]
---

# ADR 2026-09.evep — The agent edits settings.json through an order-preserving JSON object and installs clair statusline in place of the shell shim

Status: Accepted (2026-09-21); the write, the backup by rename and statusLine ownership by regexp are superseded by ADR 2026-09.y34x

**What was observed.** RELAY.md §6.5 has the agent rewrite Claude Code's `settings.json` the
way the phone's `setup.sh` does: remove every hook group whose `url` or `command` contains
`/clair/v1/`, append the new groups, wrap the user's `statusLine` in a shim that forwards usage
and then runs their own command, back the file up first. `setup.sh` needs `python3` or `node`
and writes `sh ~/.claude/clair-statusline.sh`, which no Windows box without a POSIX `sh` can
run. Go's `encoding/json` sorts object keys on output, and `encoding/json/v2` is still behind
`GOEXPERIMENT=jsonv2` in Go 1.26, so a naive rewrite would shuffle the user's file.

**What changed.** `internal/ojson` is a ~200-line order-preserving object model over
`json.Decoder`'s tokens with a writer that matches Python's `json.dump(indent=2)` and Claude
Code's own output (two-space indent, `": "`, `{}`/`[]` for empty containers, literal UTF-8,
no HTML escaping); `internal/claudecfg` does the merge on it, writes `settings.json.bak-<stamp>`
by rename, then the new file atomically, and keeps the user's `statusLine` in
`clair-statusline.sh.original.json` beside it — the LAN installer's file name, so a LAN install
migrates. The `statusLine` becomes `<absolute path to clair> statusline`: the binary reads the
statusline JSON once, posts it to the daemon at most every 30 s *concurrently* with running the
user's original command through the platform shell (`sh -c`; on Windows Git Bash if present,
else PowerShell) with the same stdin, and passes that command's output and exit status through.
Ownership of the `statusLine` is recognised by a regexp over the command
(`clair(\.exe)?['"]?\s+statusline\b`) or the legacy shim's name. A `statusLine` that is not a
command is left alone with a warning, as before. The built-in hooks block reproduces the
phone's `HooksSnippet` exactly. `SessionStart` stays a `command` hook — Claude Code 2.1.278
refuses http hooks for it ("HTTP hooks are not supported for SessionStart", verified with a
real session; RELAY.md §4 assumed otherwise) — but the command is this binary,
`<clair> hook-event /clair/v1/hook/event`, never `curl`: it forwards stdin to the daemon with
a 2 s budget and never fails the hook. The path argument carries the `/clair/v1/` marker, so
the one ownership rule every installer uses still recognises the entry.

**What it costs.** Two small parsers of our own instead of the standard library, and a
statusline that spawns one extra process per update on top of the user's (Claude Code
debounces at 300 ms). The trap: Claude Code cancels a statusline script when a newer update
arrives, so the POST must never delay the user's command — it runs on its own goroutine and is
merely waited for afterwards. What keeps this true: `TestRoundTripKeepsOrderAndForm` over
`internal/ojson/testdata`, `TestInstallMergesLikeThePhoneInstaller` (the phone's
`InstallerScriptTest` fixture: foreign `Stop` hook kept first, install twice without
duplication, uninstall restores), the golden `hooks-default.json`, and `TestRunStatusline`'s
slow-daemon case.
