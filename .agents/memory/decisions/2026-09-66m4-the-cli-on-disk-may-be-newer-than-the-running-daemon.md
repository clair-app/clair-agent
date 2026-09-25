---
id: "2026-09.66m4"
slug: the-cli-on-disk-may-be-newer-than-the-running-daemon
title: "The CLI on disk may be newer than the running daemon, so what they share only grows"
date: 2026-09-24
topics: [daemon, cli, state]
---

# ADR 2026-09.66m4 — The CLI on disk may be newer than the running daemon, so what they share only grows

Status: Accepted (2026-09-24)

**What was observed.** Until the self-update (ADR 2026-09.qk6v), the binary on disk and the
running daemon were always one build. install.sh swapped the file and restarted the service in
the same run.

Now the updater swaps the file and the daemon keeps running its old image until its next start.
That can be weeks away on a laptop that mostly sleeps, with several releases staged in between.
Meanwhile every other process starts from the new file:

- `clair status`, `clair pair`, `clair unpair`, `clair service …` and `clair update`
- the `hook-event` command hook and the `statusline` command, which Claude Code runs on every
  session and every refresh

These processes talk to the old daemon and read and write the same files. The skew has no
bound: a daemon started on v1 can run beside v5 on disk.

**What changed.** A rule, not code. These interfaces **only ever gain** fields, paths and
flags; they never lose, rename or reinterpret one:

- **The loopback surfaces.** `/clair/v1/*` and `/clair/ctl/*`: paths, methods, status codes,
  and the JSON in `internal/ctl`.
  - A newer CLI must handle an older daemon's 404 on a path it added, as `clair update` does by
    running the check itself.
  - It must also handle an absent field, as `clair status` does with a nil `Update`.
- **The config files.** `agent.json` and `pairs/<id>.json` (`internal/state`).
  - A new field's zero value, which is what an older daemon writes back when it rewrites the
    file without knowing the field, must mean the old behaviour. `autoUpdate` absent means on.
  - A change that cannot be expressed that way needs a new `v` with a migration, and older
    binaries must refuse the file rather than misread it.
- **The command lines other programs store.**
  - The service registrations run `daemon -config-dir … -log-file … -relay-ca …`.
  - The hooks block and `statusLine` in `settings.json` run `hook-event <path>` and
    `statusline`.

  Those flags and argument shapes must keep working in every later release, because the unit,
  plist, task and `settings.json` written by an old binary outlive it.

The alternatives:

- Restarting the daemon after each update, and so removing the skew, would end held decides and
  streams on the updater's schedule (ADR 2026-09.qk6v).
- Versioning the control surface (`/clair/ctl/v2/…`) would need the same rule one level up.
- Refusing to talk across versions would break `clair status` exactly when someone wants to know
  why the agent is behind.

**What it costs.** Every change to those interfaces is reviewed as a compatibility change. A
removal waits until no supported daemon can still be running the old side. With no rollback
and no forced restart, that means a release, then a deliberate grace period, then the removal.
The trigger row in `.agents/rules/decisions.md` routes a change to `internal/ctl`,
`internal/state`, the hookserver's paths, or a daemon, `hook-event` or `statusline` flag here.

`clair status` and `clair service status` print the skew ("the agent runs clair vA and this
command is vB") when both are releases and differ, so it is visible and never silent.

No test enforces the rule across real releases yet. The current tests cover an older daemon's
404 (`cmd/clair/update_test.go`) and an agent.json without the new fields
(`internal/state/state_test.go`).
