---
id: "2026-09.r7kd"
slug: the-control-surface-shares-the-loopback-listener-under-clair-ctl-with-its-own
title: "The control surface shares the loopback listener under /clair/ctl with its own token, and a pair file has one writer"
date: 2026-09-21
topics: [daemon, state, cli]
---

# ADR 2026-09.r7kd — The control surface shares the loopback listener under /clair/ctl with its own token, and a pair file has one writer

Status: Accepted (2026-09-21); a release hands the pair file over instead of deleting it since ADR 2026-09.69ym

**What was observed.** `clair pair` and `clair unpair` run as separate processes from the
daemon (interview decision 3: pairing needs no running daemon), yet the daemon must learn about
a new pair, stop an old one before its file is replaced, and answer `clair status`. Both
processes read and write `pairs/<id>.json`, and the daemon persists counters into it while it
runs (ADR 2026-09.hzwt). A Unix socket would have been the natural control channel and would
have needed a Windows named-pipe twin with its own ACL story.

**What changed.** The daemon's control surface lives on the same loopback listener as the
hooks, under `/clair/ctl/` — `GET status`, `POST reload`, `DELETE pairs/{id}` — behind a
second bearer, `adminToken` in `agent.json`, which never leaves the config directory (the hook
bearer is deliberately handed to Claude Code through `settings.json`, and a program that can
read that file must not be able to drive the daemon). The guard order stays the phone's: a path
outside `/clair/v1` and `/clair/ctl/` is 404 before any token is read. A pair file has one
writer at a time: the daemon while the pair is loaded, the CLI otherwise, and the handoff is
`DELETE /clair/ctl/pairs/{id}` — the daemon stops the pair, releases its held decides and
deletes the file — after which the CLI writes the new file once, at the end of pairing, and
`POST /clair/ctl/reload` makes the daemon pick it up. When no daemon answers
(`ctl.ErrUnreachable`) the CLI deletes and writes the files itself and says how to start one.
The alternative — pairing inside the daemon with `clair pair` as a thin client — would have
made the daemon a prerequisite for the very first command a user runs.

**What it costs.** A second token to keep, and a `clair status` that needs the daemon's port
from `agent.json`, so `daemon -listen`/`-relay` flags are persisted there. The trap: the CLI
must delete the released file itself even after a successful release, because a daemon that
never held the pair (or a test double) answers 404 and leaves it. What keeps this true:
`TestGuardOrder` (control paths reject the hook token and vice versa), `TestStatusAndControl`,
`TestPairReplacesAnExistingPair` (release → revoke → new host key), and the daemon's
`ReleasePair` in the end-to-end test.
