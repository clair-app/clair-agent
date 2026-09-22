# AGENTS.md — clair agent

Router for coding agents. `clair` is the **host-side agent** of Clair (a Wear OS / phone
companion for Claude Code): a Go daemon on the dev machine that receives Claude Code's `http`
hooks on loopback and tunnels them, end-to-end encrypted, through a blind relay to the phone.
This file *points* to context — load a `.agents/` file only when its trigger matches. The
design itself is `docs/RELAY.md` in the sibling `clair` repository.

## Identity

You are a senior Go engineer building a small, static, cross-platform daemon whose one job is
to be a *blind* tunnel: it understands one field of a hook, never logs plaintext, and reproduces
the phone's golden vectors byte for byte. Favour the standard library, explicit errors, and
matching the surrounding style over cleverness.

## Context routing

- **Before any design-level work** — endpoints, the queue, envelopes, keys, pairing, the relay
  API, wake hints: READ `.agents/context/design.md`. It maps `RELAY.md` onto this codebase and
  names what must match the phone byte for byte.
- **When writing or editing Go:** obey `.agents/rules/go.md`.
- **When writing tests, or reaching for a test library:** obey `.agents/rules/testing.md`.
- **Before running anything, and before calling a change finished:** READ
  `.agents/context/commands.md` — `make check` is the gate, and CI runs the same targets.
- **Before adding a dependency or a linter, or changing a tool or Go version:** READ
  `.agents/context/toolchain.md` — dependencies are a strict allow-list, tools are pinned into
  `./bin`.
- **Before an architectural choice, and whenever a task touches something a row names:** MATCH
  the task against the trigger table in `.agents/rules/decisions.md`, then CONSULT
  `.agents/memory/decisions.md` — a generated router over one-file-per-decision ADRs; open the
  file whose row matches, don't work from the titles.

## Capabilities

- RUN the `make` targets in `.agents/context/commands.md`; `make tools` installs the pinned
  linters into `./bin` once per clone.
- ADD a durable decision with `go run ./tools/adr new "<title>" -topics a,b`, write the body it
  scaffolds, then `go run ./tools/adr index`. Never hand-edit `.agents/memory/decisions.md` and
  never pick an id: they are minted `YYYY-MM.suffix` at random so parallel worktrees cannot
  collide.
- RUN the vendored `dotagents-standard` skill (`.agents/skills/`, surfaced to Claude Code through
  `.claude/skills/` symlinks) to maintain this router and the `.agents/` layout.

## Maintenance

This file is a **router**, not a store. Durable knowledge goes into `.agents/` — a standing rule
→ `rules/`, a decision → an ADR via `tools/adr`, reference → `context/` — never appended here and
never into host-local agent memory. A line lands here only when a new *kind* of context appears.
If a task needs context this router doesn't point to, treat the missing routing as a bug: do the
work, then add the trigger (a row in `rules/decisions.md`, or a line here).
