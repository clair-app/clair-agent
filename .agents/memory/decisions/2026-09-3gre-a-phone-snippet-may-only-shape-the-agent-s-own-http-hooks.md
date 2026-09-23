---
id: "2026-09.3gre"
slug: a-phone-snippet-may-only-shape-the-agent-s-own-http-hooks
title: "A phone snippet may only shape the agent's own http hooks"
date: 2026-09-21
topics: [hooks, security]
---

# ADR 2026-09.3gre — A phone snippet may only shape the agent's own http hooks

Status: Accepted (2026-09-21) · tightened by ADR 2026-09.ut2g (snippets are rebuilt from the agent's template, events pinned to endpoints) · amended by ADR 2026-09.bckr (values escaped as JSON, the phone's 127.0.0.1 accepted for the agent's port, unknown events dropped, the pairing fallback implemented)

**What was observed.** RELAY.md §6.5 sends the hooks block from the phone, inside `hello` and
later as a `snippet` control record, with `__PORT__`, `__TOKEN__` and `__CLAIR_HOST__`
placeholders the agent fills in, so settings such as the permission timeout stay on the phone.
Taken literally, that lets the phone write arbitrary JSON into `settings.json` — including
`command` hooks, which Claude Code runs as the user. A pairing is authenticated (§6.2), but a
stolen or compromised phone, or a bug in the phone, must not become shell access to every
paired host.

**What changed.** `claudecfg.ValidateSnippet` accepts a substituted snippet only if it is
`{"hooks": {…}}` and every hook in every group is `type: "http"` with a `url` under
`http://127.0.0.1:<port>/clair/v1/`, or the one `command` hook that is exactly this binary's
`hook-event` (`__CLAIR_EXE__ hook-event /clair/v1/hook/event` before substitution — the
SessionStart hook Claude Code will not accept over http); anything else — another `command`,
a foreign host, another loopback port, a path outside the marker — rejects the whole snippet
with `ErrSnippetRejected`,
the daemon logs which event offended, and the hooks already installed stay as they are. At
pairing time a `hello` without a snippet, or with a rejected one, falls back to the agent's
built-in rendering of the same block (interview decision 6), so a phone that does not send
snippets yet still gets a working host. The alternative — trusting the phone as RELAY.md
writes it — was not taken; the alternative of dropping only the offending group was not taken
either, because a silently edited snippet is harder to reason about than a refused one.

**What it costs.** The phone cannot add a `command` hook even for a good reason; if one is ever
wanted, it is a change to this decision and a new agent subcommand, never `curl`. The trap:
the check is on the substituted text, so a snippet must carry the placeholders — a phone that
hard-codes `127.0.0.1:7317` passes only while that is the port. What keeps this true:
`TestSubstituteAndValidate`'s rejection table and `TestSnippetInstaller`, and the daemon
end-to-end test's snippet path. RELAY.md §6.5 needs the sentence (`.agents/context/design.md`,
"RELAY.md revision proposal", G3).
