---
id: "2026-09.w4ww"
slug: the-agent-answers-a-held-decide-only-with-what-the-permissionrequest-allows
title: "The agent answers a held decide only with what the PermissionRequest allows, checked against the request"
date: 2026-09-23
topics: [hooks, security, tunnel]
---

# ADR 2026-09.w4ww — The agent answers a held decide only with what the PermissionRequest allows, checked against the request

Status: Accepted (2026-09-23) · security review 2026-09-23, finding AG-1

**What was observed.** `/hook/decide` handed the phone's response body to Claude Code byte for
byte. A `PermissionRequest` answer can do far more than allow or deny: `decision.updatedInput`
replaces the tool's input, `decision.updatedPermissions` adds allow rules to user or local
settings or switches the permission mode, and top-level `systemMessage`, `continue` and friends
are honoured. So a compromised phone, stolen phone keys, or a photographed-QR attacker the user
approved could "approve" `ls` and have Claude Code run something else — code execution as the
user on every paired host, the escalation ADR 2026-09.3gre exists to prevent — and leave allow
rules behind that survive `clair unpair`. The review's PoC had an answer carrying
`updatedInput` and `updatedPermissions` reach the hook caller unchanged.

**What changed.** `internal/hookout.Check` reads the held request and the phone's answer and
*rebuilds* the answer from what the request allows; anything else is "no decision" (`204`,
logged as `decide answer refused` with the rule, never a value). The shapes are the phone's
`HookOutput.kt`:

- only a request whose `hook_event_name` is `PermissionRequest` is answered, and only with
  `hookSpecificOutput.hookEventName: "PermissionRequest"` and `behavior` `allow` or `deny`;
- `deny` keeps `message` and `interrupt`; `allow` keeps `updatedInput` and `updatedPermissions`
  when they pass; every other field, at any level, is dropped;
- an `updatedPermissions` entry must equal one of the request's `permission_suggestions` (JSON
  equality, member order ignored), or — for `ExitPlanMode` only — be exactly
  `{type: setMode, mode: default|acceptEdits|auto, destination: session}`, the entry the phone
  writes when Claude Code suggested none;
- `updatedInput` is allowed for `AskUserQuestion` (the original input with only `answers`
  added or replaced, each answer a string) and `ExitPlanMode` (a subset of the original input:
  the phone strips the injected `plan` and `planFilePath`), and for no other tool;
- any status but `200` with a body is `204`.

This makes the agent read three more request fields — `tool_name`, `tool_input` and
`permission_suggestions` — once, at answer time, for this check only; they are never logged,
never stamped anywhere, and never change what is tunnelled. `.agents/rules/go.md`'s blind-tunnel
rule names them. The alternative a reader reaches for first, dropping only the dangerous fields
and passing the rest, was not taken: the dangerous set is Claude Code's to grow, and a
field-level blocklist fails open on the next release. Filtering on the phone was not an option:
the phone is the attacker in this threat model.

**What it costs.** The phone's legitimate answers are pinned to today's shapes. A new answer
kind — a tool whose input the phone may edit, a new plan mode — is refused as "no decision"
(the terminal dialog still works) until this check learns it; change both repositories
together. A deny `message` and an `AskUserQuestion` answer are still free text the model reads:
that is the phone answering the prompt it was shown, which the threat model allows. The check
depends on Claude Code sending `permission_suggestions` verbatim; if it ever stopped, the phone's
"don't ask again" choices would turn into plain allows being refused — no escalation, a visible
regression. What keeps this true: `internal/hookout`'s accept and refuse tables,
`TestDecideAnswers` in `internal/hookserver`, and the snippet side of the same finding
(ADR 2026-09.ut2g), which keeps any event but `PermissionRequest` away from `/hook/decide`.
