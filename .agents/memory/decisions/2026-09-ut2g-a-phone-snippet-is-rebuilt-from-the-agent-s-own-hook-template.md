---
id: "2026-09.ut2g"
slug: a-phone-snippet-is-rebuilt-from-the-agent-s-own-hook-template
title: "A phone snippet is rebuilt from the agent's own hook template, with each event pinned to its endpoint"
date: 2026-09-23
topics: [hooks, security]
---

# ADR 2026-09.ut2g — A phone snippet is rebuilt from the agent's own hook template, with each event pinned to its endpoint

Status: Accepted (2026-09-23) · tightens ADR 2026-09.3gre · security review 2026-09-23, findings AG-1 and AG-2

**What was observed.** ADR 2026-09.3gre's validator checked a phone snippet's hooks for `type`,
`url` and `command` and then installed the phone's objects as sent. Two holes followed. First,
Claude Code fills `$VAR` references in an http hook's header values from its own environment
for every name the hook lists in `allowedEnvVars`, and the agent forwards `X-Clair-Host` (and
the query) verbatim into the record the phone receives; a snippet could therefore have every
hook carry an API key or cloud credential to the phone on every event, silently (AG-2; Claude
Code's credential denylist for interpolation narrows this, to an unknown extent). Second, any
URL under the marker was accepted for any event, so a snippet could route `Stop` or
`PreToolUse` to `/hook/decide` and let the phone answer events that were meant to be
fire-and-forget (AG-1).

**What changed.** `claudecfg.ValidateSnippet` takes the host's `SnippetConfig` and rebuilds each
hook from the same builder `RenderHooks` uses. Of a phone's http hook only three things are
kept: the endpoint, a timeout (an integer, 1 to 86 400 s) and a `statusMessage` string; the
`url` is re-rendered from the endpoint, `headers` are always exactly `Authorization: Bearer
<token>` and the agent's own `X-Clair-Host`, and `allowedEnvVars` — like every other member —
is never written. Of a group only `matcher` is kept. Each event is pinned to one endpoint:
`PermissionRequest` to `/hook/decide` (optionally `?timeout=<seconds>`, re-rendered from the
number), every other event to `/hook/event` with no query, or to this binary's `hook-event`
command hook, which `PermissionRequest` may not have. Anything else rejects the whole snippet,
as before. Separately, the loopback forwards `X-Clair-Host` only when it is one to 64
characters of the sanitised-hostname set (`hostname.Valid`), so a hook shaped anywhere else
cannot use the header as a channel either. The alternative a reader reaches for first,
rejecting snippets that carry `allowedEnvVars` or unknown headers, was not taken: it keeps a
blocklist of Claude Code's hook options, and the next option it adds would pass through.

**What it costs.** A phone cannot set any hook option the agent does not know — `async`,
`once`, a new header — even harmlessly; a new one is a change here first. A phone snippet that
routes a new event to `/hook/decide` (say, a future blocking hook) is refused until this
decision is revisited together with ADR 2026-09.w4ww. What keeps this true:
`TestValidateSnippetKeepsThePhoneTemplate` (the phone's `relayTemplate()` defaults rebuild to
exactly `RenderHooks`' default block), `TestValidateSnippetRebuildsEachHook`,
`TestValidateSnippetRejects`, and `TestRequestRecordShape`'s host-header cases.
