---
id: "2026-10.mhj3"
slug: the-agent-reads-a-model-s-weekly-limit-from-claude-get-usage-when-the
title: "The agent reads a model's weekly limit from claude get_usage when the statusline has no seven-day window"
date: 2026-10-12
topics: [usage, statusline, blind-tunnel]
---

# ADR 2026-10.mhj3 — The agent reads a model's weekly limit from claude get_usage when the statusline has no seven-day window

Status: Accepted (2026-10-12) · amends the blind-tunnel rule in `.agents/rules/go.md` (the statusline's
`rate_limits` is read for whether two keys hold a value) · pairs with the phone's model-week ADR · RELAY.md r15

**What was observed.** On 2026-10-12 the user's Team plan showed no 7D meter on the watch face. Claude Code
2.1.296 builds the statusline's `rate_limits` from `five_hour`, `seven_day` and a gateway's `spend_limit` only
(read from the installed binary), and this account has no account-wide week: its statusline carries
`five_hour` alone. Its only week is a model's own. Claude Code calls it the "Fable limit"
(`seven_day_overage_included` in the rate-limit headers), and it never reaches the statusline. The SDK's
`get_usage` control request does carry it. A headless `claude -p --input-format stream-json` answered
`{"subtype":"get_usage","skip_behaviors":true}` with `"seven_day": null` and
`"model_scoped": [{"display_name": "Fable", "utilization": 4, "resets_at": "2026-10-17T16:00:00.285488+00:00"}]`.
It returned in about 1.6 s, exited 0 when its stdin closed, ran no turn, spent no tokens and wrote no transcript.

**What changed.**

- **The statusline handler reads whether two keys hold a value.** A `/statusline` body whose `rate_limits` has a
  non-null `five_hour` and no or a null `seven_day` kicks `internal/usage`'s poller (`hookserver.UsageNoter`).
  Nothing else of the body is read, and the statusline is forwarded unchanged as before. Every other body,
  including one without `rate_limits` (an API key) or with a `spend_limit` alone (a gateway), kicks nothing.
- **The poller asks Claude Code.** At most once per 10 min, counted from the attempt so a failure backs off too,
  and one at a time, it runs the user's `claude` (on `PATH`, else `~/.local/bin` or `~/.claude/local`) in an
  empty temporary directory with `--setting-sources project --settings {"disableAllHooks":true}
  --strict-mcp-config --no-session-persistence`. That leaves no hooks (Clair's own `SessionStart` would make a
  phantom session), no MCP servers and no transcript. It sends the one `get_usage` line, closes stdin, and reads
  `rate_limits.model_scoped`, or, when Claude Code made no such projection, the server's `limits[]` rows of kind
  `weekly_scoped` with a model. Claude Code keeps the credentials.
- **The result is a request the agent originates,** as `/hook/presence` is: `/clair/v1/usage` with the
  daemon's own `X-Clair-Host` and `{"seven_day_models": [{"model", "used_percentage", "resets_at"?}]}`,
  `soon`, enqueued for every pair like a statusline. An empty list says the account has no model week. A probe
  that fails sends nothing.

The alternative a reader reaches for first is to read the OAuth token from `~/.claude/.credentials.json` (the
keychain on macOS) and call the claude.ai usage endpoint directly. It is cheaper, but the agent would hold the
user's credentials, refresh them, and track a private endpoint. The second is to add the windows to the
statusline body before it is tunnelled. The tunnel never transforms a body. The third is to probe whatever the
statusline says. That starts Claude Code every 10 min for the plans that do not need it.

**What it costs.** A Claude Code start, about 1.6 s and one process, at most every 10 min, only while statuslines
without a week arrive (Team plans today). `get_usage` is an SDK control request Claude Code marks experimental,
so its shape may change. The parser skips a row it cannot read, and an answer it cannot find is an error that
sends nothing; then the phone keeps its last model weeks until their reset passes. `TestParseTeamAccount` pins the
captured answer (`internal/usage/testdata`), `TestStatuslineWithoutAWeekIsNoted` the trigger, and
`TestStatuslineWithoutAWeekSendsTheModelWeeks` the record end to end. The daemon tests inject the probe, so no
test runs `claude`. The trap: a daemon whose environment points at another Claude Code login (`CLAUDE_CONFIG_DIR`)
than the sessions' reads that login's usage.
