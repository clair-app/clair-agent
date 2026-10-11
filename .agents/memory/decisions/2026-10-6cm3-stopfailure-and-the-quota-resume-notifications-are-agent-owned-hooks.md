---
id: "2026-10.6cm3"
slug: stopfailure-and-the-quota-resume-notifications-are-agent-owned-hooks
title: "StopFailure and the quota-resume notifications are agent-owned hooks"
date: 2026-10-10
topics: [hooks, claudecfg, record]
---

# ADR 2026-10.6cm3 — StopFailure and the quota-resume notifications are agent-owned hooks

Status: Accepted (2026-10-10) · amends ADR 2026-10.ukr9 (an agent event may share its event with the phone's
group, told apart by its matcher, and not every agent event is gated) · pairs with the phone's usage-limit ADR ·
RELAY.md r14

**What was observed.** On 2026-10-10 the maintainer's workstation's sessions hit the claude.ai five-hour limit at 00:59 PDT. The
transcripts hold 16 synthetic assistant messages, `"You've hit your session limit · resets 4:20am
(America/Los_Angeles)"`, each with `error: "rate_limit"`, `apiError: "usage_limit_reached"` and
`rateLimitType: "five_hour"`. The phone and watch kept every one of those sessions on Working until Claude Code
continued them by itself at 04:20:31, about three and a half hours later, and nothing told the user they had run
out. The sessions looked active, but they were paused until the next window.

The cause is in Claude Code 2.1.296's hooks, read from the installed binary:

- **A turn that ends on an API error fires `StopFailure`, not `Stop`.** Its input is the common fields plus
  `error` (which is also what its matcher matches: `rate_limit`, `authentication_failed`, `server_error`, …),
  `error_details` and `last_assistant_message`, the text above. Neither template hooked it, so the phone saw
  the turn start and never saw it end.
- **The resume is a `Notification`.** Claude Code sends `notification_type` `quota_auto_resume_fired` when it
  continues the task, `quota_auto_resume_stale` when the reset passed while the machine slept and it waits for
  Enter, and `quota_auto_resume_disabled` when it will not continue on its own. The phone's Notification group
  matches `idle_prompt` only.

**What changed.**

- **Two more agent-owned groups,** installed the way ADR 2026-10.ukr9 installs `PostToolBatch`: rendered last,
  appended to a snippet with the decide hook, and added by the start's refresh. They are a `StopFailure` group
  with no matcher, and a second `Notification` group whose matcher is
  `quota_auto_resume_fired|quota_auto_resume_stale|quota_auto_resume_disabled`. Both are `http` hooks to
  `/hook/event` with the 2 s timeout. `StopFailure` has no matcher on purpose: every API error leaves a session
  stuck on Working, and the phone tells a usage limit from the rest.
- **An agent event with a matcher is told apart by it.** `agentEvents` entries are now `{event, matcher,
  name}`. `hasAgentGroup` counts any Clair group for an event without a matcher, as before, and only a Clair
  group with the same matcher for one with a matcher. Otherwise the phone's `idle_prompt` group would stand in
  for the quota group and it would never be added. `AgentEvents()`, and so `ctl.Status.AgentEvents` and
  `RefreshReport.Added`, name the quota group `Notification:quota_auto_resume`.
- **Neither is gated.** `StopFailure` is a turn boundary and is `soon` in `record.Wake`, like `Stop`, whatever
  the pair holds. The quota Notifications are already `soon` as Notifications. `record.Forwarded` still gates only
  `PostToolBatch`, and `TestEveryAgentEventIsGated` became `TestEveryAgentEventIsRouted`, a table that names
  each agent event's gate and fails on one it does not name.
- **The agent still reads no new field.** It routes on `hook_event_name` alone. Telling a usage limit from
  another error, and the window and reset time, is the phone's.

The alternative a reader reaches for first is to widen the phone's Notification matcher to `idle_prompt|quota_…`
and add `StopFailure` to the phone's template. That changes the snippet hash, resends every pair, and has an
older daemon trim `StopFailure` as unknown: the r12 and ukr9 objections again. The second is a `Notification` group with
no matcher. It would forward every notification type, permission prompts and `agent_completed` included, as
`soon` wakes the phone ignores. The third is to read the statusline's `rate_limits` on the host and send an alert
of the agent's own. That has the agent read a plaintext field it does not need, and the statusline is throttled
to 30 s and says nothing about which sessions stopped.

**What it costs.**

- **Removing either group by hand doesn't stick** while Clair's decide hook is installed, as ukr9 says of
  `PostToolBatch`. A quota group whose matcher was edited is no longer the agent's: the next start adds another.
- **Every API error wakes the phone,** `soon`, once per failed turn. These are rare next to tool churn, and the
  limit case is the one the user needs to hear about.
- **An older daemon** forwards a `StopFailure` group that a newer `clair pair` or refresh wrote as `no`, and its
  refresh skips it as unknown. `clair pair` beside a daemon whose `AgentEvents` lacks either name writes none of
  the agent's groups (`agentEventsMissing`), as before.
- **Unverified fields.** The live `error_details` of a plan limit and whether Claude Code accepts an `http`
  `StopFailure` hook are checked by the probe the plan installs on the maintainer's workstation. The phone reads
  `last_assistant_message` and the statusline's `rate_limits`, so it does not depend on `error_details`.

What keeps it true:

- `TestRenderHooksMatchesTheGolden` and `TestRefreshHooksBringsAnOlderBlockToTheTemplate`, whose
  `hooks-default.json` and `settings-refreshed.json` now carry both groups.
- `TestTheQuotaGroupIsToldApartByItsMatcher`, `TestValidateSnippetAddsTheAgentsEvents` and
  `TestRefreshHooksAddsTheAgentsEventsAfterTheUsers`.
- `TestEveryAgentEventIsRouted`, and `record`'s `TestWake` and `TestForwarded` rows for `StopFailure`.
