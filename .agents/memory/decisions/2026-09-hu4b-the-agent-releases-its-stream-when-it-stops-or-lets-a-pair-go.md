---
id: "2026-09.hu4b"
slug: the-agent-releases-its-stream-when-it-stops-or-lets-a-pair-go
title: "The agent releases its stream when it stops or lets a pair go"
date: 2026-09-23
topics: [relay, daemon, transport]
---

# ADR 2026-09.hu4b — The agent releases its stream when it stops or lets a pair go

Status: Accepted (2026-09-23)

**What was observed.** The relay reports a side "connected" while that side's stream
heartbeats. On Vercel a function is never told that an SSE client left, so a stream the agent
closed kept heartbeating until its invocation ended, up to 780 s. After a clean `clair daemon`
stop, the phone showed the host connected for up to about 14 minutes. The relay added
`DELETE /v1/pairs/{id}/events` (`releaseStream`) for this, but the agent never called it. The
agent's copy of the relay's OpenAPI document, from `clair-server` 556d99f, predated that route and
`/stream`, so `TestContract` could not see either one.

**What changed.**

- When a pair's receiver stops, it calls `relay.Client.ReleaseStream` once, best effort, within
  `relayTidyTimeout` (2 s). It stops on a clean daemon stop, or when `SetPairs` lets the pair go,
  which is how `ReleasePair` hands a pair to `clair unpair` or `clair pair --replace`.
- The call comes after the pair's stream has ended and never before another one opens. A late
  release would take presence away from the new stream.
- Pairs stop concurrently, so a stop waits about 2 s at most for all of them.
- A pair that ended or is parked skips the call, because the relay would answer `410`. The same
  bound covers the `DELETE` after a phone's sealed revoke (ADR 2026-09.69ym).
- The contract copy is refreshed, first from `clair-server` b063955 and then from its
  `fix/revoke-and-complete` branch at a8393a7. `TestContract` now drives `releaseStream` through
  the client.
- `/stream` answers 2xx (a `101`) only to a WebSocket upgrade, which the agent never makes (ADR
  2026-09.khcq). The test covers it by the `426 upgrade_required` a plain signed GET gets. The
  coverage rule names that one exception, so any other route the relay adds still fails the test
  until it is exercised.

The alternative a reader reaches for first releases the stream on every reconnect. That is
pointless, because the newest stream owns its side anyway (the relay's ADR 2026-09.7fc3). It is
also harmful: a release that races a reconnect idles the new stream.

**What it costs.** Against an unreachable relay, a clean stop takes up to 2 s longer, on top of
the 2 s drain. A crash releases nothing, and the relay ages the side out as before. `relaytest.Fake`
clears a side's presence when the stream's connection closes, so it cannot show the stale
"connected" itself. Tests check that the release is made:

- `internal/tunnel`'s `TestStoppingReleasesTheStream`
- `internal/daemon`'s `TestShutdownReleasesHeldDecides` and `TestReleasePairHandsTheFileOver`
- `internal/relay`'s `TestContract`
