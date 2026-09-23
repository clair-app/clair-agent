---
id: "2026-09.khcq"
slug: the-agent-speaks-sse-down-and-post-up-only
title: "The agent speaks SSE down and POST up only; streams are bounded and resumed by cursor"
date: 2026-09-21
topics: [relay, transport, protocol]
---

# ADR 2026-09.khcq — The agent speaks SSE down and POST up only; streams are bounded and resumed by cursor

Status: Accepted (2026-09-21); the canonical string is superseded by ADR 2026-09.n68c (v2, a nonce and the host)

**What was observed.** `docs/RELAY.md` (rev 2026-09-21) gives the host a WebSocket as its primary
transport with SSE + `POST` as the fallback after a failed upgrade (§7.2, §12). The relay is
being built on Vercel (`clair-server`'s plan, decision 5), where WebSockets are a gated beta and
every invocation — streams included — ends at `maxDuration` (280 s by default, 780 s on the
production plan). The relay therefore ends every `GET /v1/pairs/{pair}/events` itself with a
closing block (`id: <last cursor>` + `retry: 1000`) and expects the client back with
`Last-Event-ID`. A WebSocket client in this module would have been a dependency (there is none
in the standard library) with nothing on the other end to talk to.

**What changed.** The agent speaks SSE down and `POST` up only, and treats every stream as
bounded: `relay.Client.Stream` owns reconnection — a clean end is followed after the relay's
`retry:` (clamped to [250 ms, 30 s]), a failed connection after an equal-jitter exponential
backoff (1 s → 60 s), a 401 the clock can fix immediately — and returns only for a context end,
a handler error, a `revoked` event or an answer a reconnect cannot fix (404, 401, 409, 410,
413). The resume cursor advances only after the tunnel's handler applied an event, so a crash
mid-drain re-delivers, which the record counter `n` and the envelope id make harmless.
Requests are signed with the canonical string the relay pinned — `METHOD "\n" path?query
"\n" ts "\n" hex(sha256(body))` — with `key` and `sig` as unpadded base64url, and the clock
is corrected from a 401's `serverTime` (then the `Date` header) and retried once. Uploads are
batched to ≤ 100 envelopes / ≤ 4 MiB with one in flight per (pair, direction), since the
relay's cursors do not commit in order under concurrency. The alternative — keeping WSS as
"primary" with SSE as the fallback, as written — would have shipped code nobody could run
against the relay that exists.

**What it costs.** One more request per phone→host envelope than a socket would need (the
phone sends few), and a reconnect roughly every 13 minutes on the production relay, which the
`Last-Event-ID` resume makes invisible. The trap: `http.ProxyFromEnvironment` reads the
environment once per process and never proxies loopback targets, so the proxy selector is an
injected option (`relay.Options.Proxy`) and the `HTTPS_PROXY` path is not exercised by a test.
What keeps this true: `internal/relay`'s stream tests against `relaytest.Fake` (bounded end →
`Last-Event-ID` resume, revoke → `ErrRevoked`, idle watchdog, 503 backoff, skew correction) and
the signing vector in `internal/relay/testdata/signing-vector.json`, shared with the relay repo.
`.agents/context/design.md` records the §7.2/§7.3 divergence from RELAY.md.
