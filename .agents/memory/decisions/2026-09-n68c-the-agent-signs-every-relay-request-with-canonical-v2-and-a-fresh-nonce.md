---
id: "2026-09.n68c"
slug: the-agent-signs-every-relay-request-with-canonical-v2-and-a-fresh-nonce
title: "The agent signs every relay request with canonical v2 and a fresh nonce, and re-signs once on replay"
date: 2026-09-22
topics: [relay, auth, protocol]
---

# ADR 2026-09.n68c — The agent signs every relay request with canonical v2 and a fresh nonce, and re-signs once on replay

Status: Accepted (2026-09-22)

**What was observed.** The relay (clair-server `d74f7a7`, its ADR 2026-09.9vsq) now takes a
`nonce=` parameter that selects **canonical v2**. v2 signs `"clair-v2"`, the method, the **`Host`**,
the request target, `ts`, the nonce and the body hash, one per line. The relay spends each nonce
once per key until `ts + 300 s` and answers a second use `401 replay`. It still accepts the old
three-parameter form while `AUTH_NONCE=optional`. Once it is set to `required`, a header without a
nonce is `401 malformed` on every call, so an agent signing v1 is locked out. The agent signed v1.
It treated any 401 other than `skew` as final, so `clair pair`'s `WaitPairing` would die on a
`replay`, which should never be fatal. A replay is not only an attacker's doing. Go's
`http.Transport` re-sends an idempotent request (the SSE `GET`s, `DELETE`) on a reused connection
that broke, headers and all, and a request the relay already verified then comes back as `replay`.

**What changed.** The agent signs **v2 only**, with no v1 path and no switch. Nothing is
deployed that would need one, and a switch left at the wrong setting fails exactly at the
`required` flip. The v1 vector and its test are deleted; git history keeps them.
`relay.Client.newRequest` signs every request afresh, the streams included. It reads 16 bytes
(`NonceSize`) from `Options.Entropy`, which defaults to `crypto/rand.Reader`, for a 22-character
base64url nonce. It takes the host from `req.Host`, falling back to `req.URL.Host`, lower-cased
with its port if it has one: the value the `Host` header carries. `relay.New` refuses a non-ASCII
host, because Go sends it punycoded and the signed host would differ. A 401 whose `reason` is
`replay` is re-signed and retried **once**, in the same place as a `skew` 401 (`Client.resign`,
used by `do` and by `openStream`). A second refusal in a row surfaces as `ErrUnauthorized` and is
never retried again. For a stream, that is `follow`'s `retriedNow` flag, which also ends the
immediate-reconnect loop a stubborn `skew` could once cause. The alternative a reader would reach
for first is keeping v1 behind a flag until the relay flips. Here that is dead code the day it
ships, and a way to stay locked out after the flip. Retrying `replay` like a transport error, with
backoff, would hold up a pairing for seconds over something one fresh signature fixes.

**What it costs.** One `crypto/rand` read per request. A relay behind a proxy that rewrites
`Host` refuses every request as `signature`, and so does an IDN relay URL not given in punycode;
that is the relay's trade-off, and the error names it. A second `replay` in a row is surfaced
rather than hidden, which the tunnel's outer loops (uploader backoff, receiver restart, the
ack tick) absorb and `clair pair` reports. It does not cover the phone, which needs the same
change in its own repository. The guards are `TestSigningVectorV2`, which uses
`internal/relay/testdata/signing-vector-v2.json` (the relay's RFC 8032 TEST 1 vector, copied
unchanged). `TestEveryRequestCarriesAFreshNonceAndTheHost`, `TestReplayIsResignedAndRetriedOnce`
(unary calls, stream open and pairing wait; once succeeds, twice surfaces) and `TestContract`'s
signed-request refusals (a reused header → `replay`, another host → `signature`, no nonce →
`malformed`) run against `relaytest.Fake`, which verifies v2 as the relay does with
`AUTH_NONCE=required` and builds its canonical string itself, not with the client's
`relay.Canonical`. The trap is caching a signed header, or building the request once outside the
retry loop. Either sends the spent nonce again and turns the one retry into a guaranteed second
`replay`.
