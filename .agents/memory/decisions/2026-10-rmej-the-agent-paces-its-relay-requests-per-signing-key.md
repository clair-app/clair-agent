---
id: "2026-10.rmej"
slug: the-agent-paces-its-relay-requests-per-signing-key
title: "The agent paces its relay requests per signing key"
date: 2026-10-10
topics: [relay, tunnel, rate-limit]
---

# ADR 2026-10.rmej — The agent paces its relay requests per signing key

Status: Accepted (2026-10-10) · pairs with the relay's ADR 2026-10.bsre ("A signing key gets the same request
rate as an address", `RequestBudget`, `REQUEST_RATE_PER_KEY_BURST` / `REQUEST_RATE_PER_KEY_PER_SECOND`) ·
corrects ADR 2026-10.ukr9's reading of the maintainer's workstation's 429s

**What was observed.** The maintainer's workstation's `daemon.log` has 2,171 lines naming a 429 or `rate_limited` since 2026-10-05,
394 of them in the 23:00 PDT hour of 2026-10-09. Nearly all are `POST /v1/pairs/<id>/envelopes`, with a few
acks and one `/events` open. The relay's journal logs each one as a signing key that hit its request rate. That
is `RequestBudget`'s per-key bucket, 60 deep and refilling 1 a second in production, not the `/envelopes` byte
budget per address that ADR 2026-10.ukr9 first blamed. Every refusal was `attempt=1` and cleared on the 1 s
retry. The cause was the uploader. It posted as soon as the queue held anything, one upload in flight, so under
tool churn every hook became an upload of its own. Acks and stream reopens spend the same key's budget, and once
the burst was gone about every other request was refused.

**What changed.**

- **Uploads under one key start at least `uploadSpacing`, 1 s, apart** (`internal/tunnel`'s `pacer`). The first
  upload after a quiet spell goes at once. One right after another waits, and whatever is queued meanwhile joins
  its batch, within `batchN` and `relay.BatchMaxBytes` as before. A busy pair therefore stays at 1 upload a
  second, half the relay's new per-key rate (bsre: a bucket of 120 refilling 2 a second, which the relay treats
  as a ceiling, not a target). That leaves room for acks and stream reopens. Latency stays within about 1 s, as
  before, because the old refusals cost a 1 s retry anyway.
- **A queued `now` record does not wait.** Decides and `/hook/presence` are what someone is looking at their
  watch for, and they are rare. The upload that carries one is booked as a start, so the spacing runs on from
  it. While an upload waits, a new record cuts the wait short so a `now` one can go.
- **The pace is per signing key, not per pair.** Every pair signs with the one host key, so pacing per pair would
  let several busy pairs add up past the key's rate. The tunnel keeps one pacer for each `PairConfig.Relay`, and
  the daemon's `relayFor` builds one client per relay URL and host key, so a pacer is exactly one key at one
  relay. A pair on another relay, or with other keys after a re-pair, gets its own pacer. `SetPairs` forgets a
  pacer once no pair uses it.
- **Acks are paced too.** The acker used to send a cursor as soon as it was applied, and the 1 s ticker only
  caught stragglers. Now an ack starts at most once every `ackInterval` (1 s) per pair, and cursors applied
  meanwhile coalesce into it. Acks only follow the phone's envelopes, which are rare (responses, policy,
  snippets), so a per-pair pace is enough. A host with several pairs on one relay, each answering, can still add
  acks on top of the 1 upload a second.
- **`Retry-After` on a 429 is honoured as before** (the uploader waits the larger of it and its backoff). The
  pacer counts real time (`time.Now`), not the tunnel's clock, because it paces against a bucket that refills in
  real time.

The alternative a reader reaches for first is a pacer inside `relay.Client`, around every signed request. It
would pace by key with no map, but it would wait after the uploader has already chosen its batch. Nothing queued
during the wait could join that batch, so under churn the agent would still send one hook per request, only
slower. Coalescing needs the wait before the peek, so the pacer has to sit in the tunnel. The second alternative
was to keep posting at once and let the relay's raised rate absorb it. A sustained churn of 2 hooks a second
would then use the whole of the new rate and leave nothing for acks and reconnects.

**What it costs.** A burst of hooks reaches the phone up to 1 s later than the first of them did before, where
the relay used to accept the first 60 at once. Stream (re)opens and `DELETE`s are not paced. They are few, and
`backoff` already spaces their retries. Production stays at the old bucket (60, refilling 1 a second) until bsre
deploys. Under it, one upload a second uses the whole refill, so acks and reopens on top of a sustained stream
can still be refused now and then, and each such refusal clears on its retry as before. `Options.UploadSpacing` exists for the tests: the harness turns pacing off, because those tests look at
what is uploaded, not when. `TestUploadsArePacedAndBatchedButADecideIsNot`,
`TestPairsOnOneRelayClientShareThePace` and `TestAcksArePaced` keep the rules above true.
