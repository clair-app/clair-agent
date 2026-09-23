---
id: "2026-09.32b5"
slug: a-parked-pair-resumes-only-when-the-relay-accepts-its-reset
title: "A parked pair resumes only when the relay accepts its reset, and only the relay's own 404 parks it"
date: 2026-09-23
topics: [relay, state, security]
---

# ADR 2026-09.32b5 — A parked pair resumes only when the relay accepts its reset, and only the relay's own 404 parks it

Status: Accepted (2026-09-23); amends ADR 2026-09.9ufb

**What was observed.** ADR 2026-09.9ufb parks a pair on a 410, `event: revoked` or *any* 404,
and resumes it on its stream's first `presence` or `envelope`. Three things broke those rules.

- A revoke now keeps the goodbye (RELAY.md r9 §6.6; the relay's ADR 2026-09.ppxy):
  `DELETE /v1/pairs/{id}` purges only what the revoker would have received. The other side's
  stream on the revoked pair opens normally: `presence`, the revoker's rows (its sealed `revoke`
  last), then `revoked`. Its `/ack` answers `204` while rows remain. A served stream no longer
  means a live pair.
- Under 9ufb the common case flapped. The phone unpairs while the laptop sleeps. The daemon
  starts, its start-up `reset` gets `410`, and the pair parks. Then the stream's `presence`
  resumes it and clears the persisted start, a second `reset` gets `410`, and it parks again with
  a fresh start. The envelope resumes it again and a third `reset` is queued before the `revoke`
  finally applies. Each drained stream restarted the week's grace and queued a `reset` the relay
  refused.
- A 404 is as often Vercel's `DEPLOYMENT_NOT_FOUND` mid-deploy, an edge's or a proxy's as the
  relay's own. None of those carries the relay's `error` code, yet each parked every host it
  reached.
- The acker retried a failed ack on every 1 s tick. On a parked pair whose ack failed, that was
  one request a second for up to seven days (the 2026-09-23 review).

**What changed.**

- Only a 404 whose `error` is `pair_not_found` is a report: `relay.ErrPairNotFound`, which is
  also `ErrNotFound`. Any other 404 is a failure like a 5xx. A stream retries it itself, and the
  uploader and the receiver back off. `410` and `event: revoked` park as before. A tombstone the
  relay has swept still answers its own `404 pair_not_found`, so a host that was off for a month
  still cleans up after the grace.
- A parked pair's stream is still read. Its envelopes are applied and acked. A drained sealed
  `revoke` ends the pair where it stands, without resuming it first. The pair's `presence` or an
  envelope queues one `reset` as a *probe* (`tunnel.pair.probe`). The pair resumes only when the
  relay accepts that upload, which it never does for a revoked pair. A refused probe changes
  nothing: no fresh start, nothing persisted, and no `reset` reaches the phone. When hooks flow
  again, the `reset` is already first in line, which the phone needs to close the decides let go
  while parked. A start persisted by an earlier run (`relayRevokedAt`) is forgotten on the first
  upload the relay accepts. A `revoked` event for a pair already ended is a no-op.
- The acker backs off after a failure (1 s doubling to 60 s), and cursors applied meanwhile
  coalesce into the retry. An ack answered `410` or `pair_not_found` is dropped, and parking
  drops whatever ack was pending.

The alternative a reader reaches for first keeps resuming on `presence` and holds the `reset`
until the first envelope is applied. That fails a quiet live pair in two ways. With nothing to
deliver, its `reset` never goes. Its hooks flow again at once, so a `reset` sent later would close
the very decides they carry on the phone. A settle timer after `presence` fails differently: a
mailbox of thousands of rows can drain for longer than any timer.

**What it costs.** A parked pair the relay serves again waits one upload round trip before hooks
reach it. Each stream open of a draining pair costs one refused `reset` upload. That is at most
one per re-check, and a drain is short. A relay that serves streams but refuses every upload for a
week still ends the pair, as under 9ufb. An edge 404 is retried with backoff for as long as it
lasts and never parks anything. What keeps this true: `internal/tunnel`'s
`TestDrainedRevokeEndsAParkedPairCleanly`, `TestParkedPairResumesOnceTheRelayTakesItsReset`,
`TestAnEdgeNotFoundParksNothing`, `TestAckBacksOffAndDropsWhatTheRelayWillNotTake` and
`TestDormantGraceCountsFromThePersistedStart`; `internal/relay`'s
`TestOnlyTheRelaysNotFoundNamesThePair`; `internal/daemon`'s
`TestPhoneUnpairWhileTheHostIsDownEndsThePairCleanly`.
