---
id: "2026-09.69ym"
slug: ending-a-pair-is-a-sealed-revoke
title: "Ending a pair is a sealed revoke, then DELETE; the CLI seals it from the pair file the daemon hands over"
date: 2026-09-23
topics: [protocol, state, cli]
---

# ADR 2026-09.69ym — Ending a pair is a sealed revoke, then DELETE; the CLI seals it from the pair file the daemon hands over

Status: Accepted (2026-09-23); amends ADR 2026-09.r7kd (a release hands the pair file over)

**What was observed.** Only the other side's sealed `revoke` ends a pair at once. A revoke the
relay reports without one only parks the pair for a week (ADR 2026-09.9ufb on this side; the
phone parks the same way since RELAY.md r9).

- `clair unpair` and `clair pair --replace` sent no sealed record, only
  `DELETE /v1/pairs/{id}`. So every unpair made on the host left the phone holding a dead pair
  for a week.
- After reading the phone's sealed `revoke`, the daemon told the relay nothing. If the phone's own
  `DELETE` never landed, the relay kept the pair until its idle sweep.
- The trap is `n`. The sealed record needs an `n` above every `n` the host has used. While the
  daemon runs a pair it owns the counter and reserves blocks in the file (ADR 2026-09.hzwt,
  2026-09.r7kd), so the copy of the file the CLI read when the command started can be a block or
  more behind.

**What changed.**

- `ReleasePair` now stops the pair — its last counters written, its stream released — and
  *hands the file over* instead of deleting it.
- The CLI takes each released file: `state.Dir.TakePair` reads it and deletes it under the lock
  the counter updates take. With no daemon, or one that never held the pair, the CLI is already
  the file's writer and takes it the same way.
- The CLI seals the pair's `revoke` (`wake: soon`, `ttlSec: 86400`) with `n` set to the file's
  `h2pNext`. The counter persists a block's limit before it hands out any value in the block, so
  every `n` ever used is below that limit. With the file gone, no counter can reserve from it
  again.
- All pairs say goodbye at once. The relay gets the sealed `revoke` first. Only once it has taken
  it, the CLI sends the `DELETE`: after a `DELETE` the relay refuses every upload, and it keeps
  the revoker's sent rows for the other side (RELAY.md r9 §6.6).
- Each call is bounded by `goodbyeTimeout` (3 s), so an unreachable relay delays unpairing by
  about 6 s at most. It never stops the unpairing, which is local. Failures are reported on
  stderr.
- A pair whose file records the relay reporting it gone (`relayRevokedAt`) gets no sealed record,
  because the relay would refuse it. It still gets the `DELETE`. An upload answered `410` or
  `pair_not_found` skips the `DELETE`.
- After the daemon applies a phone's sealed `revoke`, it deletes the pair at the relay as well,
  once the pair's goroutines have stopped and its ack of the record has gone. This is best effort
  within 2 s (ADR 2026-09.hu4b). `410` is the usual answer, because the phone's `DELETE` landed
  first.

The alternative the cross-repo spec also offered was to let the daemon seal, upload and `DELETE`
through the control channel, with the counter it holds. It was not taken:

- The no-daemon path would still need the seal from the file, so there would be two paths for one
  job.
- The relay round trips would run inside a control call whose client gives up after 5 s.
- A pair's record would queue behind its backlog, or be refused outright if the pair was parked.

**What it costs.**

- The CLI must take or delete the file after every release. It already did, because a daemon that
  never held the pair answers 404 (r7kd's trap).
- A daemon from before this change deletes the file itself. The CLI then finds nothing to take
  and sends only the `DELETE`, and the phone parks the pair for a week.
- The handover assumes nobody reloads the daemon between the release and the take, a window of
  milliseconds. A reload that has already reserved a block is harmless: `TakePair` reads the new
  limit. So is one that has not, because its first reservation then finds no file and hands out
  nothing (`TestCounterHandsOutNothingWhenReserveFails`). Only a reservation interleaved with the
  take, across the two processes, could reuse an `n`.
- The phone can read the host's `revoke` only while the relay keeps it, which is 24 hours at most
  (its TTL).

What keeps this true:

- `internal/pairing`: `TestUnpair`, `TestUnpairSealsAboveTheDaemonsLastReservation`,
  `TestUnpairSendsAParkedPairNoGoodbye`, `TestUnpairIsNotHeldUpByAnUnreachableRelay`,
  `TestPairReplacesAnExistingPair`
- `internal/tunnel`: `TestPhoneRevokeReleasesHoldsAndNotifiesOnce` (the ack, then the `DELETE`)
- `internal/daemon`: `TestReleasePairHandsTheFileOver`, `TestEndToEnd`
