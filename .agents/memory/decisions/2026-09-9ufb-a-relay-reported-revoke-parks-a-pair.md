---
id: "2026-09.9ufb"
slug: a-relay-reported-revoke-parks-a-pair
title: "A relay-reported revoke parks a pair; only the phone's sealed revoke or a week of unbroken reports deletes it"
date: 2026-09-23
topics: [relay, state, security]
---

# ADR 2026-09.9ufb — A relay-reported revoke parks a pair; only the phone's sealed revoke or a week of unbroken reports deletes it

Status: Accepted (2026-09-23)

**What was observed.** RELAY.md §6.6 has a host that sees `event: revoked`, a `410`, or
(in the code) any `404` delete its pair file and, once no pair remains, uninstall its hooks and
statusline and delete `host.key`. The production security review (2026-09-23, AG-3) showed a
relay holding no key material could do exactly that: none of those answers is authenticated.
The phone's sealed `revoke` record existed but was optional, "a courtesy". A hostile relay, its
operator, or a single relay bug (a misrouted deploy answering `404`) could therefore unpair
every host at once, and every host would have to scan a new QR.

**What changed.**
- The only authenticated end of a pair is the phone's sealed `revoke` control record, and it
  still ends the pair at once.
- `event: revoked`, a `410` or a `404` on the stream or an upload now *parks* the pair
  (`tunnel.pair.quarantine`):
  - Its held decides are answered "no decision" and its queue is dropped.
  - Hooks skip it, so the loopback answers `204` at once.
  - Its pair file, `host.key` and the `settings.json` hooks stay.
  - When the reports began is persisted in the pair file (`relayRevokedAt`), so it survives
    restarts. `clair status` shows it with the date the pair will be removed.
- The receiver asks again from 1 min, doubling to 15 min. The first `presence` or `envelope`
  event resumes the pair (the relay opens every stream it serves with `presence`), clears the
  persisted start and sends `reset`.
- Reports that hold without a break for seven days end the pair the old way. A real revoke
  keeps answering `410` for the relay's 30-day tombstone, so a phone-side revoke still cleans
  up on its own. A `404` is treated like a `410`, not as a routine failure: once the tombstone
  is swept, a revoked pair reads `404`, and a host that was off for a month must still clean
  up.

The alternative a reader reaches for first is quarantine with no end: nothing but the sealed
record or `clair unpair` deletes anything. With RELAY.md as written, that leaves every host
whose phone revoked it parked indefinitely. The relay's `DELETE` purges the mailbox, so the
sealed record rarely survives to be read.

**What it costs.** After a phone-side revoke whose sealed record the host did not read first,
the host keeps its keys and its hooks for a week, answered locally. The hooks cost one
loopback call per event, and `clair status` says what is happening. A hostile relay can still
unpair a host, but only by answering `410` or `404` without a break for a week, not in one
reply. It can also flip a pair between parked and served, which is the drop-or-delay power it
already had. The protocol half is the phone's: RELAY.md §6.6 should make the sealed `revoke`
record required and send it before the `DELETE`, which then waits until the host has read it.
That is proposed to the `clair` repository alongside PH-10, the phone's mirror of this flaw.
What keeps this true: `internal/tunnel`'s `TestRelayReportedRevokeParksThePair`,
`TestDormantPairResumesWhenServedAgain`, `TestDormantGraceCountsFromThePersistedStart` and
`TestPhoneRevokeReleasesHoldsAndNotifiesOnce`, and `internal/daemon`'s
`TestRelayOnlyRevokeKeepsTheHostsState`.
