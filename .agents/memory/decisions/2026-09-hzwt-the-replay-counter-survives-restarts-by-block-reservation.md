---
id: "2026-09.hzwt"
slug: the-replay-counter-survives-restarts-by-block-reservation
title: "The replay counter survives restarts by block reservation; the mailbox cursor is not persisted"
date: 2026-09-21
topics: [protocol, state]
---

# ADR 2026-09.hzwt — The replay counter survives restarts by block reservation; the mailbox cursor is not persisted

Status: Accepted (2026-09-21)

**What was observed.** RELAY.md §5.4 has the receiver reject any record whose `n` is at or
below the highest it accepted, per pair and direction, and ADR 2026-09.ew4t says "neither end
persists a counter across restarts" — which is true of the AEAD nonce (24 random bytes) and
false of `n`: an agent that restarted at `n = 1` would have every record refused as a replay
until it passed the phone's high-water mark, which it never learns. The cursor is different:
the agent acks a mailbox row only after applying it, and a stream opened without
`Last-Event-ID` drains from the oldest surviving row, so a crash loses nothing that was not
already acked.

**What changed.** The sender's `n` is allocated by `envelope.Counter`, which reserves blocks
of 4096 values and persists the block's upper limit (`h2pNext` in the pair file) *before*
handing out the first value; a restart continues from the persisted limit, wasting at most one
block, and §5.4 allows gaps. `clair pair` uses `n = 1` for the hello-ack and writes
`h2pNext = 2`. The receiver's high-water mark (`p2hLast`) is persisted lazily — every 64
records, every 30 s, and on stop — because a replayed phone record after a restart could at
most re-deliver a `snippet` or a late `response` that finds no hold. The mailbox cursor is not
persisted at all. The alternative — a time-derived `n` (milliseconds since the epoch shifted
left) with no persistence — was not taken because a wall clock that steps backwards would lock
the pair until it caught up, and the phone would have to accept the same convention.

**What it costs.** One small file write per 4096 outbound records, and `n` grows by up to
4096 per restart. The trap is two writers: the daemon persists counters while `clair pair`
writes a new pair file, so the file has one owner at a time (ADR 2026-09.r7kd) and `state.Dir`
serialises its read-modify-write cycles with deletes under one mutex. What keeps this true:
`TestPairCountersPersist` (the limit is on disk before the first `Next`, a restart continues
above it), `TestCounterHandsOutNothingWhenReserveFails`, and the end-to-end test's revoke,
which once resurrected a deleted pair file until the lock covered deletes. RELAY.md needs a
revision saying so (`.agents/context/design.md`, "RELAY.md revision proposal", G1).
