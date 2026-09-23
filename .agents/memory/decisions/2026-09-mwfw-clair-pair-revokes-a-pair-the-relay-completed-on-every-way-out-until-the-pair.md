---
id: "2026-09.mwfw"
slug: clair-pair-revokes-a-pair-the-relay-completed-on-every-way-out-until-the-pair
title: "clair pair revokes a pair the relay completed on every way out until the pair file is saved"
date: 2026-09-23
topics: [pairing, relay]
---

# ADR 2026-09.mwfw — clair pair revokes a pair the relay completed on every way out until the pair file is saved

Status: Accepted (2026-09-23) · cross-repo fix D4 (2026-09-23)

**What was observed.** Once the relay reports a pairing `completed`, it holds a pair and the
phone shows it, waiting for the host's `hello-ack`. `clair pair` revoked that pair only on
three paths (an impostor, a hello with an absurd `n`, a "no" at the prompt), each with the
command's own context. Ctrl-C at "Pair with …? [Y/n]" cancelled that context, so there was
nothing left to revoke with; SIGHUP (the terminal closed) was not caught at all and killed the
process; a terminal read error or a failed `SavePair` returned without a word to the relay.
Each left the phone with a pair whose `hello-ack` never came — its `HELLO` link reason had no
timeout, so it pinned the foreground service and the stream — and the orphan counted against
the host's cap of five pairs.

**What changed.** From the moment `/wait` reports completion until the pair file is saved,
`Pair` holds an `unfinishedPair`, and a deferred `abandon` revokes it on every way out: an
impostor, an absurd hello, a "no", Ctrl-C, SIGTERM, SIGHUP, a terminal error, a failed
replace, a failed save. It runs on `context.WithoutCancel` bounded to 5 s, since the command's
context may be what ended. Before the hello-ack is sent the relay's revoke is enough: the phone
drops a pair still waiting for its hello-ack on a relay-reported revoke (RELAY.md §6.6, fix
D3.4). Once the hello-ack may have reached the relay — it is marked before the upload, whose
outcome an interrupt leaves unknown — `abandon` first seals a `revoke {}` control record
(`n = 2`, the hello-ack took 1) and uploads it, bounded to 2 s of the 5, then the `DELETE`: a
phone that read the hello-ack would otherwise park the pair for a week instead of ending it
(the relay keeps what the revoker sent, fix D3.2). Once the file is saved the pair is kept
whatever follows, including hooks that cannot be written (ADR 2026-09.bckr). `cmd/clair` adds
SIGHUP to the signals that end a command through its context, unless SIGHUP is ignored:
`signal.Notify` would undo a `nohup` and stop a daemon meant to outlive its terminal. The
alternative a reader reaches for first, revoking in each error branch, is how the paths were
missed; one deferred owner cannot miss a new return.

**What it costs.** Up to 5 s more before an interrupted `clair pair` exits, during which a
second Ctrl-C does nothing (the signal is still routed to the cancelled context). A relay that
cannot be reached in that time leaves the pair for its own cleanup, with a line on stderr. An
interrupt while `/wait` is still open is not covered: the host has no pair id to revoke, and
the phone side's bounded `HELLO` reason (fix D4, phone half) is what ends that one. What keeps
this true: `TestAnUnfinishedPairingIsRevoked` (declined, terminal error, interrupted at the
prompt and during the hello-ack, unsavable pair file; the relay's mailbox holds the sealed
revoke where the phone may have the hello-ack), `TestPairRefusesAPhoneThatDidNotScanThisCode`,
`TestPairBoundsWhatTheHelloSays`, and `cmd/clair`'s `TestStopSignalsIncludeTheHangup`.
