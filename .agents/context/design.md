# Design: where it lives and what binds this codebase

**The design is not in this repository.** It is `docs/RELAY.md` in the `clair` repository
(the phone/watch app) — normally a sibling checkout at `../clair`, i.e.
`../clair/docs/RELAY.md` (revision 2026-09-22 **r3**: r2 folded in this implementation's
corrections, r3 the presence rule — its "Revision 2" and "Revision 3" lists are the diff). Read it before any design-level work;
this page is the map from its sections to this codebase, not a copy. If the sibling checkout
is missing, ask for it rather than working from memory: the document is revisioned and the
numbers marked *draft* move.

Companions in that repository: ADR 2026-09.ew4t (the decision record for the relay),
`.agents/context/bridge-ingress.md` (the five endpoints the agent tunnels, with their exact
status codes, size cap and bearer contract), `.agents/context/protocol.md` (the phone ↔
watch protocol, for vocabulary only — the agent never touches it), and `:shared/relay`
(the golden vectors, `RelayVectorsTest`, see "Vectors" below).

The relay is `clair-server` (a sibling checkout at `../clair-server`, NestJS on
Vercel). **Where the relay and RELAY.md disagree, the relay wins** and the difference is listed under
"Divergences" here. The wire contract this code speaks is the relay's **OpenAPI document**
(`openapi.json` at the root of `clair-server`, served at `/openapi.json`, browsable at
`/docs`). It is the source of truth for routes, status codes, `error` codes, body and SSE
event schemas, and the `Clair-Ed25519` canonical string; RELAY.md still owns the crypto and
the behaviour. See "Relay contract" below.

## The posture

- **The agent is a blind tunnel** of the existing v1 HTTP surface (§4). It implements
  RELAY.md, not the phone's Kotlin: both sides reproduce the same vectors from the same
  document and share no code. A disagreement with the phone is settled by the document,
  then by a vector test in both repositories.
- It reads **two** plaintext fields: `hook_event_name`, only to pick `wake` (§4, §7.5), and
  `permission_mode`, only to tell a background subagent's decide, which is handed to the
  terminal while someone is at one (§4.3, ADR 2026-09.34qh). The loopback server also checks
  that `session_id` is *present* (the phone's 400 rule) and never reads it.
- The relay (`clair-server`) never holds a traffic key and is trusted for nothing (§3,
  §10). Everything the agent sends it is ciphertext plus routing headers.

## Section → package

| RELAY.md | Package | What it owns |
| --- | --- | --- |
| §4, §4.1 | `internal/hookserver`, `internal/record` | Loopback listener on `127.0.0.1:7317` with `HookServer`'s bearer-and-path contract; tunnel records (`request` / `response` / `control`); `/hook/event`, `/statusline`, `/ping` answered `204` locally; `/hook/decide` held open until the response record or the deadline; `/status` answered locally |
| §4.2 | `internal/tunnel` | One bounded FIFO per pair (draft 2 000 records / 16 MiB), shedding `no` first, then `soon`, never `now`; in memory; `reset` on start, `cancel {reqId, reason}` when Claude Code abandons a decide (`client`), the terminal takes it (`terminal`) or the agent stops (`stop`) |
| §4.3 | `internal/presence`, `internal/tunnel` | Terminal input idle from pty access times (`/dev/pts/*`, `/dev/ttys*`) or `GetLastInputInfo`; stamped as `X-Clair-Idle-Ms` on every request record; a `bubble` decide is released to the terminal at once while the idle is under the phone's threshold (`hello.presence` / `policy`, default 120 s, 0 = off), or when someone returns while it is held; flips while a decide is held go out as `/hook/presence` requests (`now`) |
| §5.1 | `internal/identity`, `internal/state` | Host X25519 + Ed25519 seeds in `host.key` (0600) under `os.UserConfigDir()/clair` — `~/.config/clair` on Linux, `~/Library/Application Support/clair` on macOS, `%AppData%\clair` on Windows; `CLAIR_CONFIG_DIR` overrides |
| §5.2–5.4 | `internal/envelope` | HKDF derivation with `salt = k`; the envelope (`v`, `pair`, `id`, `dir`, `wake`, `ttlSec`, `ct`); XChaCha20-Poly1305 with a 24-byte random nonce and the exact AAD layout; per-direction replay counters (`Counter`, `HighWater`); ULID ids; the 4 MiB cap and the derived 3 145 592-byte record cap |
| §5.5 | `internal/envelope` | Standard-library `crypto/ecdh`, `crypto/hkdf`, `crypto/ed25519`; `golang.org/x/crypto/chacha20poly1305` is the only outside import (RELAY.md names `x/crypto/{curve25519,hkdf}`; the stdlib has both since Go 1.20/1.24) |
| §6 | `internal/pairing` | `clair pair`: mint, the QR (`rsc.io/qr`, half-blocks, `-qr ascii|none`, `-invert`), wait, prove the phone knows `k` by opening `hello`, confirm on the controlling terminal, `hello-ack`, write the pair file and `settings.json`, reload the daemon |
| §6.1 | `internal/pairing` | Payload `0x01 ‖ pairingId[16] ‖ hostPub[32] ‖ k[16] ‖ relay-host?` as `https://<relay>/p#<base64url>`; version 6 at level L |
| §6.5, §6.6 | `internal/claudecfg`, `internal/ojson` | The order-preserving `settings.json` merge, the `clair statusline` shim, snippet substitution and validation; `clair unpair`; `410` handling |
| §7.2, §7.3 | `internal/relay` | SSE down + `POST` up (no WebSocket); `Authorization: Clair-Ed25519 key, ts, nonce, sig` over the relay's **canonical v2** (`"clair-v2"`, method, `Host`, target, ts, nonce, body hash; relay ADR 2026-09.9vsq, ours 2026-09.n68c): a fresh 16-byte `crypto/rand` nonce on every request, retries included; a `401 skew` (clock from `serverTime`, then `Date`) or `401 replay` is re-signed and retried once, a second refusal surfaced; bounded streams resumed with `Last-Event-ID`; one upload in flight per (pair, dir); `--relay-ca`, `HTTPS_PROXY` |
| §7.4, §7.5 | `internal/tunnel`, `internal/record` | Cursor acks after *applying* envelopes, coalesced to 1 s; `wake` stamped from `hook_event_name`, `PostToolUse*` promoted to `soon` while a decide is held; TTLs |
| §7.6 | `internal/tunnel`, `internal/ctl`, `internal/relay` | Presence shown by `clair status`. The newest `/events` stream owns a pair side's presence (relay ADR 2026-09.7fc3): an older one ends quietly, with no event and no `retry:`, and `Stream` treats that as a routine end and resumes with `Last-Event-ID`. The agent keeps exactly one `/events` stream per pair (`tunnel.pair.receiver`); a second would evict the first on every reconnect |
| §12 | `internal/relay` | `HTTPS_PROXY` / `NO_PROXY` through `http.ProxyFromEnvironment`, system trust store, `--relay-ca` replaces it |
| §13 | `internal/tunnel`, `internal/daemon` | Relay unreachable (queue, backoff), restart (`reset`), revoke (`410` → hooks and keys removed, daemon keeps serving `204`s), skew (`401 skew` → adopt `serverTime`), a spent nonce (`401 replay` → re-sign once), an edge `429` without a JSON body or `Retry-After` (backoff) |
| §14 | — | Phase 2 (tunnel + pair) is implemented; the agent's part of phase 3 (`wake`) too; OS service install, releases and `install.sh` are later plans |

`internal/daemon` wires the above for `clair daemon`; `cmd/clair` is the dispatch.
`tools/phonesim` is a phone stand-in and `tools/relaysim` serves the fake relay, for
running the whole thing as real processes before the Android `RelayIngress` exists.

## Divergences from RELAY.md and from the phone's LAN contract

Deliberate, all recorded in ADRs:

- **SSE + `POST` only**; no WebSocket (ADR 2026-09.khcq; the relay's platform).
- **Strict `Bearer `** on the loopback (the phone's guard also accepts a bare token).
- **`405` + `Allow`** for a wrong method on a known path (the phone's routing is untested there).
- **`GET /clair/v1/status`** is answered locally with the agent's status (RELAY.md has it
  round-trip; debug-only).
- **Records over 3 145 592 bytes are dropped at enqueue** (a decide so dropped answers `204` at
  once); the phone's 4 MiB → `413` body rule stays on the loopback.
- **`clair statusline`** replaces the `sh clair-statusline.sh` shim (ADR 2026-09.evep).
- **Config lives under `os.UserConfigDir()/clair`**, which is `~/.config/clair` on Linux only.
- **Canonical v2 signing, and registration at mint/complete** (the relay's phase 4: ADRs
  2026-09.9vsq and 2026-09.7fc3 in `clair-server`, ours 2026-09.n68c). RELAY.md §7.3 still shows
  the three-parameter form and says a device registers on its first signed request. Its next
  revision is deliberately deferred and folds these in. The agent signs v2 only, so it is ready
  for the relay's `AUTH_NONCE=required`.

## Revision 3 (2026-09-22): presence

Folded into RELAY.md r3 §4.3 from NOTES.md's observation in the `clair` repository (ADR 2026-09.34qh
here): the `X-Clair-Idle-Ms` header, `cancel.reason`, `hello.presence` / the `policy` control, and the
`/hook/presence` request. The relay is untouched by it (ciphertext is ciphertext); the phone's
`RelayIngress` and `HookServer` read the header and the new control when they are written.

## Corrections this implementation made to RELAY.md (folded into r2; still to carry into the relay's `protocol.md`)

- **G1** — the sender's `n` must survive restarts: block reservation, persisted before use
  (ADR 2026-09.hzwt). ADR ew4t's "neither end persists a counter" is about nonces.
- **G2** — a `cancel {reqId}` control record (host → phone, `soon`) when Claude Code abandons
  a held decide; on shutdown held decides answer `204` and `cancel` is sent best-effort;
  `reset {}` follows the `hello-ack` on every start.
- **G3** — a snippet is accepted only if every hook is the agent's own `http` hook, or the
  one `command` hook that runs this binary's `hook-event` (ADR 2026-09.3gre); the phone's
  block must carry `__PORT__`, `__TOKEN__`, `__CLAIR_HOST__` and `__CLAIR_EXE__`.
- **G4** — `SessionStart` **cannot** be an `http` hook: Claude Code 2.1.278 logs "HTTP hooks are
  not supported for SessionStart" and skips it (verified with a real session). It is a
  `command` hook running `<clair> hook-event /clair/v1/hook/event` — this binary, never
  `curl` — and a phone snippet renders it as `__CLAIR_EXE__ hook-event /clair/v1/hook/event`
  (the fourth placeholder). RELAY.md §4's "SessionStart finally becomes an http hook" is wrong;
  the phone's LAN snippet had it right.
- **G5** — the plaintext record cap is 3 145 592 bytes under the 4 MiB envelope cap.
- **QR payload** — the binary layout above; `relay` omitted when it equals the origin; level L.
- **Control schemas** — `hello {name, snippet?}`, `hello-ack {hostname, agentVersion}`,
  `snippet {snippet}`, `reset {}`, `cancel {reqId}`, `revoke {}`; `n` is `uint64`.
- **`fp`** is shown as lowercase hex in groups of four.

## Vectors

`internal/envelope/testdata/relay-vectors.json` is `:shared/relay`'s `relay-vectors.json`
(`RelayVectorsTest`), copied unchanged; the comment beside the loader in
`internal/envelope/vectors_test.go` names the clair commit it was taken from, and a refresh
updates both. The schema (pinned `k`, both key pairs, derived keys, and per envelope the
header, `nonce`, exact `recordBytes`, `aad` and `ct`, all base64url) is shared with the phone,
so a vector that fails is a bug in one of the two implementations, never a fixture to edit.
The crypto is independently pinned by RFC 5869 A.1 and draft-irtf-cfrg-xchacha A.3.1 through
our layout, plus an independent HKDF in the tests.

## Relay contract

`internal/relay/testdata/openapi.json` is the relay's `openapi.json`, copied unchanged; the
comment beside `specPath` in `internal/relay/contract_test.go` names the `clair-server`
commit it was taken from, and a refresh updates both. `testdata/signing-vector-v2.json` is
the relay's `src/auth/testdata/signing-vector-v2.json` under the same rule (`signingVectorPath`
in `client_test.go`). `relaytest.Fake` verifies requests as the relay does with
`AUTH_NONCE=required` (nonce single use per key, `Host` bound, no-nonce headers `malformed`) and
builds its canonical string itself. `TestContract` drives the real client
(and raw signed requests for the refusals the client never provokes) through
`relaytest.Fake`, records every exchange and checks it against the document: route and
method, declared status, an `error` code the response lists, JSON and SSE event schemas,
and the request body of every 2xx. Every `pairings` and `pairs` operation must be
exercised, so a route the relay adds fails the test until it is covered. Like a vector, the
copy is never edited to make a check pass: a failure is drift in the client or the fake, or
a relay change to follow.

The validator is a standard-library subset of JSON Schema (ADR 2026-09.vnj9), not a
library. A schema that uses a keyword it does not know fails loudly instead of passing. No
code is generated from the document: the client is small, streams SSE, signs raw body bytes,
and depguard's allow-list (ADR 2026-09.kau2) has no room for a generator's runtime.

## Numbers that are *draft*

Queue bounds, TTLs, backoffs, the ack interval, the counter block and flush cadence are
starting points (RELAY.md's status line). Each is one named constant with a comment citing
its section: `internal/tunnel/tunnel.go`, `internal/relay/client.go`, `internal/record/wake.go`,
`internal/envelope/envelope.go`.
