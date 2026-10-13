# Design: where it lives and what binds this codebase

**The design is not in this repository.** It is `docs/RELAY.md` in the `clair` repository
(the phone/watch app) — normally a sibling checkout at `../clair`, i.e.
`../clair/docs/RELAY.md` (revision 2026-10-12 **r15**: r2 folded in this implementation's
corrections, r3 the presence rule, r8 canonical v2 signing, r9 the pairing and revoke seams, r10 the
timeout cancel, r11 the phone's idle stream, r12 what marks a background agent's decide, r13 the
`PostToolBatch` that closes a prompt answered at the terminal with feedback, r14 the `StopFailure` and
quota-resume Notification that end and resume a turn stopped at a usage limit, r15 the agent's own `/usage`
record, a model's weekly window for a plan with no account-wide week — its "Revision" lists are the
diff). Read it before any design-level work;
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
- It reads **two** plaintext fields and whether a third is there: `hook_event_name`, only to
  pick `wake` (§4, §7.5) and to drop a `PostToolBatch` while it holds no decide (r13, ADR
  2026-10.ukr9), and `permission_mode` and the presence of `agent_id`, only to tell a
  background subagent's decide, which is handed to the terminal while someone is at one (§4.3,
  ADRs 2026-09.34qh and 2026-10.gw8w). The decide hook's own `X-Clair-Entrypoint` header, filled
  in by Claude Code from its environment, keeps a `claude -p` run's decide held; it is read on
  the loopback and never forwarded. The loopback server also checks that `session_id` is
  *present* (the phone's 400 rule) and never reads it. Of a `/statusline` body it reads only
  whether `rate_limits.five_hour` and `rate_limits.seven_day` hold a value: a five-hour window
  with no week has the agent ask Claude Code's `get_usage` for each model's own week, at most
  every 10 min, and send it as a `/usage` request of its own (r15, ADR 2026-10.mhj3). The
  statusline itself is forwarded unchanged.
- The phone is trusted to answer prompts, not to act on the host. Its decide answer is checked
  against the held request — `tool_name`, `tool_input`, `permission_suggestions`, read at answer
  time only — and rebuilt (`internal/hookout`, ADR 2026-09.w4ww); its snippets are rebuilt from
  the agent's own hook template (ADR 2026-09.ut2g).
- The relay (`clair-server`) never holds a traffic key and is trusted for nothing (§3,
  §10). Everything the agent sends it is ciphertext plus routing headers.

## Section → package

| RELAY.md | Package | What it owns |
| --- | --- | --- |
| §4, §4.1 | `internal/hookserver`, `internal/record`, `internal/hookout` | Loopback listener on `127.0.0.1:7317` with `HookServer`'s bearer-and-path contract; tunnel records (`request` / `response` / `control`); `/hook/event`, `/statusline`, `/ping` answered `204` locally, a `PostToolBatch` queued only while the pair holds a decide (`record.Forwarded`, ADR 2026-10.ukr9); `/hook/decide` held open until the response record or the deadline, and answered only with what the request allows; `/status` answered locally; a statusline with a five-hour window and no week kicks `internal/usage`, which reads each model's own week from a headless `claude -p` `get_usage` and sends it as the agent's own `/usage` request, `soon` (r15, ADR 2026-10.mhj3) |
| §4.2 | `internal/tunnel` | One bounded FIFO per pair (draft 2 000 records / 16 MiB), shedding `no` first, then `soon`, never `now`; in memory; `reset` on start, `cancel {reqId, reason}` when Claude Code abandons a decide (`client`), the terminal takes it (`terminal`), the agent stops (`stop`) or the hold runs out, 2 s before Claude Code's own timeout (`timeout`, ADR 2026-09.72gv) |
| §4.3 | `internal/presence`, `internal/tunnel` | Terminal input idle from pty access times (`/dev/pts/*`, `/dev/ttys*`) or `GetLastInputInfo`; stamped as `X-Clair-Idle-Ms` on every request record; a bubbled decide (`record.Hook.Bubbled`: an `agent_id` or `bubble`, in an interactive session by its `X-Clair-Entrypoint`, ADR 2026-10.gw8w) is released to the terminal at once while the idle is under the phone's threshold (`hello.presence` / `policy`, default 120 s, 0 = off), or when someone returns while it is held; flips while a decide is held go out as `/hook/presence` requests (`now`) |
| §5.1 | `internal/identity`, `internal/state` | Host X25519 + Ed25519 seeds in `host.key` (0600) under `os.UserConfigDir()/clair` — `~/.config/clair` on Linux, `~/Library/Application Support/clair` on macOS, `%AppData%\clair` on Windows; `CLAIR_CONFIG_DIR` overrides |
| §5.2–5.4 | `internal/envelope` | HKDF derivation with `salt = k`; the envelope (`v`, `pair`, `id`, `dir`, `wake`, `ttlSec`, `ct`); XChaCha20-Poly1305 with a 24-byte random nonce and the exact AAD layout; per-direction replay counters (`Counter`, `HighWater`); ULID ids; the 4 MiB cap and the derived 3 145 592-byte record cap |
| §5.5 | `internal/envelope` | Standard-library `crypto/ecdh`, `crypto/hkdf`, `crypto/ed25519`; `golang.org/x/crypto/chacha20poly1305` is the only outside import (RELAY.md names `x/crypto/{curve25519,hkdf}`; the stdlib has both since Go 1.20/1.24) |
| §6 | `internal/pairing` | `clair pair`: mint, the QR (`rsc.io/qr`, half-blocks, `-qr ascii|none`, `-invert`), wait, prove the phone knows `k` by opening `hello`, confirm on the controlling terminal, `hello-ack`, write the pair file and `settings.json`, reload the daemon. Between the relay's completion and the saved pair file every way out — a no, Ctrl-C, SIGTERM, SIGHUP, a terminal or save error — revokes the pair on a context of its own, after a sealed `revoke` once the `hello-ack` may have gone (ADR 2026-09.mwfw) |
| §6.1 | `internal/pairing` | Payload `0x01 ‖ pairingId[16] ‖ hostPub[32] ‖ k[16] ‖ relay-host?` as `https://<relay>/p#<base64url>`; version 6 at level L |
| §6.5 | `internal/claudecfg`, `internal/ojson` | The order-preserving `settings.json` merge, the `clair statusline` shim, the decide hook's `X-Clair-Entrypoint: $CLAUDE_CODE_ENTRYPOINT` and its one `allowedEnvVars` (ADR 2026-10.gw8w), snippet substitution (values escaped as JSON) and validation (the phone's `http://127.0.0.1:<port>` accepted for the agent's port, the agent's origin written; events the template does not hook dropped with a warning); at pairing a refused snippet gives way to the built-in block with a warning, and no hooks at all fails `clair pair` with the pair kept; an install that changes nothing writes nothing (ADR 2026-09.bckr); at each start a paired daemon rebuilds the Clair groups already in `settings.json` from its template where they stand, adding none but the agent's own groups to a block with Clair's decide hook, and `clair status` says what it found (`RefreshHooks`, ADR 2026-10.sm5c). Those groups (`agentEvents`: `PostToolBatch`, `StopFailure`, and a `Notification` group matching the `quota_auto_resume_*` types, told apart from the phone's `idle_prompt` group by its matcher) are the agent's, not the phone's: the built-in block and every snippet with the decide hook get them, and `clair pair` writes them only beside a daemon whose `ctl.Status.AgentEvents` lists them, or with none running (ADR 2026-10.ukr9, ADR 2026-10.6cm3) |
| §6.6 | `internal/pairing`, `internal/state`, `internal/daemon`, `internal/tunnel` | Ending a pair is a sealed `revoke` (`soon`, `ttlSec` 86400), then `DELETE`, never before it (r9): `clair unpair` and `clair pair --replace` have the daemon stop each pair and hand its file over, take it (`state.Dir.TakePair`, read and deleted in one step) and seal the `revoke` with `n = h2pNext`, then upload it and `DELETE` — even when the upload failed, since the host keeps nothing to retry with — every pair at once, each call bounded to 3 s, so an unreachable relay never blocks the local unpairing; a pair the relay already reports gone gets only the `DELETE` (ADR 2026-09.69ym). The phone's sealed `revoke` ends a pair at once, after which the daemon `DELETE`s it as well (a `410` is the usual answer); `clair unpair` removes the hooks, the statusline and the host key |
| §7.2, §7.3 | `internal/relay` | SSE down + `POST` up (no WebSocket); `Authorization: Clair-Ed25519 key, ts, nonce, sig` over the relay's **canonical v2** (`"clair-v2"`, method, `Host`, target, ts, nonce, body hash; relay ADR 2026-09.9vsq, ours 2026-09.n68c): a fresh 16-byte `crypto/rand` nonce on every request, retries included; a `401 skew` (clock from `serverTime`, then `Date`) or `401 replay` is re-signed and retried once, a second refusal surfaced; bounded streams resumed with `Last-Event-ID`; one upload in flight per (pair, dir), and back-to-back uploads under one signing key 1 s apart, a `now` record excepted (`tunnel`'s `pacer`, ADR 2026-10.rmej); a 404 is the relay's word about a pair only with its `error` `pair_not_found` (`ErrPairNotFound`), and any other 404 — Vercel's `DEPLOYMENT_NOT_FOUND`, an edge, a proxy — is retried like a 5xx (ADR 2026-09.32b5); `DELETE /events` releases a stream (`ReleaseStream`); `--relay-ca`, `HTTPS_PROXY` |
| §7.4, §7.5 | `internal/tunnel`, `internal/record` | Cursor acks after *applying* envelopes, at most one a second per pair (ADR 2026-10.rmej); a failed ack is retried with backoff (1 s → 60 s), and one the relay answers `410` or `pair_not_found` is dropped, as is a parking pair's pending one (ADR 2026-09.32b5); `wake` stamped from `hook_event_name` (`StopFailure` is a turn boundary, `soon`, ADR 2026-10.6cm3), `PostToolUse*` and `PostToolBatch` promoted to `soon` while a decide is held; TTLs |
| §7.6 | `internal/tunnel`, `internal/ctl`, `internal/relay` | Presence shown by `clair status`. The newest `/events` stream owns a pair side's presence (relay ADR 2026-09.7fc3): an older one ends quietly, with no event and no `retry:`, and `Stream` treats that as a routine end and resumes with `Last-Event-ID`. The agent keeps exactly one `/events` stream per pair (`tunnel.pair.receiver`); a second would evict the first on every reconnect. When a pair stops — a clean daemon stop, or a release for `clair unpair` / `--replace` — the receiver releases its stream (`DELETE /events`, best effort within 2 s), so the phone sees the host leave at once rather than when the relay ages the closed stream out, up to ~14 min on Vercel (ADR 2026-09.hu4b) |
| §12 | `internal/relay` | `HTTPS_PROXY` / `NO_PROXY` through `http.ProxyFromEnvironment`, system trust store, `--relay-ca` replaces it |
| §13 | `internal/tunnel`, `internal/daemon` | Relay unreachable (queue, backoff), a clean stop (queue drained for 2 s, holds answered, `cancel` sent, the stream released), restart (`reset`), revoke (the phone's sealed `revoke` record → hooks and keys removed, the pair deleted at the relay too, daemon keeps serving `204`s; a relay-reported `410`, `event: revoked` or `404 pair_not_found` only parks the pair — ADR 2026-09.9ufb, first a divergence and RELAY.md's own rule since r9 §6.6. The relay drains a revoked pair's retained rows to the side that did not revoke it, so a parked pair's stream may deliver the phone's sealed `revoke`, which ends it without resuming it first; the pair resumes only when the relay accepts its `reset`, and seven days of reports end it — ADR 2026-09.32b5), skew (`401 skew` → adopt `serverTime`), a spent nonce (`401 replay` → re-sign once), an edge `429` without a JSON body or `Retry-After` (backoff) |
| §14 | — | Phase 2 (tunnel + pair) is implemented; the agent's part of phase 3 (`wake`) too; releases are tag pipelines served by claircode.app's installers (ADR 2026-09.zvs8) |
| — (updates) | `internal/update`, `cmd/clair/update.go` | The daemon checks claircode.app's `/releases/` about every 6 h, verifies the release's Ed25519 signature against the keys built in, and swaps a newer build onto disk where the binary is; the new binary runs from the next start, and nothing restarts the daemon. `clair update` asks the daemon (`/clair/ctl/update`) or checks itself. Only a linker-stamped `vX.Y.Z` updates, only forward. The CLI on disk may then be newer than the daemon, so what they share only grows (ADRs 2026-09.qk6v, 2026-09.66m4) |
| §6 (install), §15 (Windows) | `internal/service`, `internal/logfile`, `cmd/clair/service.go` | `clair service install\|uninstall\|start\|stop\|restart\|status`: the daemon as the user's login service — a systemd user unit, a LaunchAgent (`app.claircode.clair`), a logon Scheduled Task under `conhost --headless` running `clair daemon -supervise`, because Task Scheduler cannot see a crash through conhost (ADR 2026-09.pz5g) — never a system service, since presence needs the user's session; this binary where it is; the environment it needs captured at install; `POST /clair/ctl/stop` for a clean stop where Task Scheduler can only kill; `clair daemon -log-file` where no manager keeps a log. Verified on Linux, and on a Mac mini (macOS 27) on 2026-09-27; Windows unverified at a signed-in desktop (ADR 2026-09.ahq8) |

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
  2026-09.9vsq and 2026-09.7fc3 in `clair-server`, ours 2026-09.n68c). RELAY.md r8 folded v2
  into §7.3; the relay has refused every other form since it removed v1 (its ADR 2026-09.wzzg),
  and the agent signs v2 only.
- **A parked pair resumes when the relay accepts its `reset`**, not on its stream's first
  `presence` or envelope (ADR 2026-09.32b5). Since r9 a revoked pair's stream is served to the
  side that did not revoke it while the revoker's rows drain, so a served stream no longer proves
  the pair live, and an accepted upload does. What goes on the wire is unchanged: the `reset` a
  resumed pair sends first anyway.

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
  block must carry `__PORT__`, `__TOKEN__`, `__CLAIR_HOST__` and `__CLAIR_EXE__`. Since
  ADR 2026-09.ut2g it is rebuilt, not installed as sent: only `PermissionRequest` may reach
  `/hook/decide`, and headers and `allowedEnvVars` are the agent's, never the phone's. Since
  ADR 2026-09.bckr the placeholders are filled in as JSON string content (a quoted Windows path
  used to break the JSON), the phone's `127.0.0.1` is accepted for the agent's own port whatever
  loopback spelling it listens on, an event the template does not hook is dropped with a
  warning, and at pairing a refused snippet installs the built-in block — RELAY.md r2 item 5
  promised that fallback; the agent installed nothing. Since ADR 2026-10.ukr9 a snippet with
  the decide hook also gets the agent's own `PostToolBatch` group, which the phone does not list.
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
in `client_test.go`). `relaytest.Fake` verifies requests as the relay does
(nonce single use per key, `Host` bound, no-nonce headers `malformed`) and
builds its canonical string itself. `TestContract` drives the real client
(and raw signed requests for the refusals the client never provokes) through
`relaytest.Fake`, records every exchange and checks it against the document: route and
method, declared status, an `error` code the response lists, JSON and SSE event schemas,
and the request body of every 2xx. Every `pairings` and `pairs` operation must be
exercised, so a route the relay adds fails the test until it is covered; `/stream`, which
answers 2xx only to a WebSocket upgrade the agent never makes, is covered by its `426` to a
plain signed GET (ADR 2026-09.hu4b). The fake keeps a revoke's goodbye as the relay does (r9
§6.6): a `DELETE` purges only the revoker's inbound rows, and the other side's stream drains
the rest, then says `revoked`, and its `/ack` is served while any are left. Like a vector, the
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
