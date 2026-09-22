# Design: where it lives and what binds this codebase

**The design is not in this repository.** It is `docs/RELAY.md` in the `clair` repository
(the phone/watch app) — normally a sibling checkout at `../clair`, i.e.
`../clair/docs/RELAY.md`. Read it before any design-level work; this page is the map
from its sections to this codebase, not a copy. If the sibling checkout is missing, ask
for it rather than working from memory: the document is revisioned and the numbers marked
*draft* move.

Companions in that repository: ADR 2026-09.ew4t (the decision record for the relay),
`.agents/context/bridge-ingress.md` (the five endpoints the agent tunnels, with their exact
status codes, size cap and bearer contract), `.agents/context/protocol.md` (the phone ↔
watch protocol, for vocabulary only — the agent never touches it), and `:shared/relay`
(the golden vectors, `RelayVectorsTest`).

## The posture

- **The agent is a blind tunnel** of the existing v1 HTTP surface (§4). It implements
  RELAY.md, not the phone's Kotlin: both sides reproduce the same vectors from the same
  document and share no code. A disagreement with the phone is settled by the document,
  then by a vector test in both repositories.
- It reads **one** plaintext field, `hook_event_name`, and only to pick `wake` (§4, §7.5).
- The relay (`clair-relay`, NestJS, separate) never holds a traffic key and is trusted for
  nothing (§3, §10). Everything the agent sends it is ciphertext plus routing headers.

## Section → responsibility

| RELAY.md | What this codebase owns |
| --- | --- |
| §4, §4.1 | Loopback listener on `127.0.0.1:7317` with `HookServer`'s bearer-and-path contract; tunnel records (`request` / `response` / `control`); `/hook/event`, `/statusline`, `/ping` answered `204` locally; `/hook/decide` (and debug `/status`) held open until the response record or the deadline |
| §4.2 | One bounded FIFO per pair (draft 2 000 records / 16 MiB), dropping `wake=no` first, then `soon`, never `now`; in memory; `reset` control record on start |
| §5.1–5.4 | Host X25519 + Ed25519 keys (`~/.config/clair/`, `0600`); HKDF derivation with `salt = k`; the envelope (`v`, `pair`, `id`, `dir`, `wake`, `ttlSec`, `ct`); XChaCha20-Poly1305 with a 24-byte random nonce and the exact AAD layout; per-direction replay counter `n`; ULID `id`; 4 MiB cap |
| §5.5 | `golang.org/x/crypto/{curve25519, chacha20poly1305, hkdf}` + `crypto/ed25519`; the Go vector suite reproducing `:shared/relay`'s file byte for byte |
| §6 | `clair pair`: mint the pairing at the relay, render the QR (`/p#<fragment>`, ≈85 B, version-6 QR in half-blocks; `--qr=ascii`), wait, verify the phone's `hello` decrypts, confirm on `/dev/tty` when there is one, `hello-ack`, write `settings.json` + the statusline shim from the phone's `snippet` |
| §6.5, §6.6 | The ~30-line `settings.json` merge (remove `/clair/v1/` entries, append, back up first); `clair unpair`; `410` handling |
| §7.2, §7.3 | Relay client: WSS primary, SSE + `POST` fallback after a failed upgrade; Ed25519-signed requests (`Authorization: Clair-Ed25519 …`), ±5 min skew corrected from the relay's `Date` |
| §7.4, §7.5 | Cursor acks after *applying* envelopes; `wake` stamped from `hook_event_name`, with `PostToolUse*` promoted to `soon` while a decide is held |
| §12 | `HTTPS_PROXY` / `NO_PROXY`, system trust store, `--relay-ca`; `CLAIR_AGENT_URL` for devcontainers |
| §13 | Failure modes the daemon must survive: relay unreachable (queue, jittered backoff), restart (`reset`), revoke (`410` → remove hooks and keys, print why), skew (`401` → adopt `Date`) |
| §14 | Phasing: this repository's first milestone is phase 2 (tunnel + pair), then 3 (wake), then 4 (hardening: SSE fallback, quota telemetry, rate limits) |
| §15 | Open: Windows install shape (after macOS/Linux); whether the QR may name any relay |

## Numbers that are *draft*

Queue bounds, mailbox caps, TTL clamps, the charging/unmetered stream policy and the 5-min
`soon` coalescing are starting points (RELAY.md's status line). Put each behind one named
constant with a comment citing the section, so they change in one place when they move.
