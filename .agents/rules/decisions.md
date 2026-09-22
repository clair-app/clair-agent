# Decisions

When an ADR must be read, and how a new one is recorded. Routed from
[`AGENTS.md`](../../AGENTS.md): match the trigger table before touching code, and read the
whole file before recording an architectural choice.

## When to read one

Every row names a **trigger** and a **file**. Follow the rows that match the task; skip the
rest. The traps are recorded in the routed files, not here — if a trigger starts growing
an explanation, that explanation belongs in the ADR.

| If touching | READ |
| --- | --- |
| `go.mod`, `.golangci.yml`'s `depguard` allow-list or linter list, the tool pins in the `Makefile`, or reaching for a library the standard library could replace | [ADR 2026-09.kau2](../memory/decisions/2026-09-kau2-static-analysis-is-one-pinned-golangci-lint-with-an-explicit-linter-set-and-a.md) |
| a `_test.go` that wants `testify`, `gomega` or `go-cmp`, or a golden vector that "needs a small fix" | [ADR 2026-09.vnj9](../memory/decisions/2026-09-vnj9-tests-are-the-standard-library-and-golden-vectors.md) |
| `internal/relay` — a transport, the auth header, stream reconnection, or the idea of a WebSocket | [ADR 2026-09.khcq](../memory/decisions/2026-09-khcq-the-agent-speaks-sse-down-and-post-up-only.md) |
| the QR payload, its rendering, or `rsc.io/qr` | [ADR 2026-09.zhzc](../memory/decisions/2026-09-zhzc-the-qr-is-rendered-with-rsc-io-qr-and-drawn-in-half-blocks-by-the-agent.md) |
| `n`, `h2pNext`, `p2hLast`, the mailbox cursor, or a pair file's counters | [ADR 2026-09.hzwt](../memory/decisions/2026-09-hzwt-the-replay-counter-survives-restarts-by-block-reservation.md) |
| `/clair/ctl`, the admin token, the hookserver guard order, or who writes a pair file | [ADR 2026-09.r7kd](../memory/decisions/2026-09-r7kd-the-control-surface-shares-the-loopback-listener-under-clair-ctl-with-its-own.md) |
| `settings.json`, the hooks block, `statusLine`, or `internal/ojson` | [ADR 2026-09.evep](../memory/decisions/2026-09-evep-the-agent-edits-settings-json-through-an-order-preserving-json-object-and.md) |
| what a phone snippet may install | [ADR 2026-09.3gre](../memory/decisions/2026-09-3gre-a-phone-snippet-may-only-shape-the-agent-s-own-http-hooks.md) |

Add a row when an ADR guards something a future edit is likely to touch; not every ADR
needs one.

## How to record one

1. `go run ./tools/adr new "<the decision, as a sentence>" -topics a,b` (or
   `make adr-new TITLE="…" TOPICS=a,b`). The id is minted for you — `YYYY-MM.suffix`,
   random — so parallel worktrees cannot collide. Never pick one by hand.
2. Write the body in the scaffold's shape: **what was observed** (numbers where there are
   numbers), **what changed** and the alternative a reader would reach for first, **what
   it costs** and the test, gate or invariant that keeps it true.
3. `go run ./tools/adr index` regenerates `.agents/memory/decisions.md`. Never hand-edit
   it. Commit the ADR and the router together — `.githooks/pre-commit` (`make hooks`)
   refuses a commit where they disagree, and CI's `adr-index` job is the backstop.
4. Cite it as `ADR 2026-09.k3f9` in code comments and commit messages; the heading line in
   the file is the grep anchor.
5. Supersede by writing a new ADR and changing the old one's `Status:` line — never by
   deleting or renumbering.

A decision the *phone* side owns (the wire format, the hook contract, the relay API) is
recorded in the `clair` repository's ADRs; this repository's ADRs are about the agent.
