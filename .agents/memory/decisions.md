# Architecture decision records

The load-bearing decisions and *why* they hold, so future work stays consistent. One
file each, in [`decisions/`](decisions/) — this page is the router. Open the file whose
row matches; don't guess from the title alone. Supersede by writing a new ADR and
changing the old one's `Status:` — never by deleting it.

**This file is generated. Do not edit it by hand.** Add a decision with
`go run ./tools/adr new "<title>" -topics a,b`, write the body, then
`go run ./tools/adr index` (`make adr-index`).

**Ids are `YYYY-MM.suffix`** (`ADR 2026-09.k3f9`), minted at random from day one. A
sequence number is itself a merge conflict — parallel worktrees all read the same "next
number" and all take it — so nobody picks one. Cite the id an ADR carries; never renumber.

| ADR | Decision | Topics |
| --- | --- | --- |
| [2026-09.34qh](decisions/2026-09-34qh-the-agent-reads-terminal-input-idle-time-itself-and-releases-a-bubbled-decide.md) | The agent reads terminal input idle time itself and releases a bubbled decide to the terminal while someone is at it | presence, hooks, tunnel |
| [2026-09.3gre](decisions/2026-09-3gre-a-phone-snippet-may-only-shape-the-agent-s-own-http-hooks.md) | A phone snippet may only shape the agent's own http hooks | hooks, security |
| [2026-09.evep](decisions/2026-09-evep-the-agent-edits-settings-json-through-an-order-preserving-json-object-and.md) | The agent edits settings.json through an order-preserving JSON object and installs clair statusline in place of the shell shim | hooks, claudecfg |
| [2026-09.hzwt](decisions/2026-09-hzwt-the-replay-counter-survives-restarts-by-block-reservation.md) | The replay counter survives restarts by block reservation; the mailbox cursor is not persisted | protocol, state |
| [2026-09.kau2](decisions/2026-09-kau2-static-analysis-is-one-pinned-golangci-lint-with-an-explicit-linter-set-and-a.md) | Static analysis is one pinned golangci-lint with an explicit linter set and a dependency allow-list | toolchain, lint, dependencies |
| [2026-09.khcq](decisions/2026-09-khcq-the-agent-speaks-sse-down-and-post-up-only.md) | The agent speaks SSE down and POST up only; streams are bounded and resumed by cursor | relay, transport, protocol |
| [2026-09.r7kd](decisions/2026-09-r7kd-the-control-surface-shares-the-loopback-listener-under-clair-ctl-with-its-own.md) | The control surface shares the loopback listener under /clair/ctl with its own token, and a pair file has one writer | daemon, state, cli |
| [2026-09.vnj9](decisions/2026-09-vnj9-tests-are-the-standard-library-and-golden-vectors.md) | Tests are the standard library and golden vectors, not an assertion framework | testing, toolchain |
| [2026-09.zhzc](decisions/2026-09-zhzc-the-qr-is-rendered-with-rsc-io-qr-and-drawn-in-half-blocks-by-the-agent.md) | The QR is rendered with rsc.io/qr and drawn in half-blocks by the agent | pairing, dependencies |
