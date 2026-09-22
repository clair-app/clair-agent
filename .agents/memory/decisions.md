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
| [2026-09.kau2](decisions/2026-09-kau2-static-analysis-is-one-pinned-golangci-lint-with-an-explicit-linter-set-and-a.md) | Static analysis is one pinned golangci-lint with an explicit linter set and a dependency allow-list | toolchain, lint, dependencies |
| [2026-09.vnj9](decisions/2026-09-vnj9-tests-are-the-standard-library-and-golden-vectors.md) | Tests are the standard library and golden vectors, not an assertion framework | testing, toolchain |
