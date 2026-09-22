---
id: "2026-09.vnj9"
slug: tests-are-the-standard-library-and-golden-vectors
title: "Tests are the standard library and golden vectors, not an assertion framework"
date: 2026-09-21
topics: [testing, toolchain]
---

# ADR 2026-09.vnj9 — Tests are the standard library and golden vectors, not an assertion framework

Status: Accepted (2026-09-21; `make test`, `.agents/rules/testing.md`)

**What was observed.** The agent's correctness claim is narrow and exact: it reproduces
`:shared/relay`'s golden vectors *byte for byte* — the HKDF derivation, the AAD layout, the
envelope — and it must implement `RELAY.md`, not the phone's code (RELAY.md §5.5). Almost
every test that matters is therefore "these bytes equal those bytes" or "this table of inputs
produces this table of outputs", and the failure a reader needs is a hex dump, not a prose
assertion. The Kotlin side reached the same shape with `RelayVectorsTest` and knit-next's
`ScopeVectorTest`.

**What changed.** Tests are `package testing` as shipped: table tests, `t.Run` subtests,
`t.Parallel()` by default (enforced by `tparallel`), `t.TempDir()` over hand-rolled temp
paths (`usetesting`), and `go test -race -shuffle=on -count=1` as the only invocation
(`make test`). Golden vectors are checked-in files compared with `bytes.Equal` and reported
with `%x`. Nothing is asserted through a library.

The alternative a reader reaches for first is `testify`: `assert.Equal` reads well and
prints a diff. It was not taken because it adds a dependency to a module whose entire
dependency posture is "stdlib plus `golang.org/x/crypto`" (RELAY.md §5.5, ADR 2026-09.kau2),
its diff output for `[]byte` is worse than `%x`, and its `assert` (non-fatal) vs `require`
(fatal) split is a second thing every test author has to get right. Ginkgo/Gomega were
never candidates: a BDD DSL over a daemon with no behaviour to specify in prose. `go-cmp` is
the one library worth its cost — a structural diff of two nested values — and it is added
on the day a test needs one (through `depguard`'s allow-list, with the reason in that
commit), not speculatively.

**What it costs.** Table tests are more typing than an assertion chain, and a wrong
expectation reads as `got X, want Y` rather than a coloured diff. The trap is a test that
compares two structs with `!=` or `reflect.DeepEqual` and prints them with `%v`, which for
anything nested is unreadable: reach for `%+v` first, and if that is still not enough, that
is the day `go-cmp` earns its row. What keeps this true: `depguard` refuses any import
outside the allow-list, so a `testify` import fails `make lint` rather than sliding in.
