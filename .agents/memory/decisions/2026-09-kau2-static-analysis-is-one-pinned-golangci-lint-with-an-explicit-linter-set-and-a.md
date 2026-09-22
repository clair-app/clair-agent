---
id: "2026-09.kau2"
slug: static-analysis-is-one-pinned-golangci-lint-with-an-explicit-linter-set-and-a
title: "Static analysis is one pinned golangci-lint with an explicit linter set and a dependency allow-list"
date: 2026-09-21
topics: [toolchain, lint, dependencies]
---

# ADR 2026-09.kau2 — Static analysis is one pinned golangci-lint with an explicit linter set and a dependency allow-list

Status: Accepted (2026-09-21; `Makefile`, `.golangci.yml`, `.gitlab-ci.yml`)

**What was observed.** The Go ecosystem's static analysis is a dozen separately versioned
tools (`vet`, `staticcheck`, `gosec`, `revive`, `gocritic`, the `modernize` analyzers, two
formatters) and the classic failure is that every machine runs a different subset at a
different version: a clean local run, a red CI job, and an hour spent discovering that the
runner's `golangci-lint` is two minors ahead and picked up a linter nobody enabled. The
sibling Kotlin repository hit the same shape and answered it with detekt/ktlint pinned as
Gradle plugins (knit-next ADR 007 / 011). This module also has a dependency posture to
defend — RELAY.md §5.5: the agent is stdlib plus `golang.org/x/crypto`, and nothing is
shared with the relay — and "please don't add a dependency" in a rules file is not a gate.

**What changed.**

1. **One runner, one version, one place.** `golangci-lint` v2 and `govulncheck` are pinned
   in the `Makefile` and installed by `go install …@version` into `./bin` (gitignored), never
   read from `$GOPATH/bin`. A stamp file per (tool, version) makes a bumped pin reinstall.
   CI's before-script is `make tools`, so the runner lints with the same binary a clone does,
   and every CI job is a `make` target so a red job reproduces with one local command.
2. **The linter set is explicit.** `.golangci.yml` says `default: none` and lists every
   enabled linter, so a golangci-lint upgrade cannot enable something new on its own; a
   linter is added with a reason. Left out on purpose: the complexity meters (`cyclop`,
   `funlen`, `gocognit`, `nestif`), magic-number and line-length policing (`mnd`, `lll`),
   and the pure-style sets (`wsl`, `nlreturn`, `varnamelen`) — for a small daemon they were
   judged more noise than signal. `govet` runs with `enable-all` including `shadow`, which is
   why gocritic's `sloppyReassign` is disabled: the two contradict on `if err = …` and
   `shadow` is the one that finds bugs. Formatting is `gofumpt` + `goimports` through the
   same binary (`make fmt` / `make fmt-check`), so there is no second formatter version.
3. **Dependencies are an allow-list.** `depguard` in `list-mode: strict` permits `$gostd`,
   this module and `golang.org/x/…` and refuses everything else. Adding a dependency is an
   edit to that list, which puts the reason in a reviewable diff instead of a `go.sum` churn
   nobody reads.

The alternative for pinning was Go 1.24's `tool` directive (`go get -tool …; go tool
golangci-lint`), which records the version in `go.mod` itself. It was not taken because it
merges golangci-lint's several-hundred-module dependency graph into this module's `go.sum`
and its `go mod tidy`, and golangci-lint's own documentation advises against it for exactly
that reason. A separate `tools/go.mod` module would avoid the merge and was judged one
module too many for two binaries the Makefile already pins.

**What it costs.** A fresh clone needs `make tools` (≈ 1 min, cached thereafter) before
`make lint` works, and the first `go install` of golangci-lint compiles ~57 MB. The explicit
list means a genuinely useful new linter is not picked up until someone reads a release
note. The trap: a stale `./bin` after a pin bump is handled by the stamp, but a *hand*
installed `golangci-lint` earlier on `$PATH` is not — the Makefile always invokes
`./bin/golangci-lint` by path, so use `make lint`, not the bare command. What keeps this
true: CI runs the same targets, and `.agents/context/commands.md` lists them as the
finishing checks.
