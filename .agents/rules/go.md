# Go rules

Invariants for every Go file in this module. The *why* behind the tooling ones is in
ADR 2026-09.kau2; the design constraints come from `RELAY.md` (see `context/design.md`).

## Layout

- `cmd/clair/` is the binary and stays thin: flag parsing and dispatch into `internal/`.
  `main` is `os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))` so the dispatch is tested
  in-process. Nothing else lives in `package main`.
- Everything else is under `internal/` — this module exposes no importable API, and the
  compiler enforces it. One package per concern, named for what it holds (`relay`,
  `tunnel`, `pairing`), never `util`, `common` or `helpers`.
- `tools/` holds developer tools; they are `go run`, never shipped. `tools/adr` and
  `tools/machocheck` are stdlib-only; `tools/phonesim` and `tools/relaysim` may import `internal/` and
  `golang.org/x`, because they *are* the far end of the protocol.
- OS-specific code goes behind build tags (`_linux.go`, `_darwin.go`, `_windows.go`), and
  `make build-all` must keep compiling for all six targets in the Makefile. `make lint`
  lints each OS's files, tests included, from any host.

## Dependencies

- Standard library first. `golang.org/x/crypto` is the one named exception (RELAY.md
  §5.5); the rest of `golang.org/x/` is allowed on the same stewardship.
- Anything else is refused by `depguard` until it is added to the allow-list in
  `.golangci.yml` — that edit is the review surface, and the commit says why the standard
  library was not enough. Then `make tidy`. Never vendor.
- No `init()` (`gochecknoinits`), no package-level mutable state; a package-level
  `regexp.MustCompile` or a linker-set `var version` is fine.

## Errors and control flow

- Wrap with context: `fmt.Errorf("open keyfile: %w", err)`. Sentinels are
  `var ErrX = errors.New(…)` and callers test with `errors.Is` / `errors.AsType`.
- Errors are handled where they occur or returned, never both, and never logged-and-returned.
- `panic` only for a programmer error that cannot happen at runtime (a bad constant); a
  daemon that panics on input is a bug.
- `context.Context` is the first parameter of anything that blocks, dials, or sleeps.
  `context.Background()` appears in `main` and tests only.
- Every goroutine has an owner that can stop it and a documented reason to exist. The
  race detector (`make test`) is the judge; a data race is a bug even if it "can't matter".
- A phone-supplied snippet may only shape the agent's own `http` hooks (ADR 2026-09.3gre):
  never write a `command` hook from anything the phone sent, and never write a phone's hook
  object as sent — rebuild it from the agent's template, each event pinned to its endpoint
  (ADR 2026-09.ut2g).
- A phone's decide answer never reaches Claude Code as sent: `internal/hookout` checks it
  against the request and rebuilds it (ADR 2026-09.w4ww).

## The tunnel is blind — a domain rule

- The agent reads **two** plaintext fields of a hook, both top-level strings and both for
  one decision each: `hook_event_name` chooses the wake hint (RELAY.md §4, §7.5) and
  `permission_mode` tells a background subagent's decide, which is released to the terminal
  while someone is at it (§4.3, ADR 2026-09.34qh). It never inspects, transforms or branches
  on any other part of a hook body. If a change needs a third, that is a design change: an
  ADR first. Two nuances: the loopback server checks that `session_id` is *present* — the
  phone's 400 rule, so a hook the phone would drop fails fast instead of hanging a decide —
  and never reads it; and when the phone *answers* a decide, `internal/hookout` reads the
  held request's `tool_name`, `tool_input` and `permission_suggestions` to check the answer
  against it (ADR 2026-09.w4ww) — never before, never logged, never changing what is tunnelled.
- Presence is sampled in-process (`internal/presence`: pty access times, `GetLastInputInfo`)
  and only when a hook arrives or a decide is held — the tunnel's watcher ticks, but samples
  nothing while nothing is held. Never a `command` hook, never a helper binary.
- **Never log plaintext.** Hook bodies are tool inputs, commands, file paths and plans.
  Log sizes, ids (`reqId`, envelope `id`), paths and hints — never `body`, never a key,
  never `k`. Use `log/slog` with static messages and `snake_case` keys (`sloglint`).
- Cryptography comes from `crypto/*` and `golang.org/x/crypto` only, with the constants and
  layouts exactly as RELAY.md §5 writes them; randomness is `crypto/rand`. Key files are
  written `0600` under `os.UserConfigDir()`.

## Style

- `make fmt` (gofumpt + goimports) owns formatting; never format by hand and never argue
  with it. Doc comments on every exported identifier (`revive exported`), full sentences
  ending in a period (`godot`), a package comment per package.
- `//nolint:<linter> // <reason>` — specific linter, reason mandatory (`nolintlint`). A
  bare `//nolint` is refused.
- Prefer the modern form the `modernize` analyzer suggests (`range n`, `min`/`max`,
  `slices`/`maps`, `strings.SplitSeq`, `errors.AsType`); this is a Go 1.26 module.
- Comments explain *why*, match the density of the surrounding code, and name the ADR or
  RELAY.md section a non-obvious constant comes from.
