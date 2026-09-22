# Commands

Everything is a `make` target, and CI (`.gitlab-ci.yml`) runs the same targets, so a red
job reproduces locally with one command. `make help` lists them.

## The finishing gate

**`make check`** — run before calling any change done. It is, in the order that fails
fastest:

| Target | What it proves |
| --- | --- |
| `tidy-check` | `go.mod` / `go.sum` are tidy (`go mod tidy -diff`) |
| `fmt-check` | gofumpt + goimports would change nothing (`make fmt` fixes) |
| `lint` | `.golangci.yml` is clean — vet, staticcheck, gosec, revive, gocritic, modernize, depguard … |
| `test` | `go test -race -shuffle=on -count=1` over every package; coverage in `coverage.out` |
| `vuln` | `govulncheck`: no known vulnerability reachable from this module (advisory in CI, blocking here) |
| `adr-check` | `.agents/memory/decisions.md` matches the ADR files |

Then `make build` and `bin/clair version` if the change touches `cmd/clair` or the
linker-injected version.

## Everything else

| Target | Purpose |
| --- | --- |
| `make tools` | Install the pinned `golangci-lint` and `govulncheck` into `./bin` (once per clone, and after a pin bump) |
| `make build` | `./bin/clair` for this host — static, `-trimpath`, version from `git describe` |
| `make build-all` | Cross-compile linux/darwin/windows × amd64/arm64 into `./dist` |
| `make run ARGS="version"` | `go run ./cmd/clair …` |
| `make fmt` | Rewrite sources with gofumpt + goimports |
| `make tidy` | `go mod tidy` |
| `make cover` | Open the HTML coverage report from the last `make test` |
| `make adr-new TITLE="…" TOPICS=a,b` | Scaffold a decision (`go run ./tools/adr new`) |
| `make adr-index` | Regenerate the ADR router (`go run ./tools/adr index`) |
| `make hooks` | `git config core.hooksPath .githooks` — opt this clone into the pre-commit ADR check |
| `make clean` | Remove `dist/`, `coverage.out`, `bin/clair` (keeps the tools) |

## Direct invocations that are fine

- `go test ./internal/relay/ -run TestVectors -v` while iterating; finish with `make test`.
- `go run ./cmd/clair version`.
- `bin/golangci-lint run ./internal/relay/` for one package — but always the `./bin` copy,
  never a `golangci-lint` from `$PATH` (a different version lints differently).
