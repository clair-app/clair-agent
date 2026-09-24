# Toolchain

What is pinned, where, and how to change it. The reasoning is ADR 2026-09.kau2.

## Go

- `go.mod` says `go 1.26` — the minor only, so any 1.26.x toolchain builds it and nothing
  auto-downloads. CI uses the `golang:1.26` image with `GOTOOLCHAIN=local` for the same
  reason. Bumping the minor is a deliberate edit to both.
- Module path `claircode.app/clair-agent` — a vanity path under the product's domain
  (the phone app is `app.claircode.clair`), independent of where the repository is
  hosted. It does not resolve today and does not need to: the install path is
  `curl -fsSL https://claircode.app/install.sh | sh` (and `install.ps1` on Windows), not
  `go install` (ADR 2026-09.zvs8). If that ever changes, the domain serves a
  `go-import` meta tag.
- Builds are `CGO_ENABLED=0 -trimpath -ldflags '-s -w -X main.version=… -X main.commit=…
  -X main.date=…'` (Makefile): one static binary per platform, no build path in panics.
  `main.date` is the commit's time, so a commit and a Go version fix the bytes.
  A plain `go build` still works; `cmd/clair` falls back to `debug.ReadBuildInfo()` for
  the version and VCS revision.

## Tools (`./bin`, gitignored)

| Tool | Pin | Installed by |
| --- | --- | --- |
| `golangci-lint` v2 | `GOLANGCI_LINT_VERSION` in the Makefile | `go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@<pin>` |
| `govulncheck` | `GOVULNCHECK_VERSION` in the Makefile | `go install golang.org/x/vuln/cmd/govulncheck@<pin>` |

`make tools` installs both; a stamp file `bin/.<tool>@<version>` records what is there,
so changing a pin reinstalls on the next `make lint` / `make vuln`. Nothing is read from
`$GOPATH/bin`, and the Makefile always calls `./bin/<tool>` by path. To bump: change the
pin, `make tools`, `make check`, read the linter's release notes for anything newly
enabled or deprecated (the config is explicit, so nothing enables itself), commit.

## Linting (`.golangci.yml`)

- `version: "2"`; `linters.default: none` and an explicit `enable` list, grouped by
  purpose with the deliberately-omitted linters named in the header comment. Add a linter
  with a reason in the commit.
- `govet` is `enable-all` (minus `fieldalignment`) including `shadow`; gocritic's
  `sloppyReassign` is disabled because it contradicts `shadow`.
- Formatters (`gofumpt` with grouped params, `goimports` with this module as the local
  prefix) run through the same binary: `make fmt` / `make fmt-check`.
- Exclusions are few and named: tests may ignore `Close` errors and use fixed file modes;
  `tools/` writes repo files at `0644`/`0755`.
- `make lint` runs once per `GOOS` in `LINT_OSES` (linux, darwin, windows), whatever the
  host. golangci-lint loads only the files the build tags select, so a single run would
  never type-check a `_windows.go` file or a `_darwin_test.go` on a Linux machine or in CI.

## Dependencies (`depguard`)

`list-mode: strict` with `$gostd`, this module, `golang.org/x` and `rsc.io/qr` allowed.
What is in `go.mod` and why:

| Module | Used by | Why the standard library was not enough |
| --- | --- | --- |
| `golang.org/x/crypto` | `internal/envelope` (`chacha20poly1305.NewX`) | XChaCha20-Poly1305 is not in `crypto/*` (RELAY.md §5.3) |
| `golang.org/x/term` | `internal/pairing` (`IsTerminal`) | telling a controlling terminal from a pipe |
| `rsc.io/qr` | `internal/pairing` | no QR encoder in the standard library (ADR 2026-09.zhzc) |
| `golang.org/x/sys` | `internal/claudecfg` on Windows (`LockFileEx`); also via `x/crypto` | `syscall` has no `LockFileEx` for the `settings.json` lock (ADR 2026-09.y34x) |

To add one:

1. Be sure the standard library cannot do it (RELAY.md §5.5 is the posture: stdlib plus
   `x/crypto`, nothing shared with the relay).
2. `go get <module>@<version>`, add its path to the `allow` list in `.golangci.yml`,
   `make tidy`, `make check`.
3. The commit message says what the standard library lacked. A significant one (a
   WebSocket client, a QR encoder) is an ADR.

## CI (`.gitlab-ci.yml`)

Stages `check` → `build`; jobs `adr-index`, `format`, `lint`, `test` (coverage scraped
from `go tool cover -func`), `vuln` (allow_failure: advisory until the agent handles keys)
and `build` (host binary, `clair version`, then `make build-all` as artifacts, which ends
with `tools/machocheck` verifying the darwin builds' code signatures). A `vX.Y.Z` tag
adds `release`: `make dist` and an upload to the generic package registry (ADR 2026-09.zvs8). Module and
build caches plus `./bin` are cached on `go.sum` + `Makefile`. Runs on merge requests, the
default branch and tags.

GitLab has no macOS runner, so `.github/workflows/macos.yml` runs on
`github.com/clair-app/clair-agent`, a private push mirror of this project (GitLab a remote mirror,
over SSH with a deploy key). It runs `make test` on darwin, the LaunchAgent for real, and
claircode.app's `install.sh`. Push to GitLab, never to the mirror; results show on GitHub only.

## Git hooks (`.githooks/`)

Opt in with `make hooks`. `pre-commit` extracts the *staged* ADR files and router to a
temp tree and runs `go run ./tools/adr -C <tmp> index -check` there — so it catches a
router that was regenerated but not staged, and costs nothing on a commit that touches no
ADR. `--no-verify` skips it once; CI's `adr-index` job does not.
