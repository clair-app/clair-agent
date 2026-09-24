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
| `make dist VERSION=vX.Y.Z` | `build-all` for a release: checks the stamped version, writes `dist/SHA256SUMS.txt`. The tag pipeline runs it and uploads the result (ADR 2026-09.zvs8) |
| `make run ARGS="version"` | `go run ./cmd/clair …` |
| `make fmt` | Rewrite sources with gofumpt + goimports |
| `make tidy` | `go mod tidy` |
| `make cover` | Open the HTML coverage report from the last `make test` |
| `make adr-new TITLE="…" TOPICS=a,b` | Scaffold a decision (`go run ./tools/adr new`) |
| `make adr-index` | Regenerate the ADR router (`go run ./tools/adr index`) |
| `make hooks` | `git config core.hooksPath .githooks` — opt this clone into the pre-commit ADR check |
| `make clean` | Remove `dist/`, `coverage.out`, `bin/clair` (keeps the tools) |

## Direct invocations that are fine

- `go test ./internal/envelope/ -run TestVectors -v` while iterating; finish with `make test`.
- `go test ./internal/daemon/ -run TestEndToEnd -race -v` — fake Claude Code → daemon → fake
  relay → fake phone, in one process.
- `go run ./cmd/clair service install -print` — the unit / plist / task XML this host would
  register, changing nothing. The goldens for all three OSes are `internal/service/testdata`
  and are compared byte for byte; a rendering change updates them deliberately.
- `go run ./cmd/clair version`, `make run ARGS="daemon -log-level debug"`.
- `bin/golangci-lint run ./internal/relay/` for one package — but always the `./bin` copy,
  never a `golangci-lint` from `$PATH` (a different version lints differently).

## Cutting a release

1. `make check` on the commit, then `git tag vX.Y.Z && git push origin vX.Y.Z`.
2. The tag pipeline's `release` job uploads the builds and `SHA256SUMS.txt` to
   `packages/generic/clair/vX.Y.Z/`.
3. In clair-web, `node scripts/agent-release.mjs pin vX.Y.Z` hashes the uploaded files into
   `agent-release.json`. Never pin from a local `dist/`: the build time is stamped in, so a
   local build never matches the uploaded bytes.

## Running the whole thing without a phone or a relay

Point both config directories at scratch space so nothing of yours is touched:

```sh
export CLAIR_CONFIG_DIR=/tmp/clair-scratch CLAUDE_CONFIG_DIR=/tmp/claude-scratch
go run ./tools/relaysim -listen 127.0.0.1:3000            # the fake relay, on a port
go run ./cmd/clair daemon -relay http://127.0.0.1:3000     # in a second terminal
go run ./cmd/clair pair -qr none                           # prints a link; leave it waiting
go run ./tools/phonesim -v '<the link>'                    # the "phone": completes the pairing, answers decides
go run ./tools/phonesim -idle-threshold 30 '<the link>'    # …asking for a 30 s presence threshold (0: never release to the terminal)
go run ./cmd/clair status
curl -X POST -H "Authorization: Bearer $(jq -r .token $CLAIR_CONFIG_DIR/agent.json)" \
  --data '{"session_id":"s","hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"ls"}}' \
  'http://127.0.0.1:7317/clair/v1/hook/decide?timeout=30'   # → the phone's hookSpecificOutput, HTTP 200
go run ./cmd/clair unpair
```

To try the service the same way: with the scratch variables still exported,
`clair daemon -listen 127.0.0.1:7417 -relay http://127.0.0.1:3000` once (it writes `agent.json`;
Ctrl-C it) so the unit does not take a real agent's port, then `make build` and
`bin/clair service install` (a `go run` binary is refused, so it must be a built one). Then
`clair pair` / `phonesim` as above, `journalctl --user -u clair`, `bin/clair service status`, and
`bin/clair service uninstall` at the end. The unit is real (`~/.config/systemd/user/clair.service`),
so uninstall it before switching back to your own config.

Against a real relay, drop `relaysim` and pass its URL to `-relay`; `tools/phonesim` still
plays the phone until the Android `RelayIngress` exists. `CLAUDE_CONFIG_DIR` is Claude Code's
own variable: with it set, a real `claude` session in a scratch project picks up the written
hooks.
