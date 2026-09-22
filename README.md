# clair agent

`clair` is the host-side agent of [Clair](../clair), a Wear OS / phone companion for Claude
Code. It runs on the dev machine as a user-level daemon, receives Claude Code's `http` hooks on
`127.0.0.1:7317`, and tunnels them — end-to-end encrypted — through a blind relay to the phone.
The relay and Google's push infrastructure only ever see ciphertext.

The design is `docs/RELAY.md` in the `clair` repository. This repository is the Go
implementation of its "agent" half; the relay (`clair-relay`) is separate.

**Status:** project scaffolding. `clair version` is the only command.

## Development

Requires Go 1.26 and `make`.

```sh
make tools      # once per clone: pinned golangci-lint + govulncheck into ./bin
make check      # tidy, format, lint, test (-race), govulncheck, ADR router — the CI gate
make build      # ./bin/clair
make hooks      # opt in to .githooks (pre-commit ADR router check)
make help       # every target
```

CI (`.gitlab-ci.yml`) runs the same `make` targets, so a red job reproduces locally with one
command.

### Layout

| Path | What |
| --- | --- |
| `cmd/clair/` | The binary. Thin: parse, dispatch, exit. |
| `internal/` | Everything else, as it is written; no importable API. |
| `tools/adr/` | Mints and indexes architecture decision records. |
| `.agents/` | Context for coding agents — rules, reference, decisions. `AGENTS.md` is the router. |
| `.githooks/` | Opt-in git hooks (`make hooks`). |

### Decisions

Architecture decisions are one file each in `.agents/memory/decisions/`, indexed by the
generated `.agents/memory/decisions.md`. Add one with
`go run ./tools/adr new "<title>" -topics a,b`, write the body, then
`go run ./tools/adr index`. Ids are `YYYY-MM.suffix`, minted at random, so parallel worktrees
never collide on a number.
