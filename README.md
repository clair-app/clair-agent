# clair agent

`clair` is the host-side agent of [Clair](../clair), a Wear OS / phone companion for Claude
Code. It runs on the dev machine as a user-level daemon, receives Claude Code's `http` hooks on
`127.0.0.1:7317`, and tunnels them — end-to-end encrypted — through a blind relay to the phone.
The relay and Google's push infrastructure only ever see ciphertext.

The design is `docs/RELAY.md` in the `clair` repository. This repository is the Go
implementation of its "agent" half; the relay (`clair-server`) is separate.

**Status:** the tunnel and pairing are implemented and proven end to end against an in-process
fake relay and a fake phone (`internal/daemon/e2e_test.go`), and as real processes with
`tools/relaysim` and `tools/phonesim`. Not yet: OS service installation, `install.sh`, releases —
run `clair daemon` in a terminal for now — and the Android side of the relay.

```text
clair daemon      serve Claude Code's hooks on loopback and tunnel them to the phone
clair pair        show a QR for the phone to scan; write the pair and the hooks
clair unpair      revoke the pair, remove the hooks and the keys
clair status      what the running agent is doing
clair statusline  the statusLine command settings.json points at
clair version
```

Config lives under `os.UserConfigDir()/clair` (`~/.config/clair` on Linux; `CLAIR_CONFIG_DIR`
overrides): `agent.json` (the loopback bearer, the admin token, the relay URL), `host.key`, and
one `pairs/<id>.json` per pair. Flags: `-config-dir`, `-log-level`, `-relay`, `-relay-ca`;
`clair pair` adds `-qr unicode|ascii|none`, `-invert`, `-replace`, `-yes`.

## Development

Requires Go 1.26 and `make`.

```sh
make tools      # once per clone: pinned golangci-lint + govulncheck into ./bin
make check      # tidy, format, lint, test (-race), govulncheck, ADR router — the CI gate
make build      # ./bin/clair
make build-all  # linux/darwin/windows × amd64/arm64 into ./dist
make hooks      # opt in to .githooks (pre-commit ADR router check)
make help       # every target
```

CI (`.gitlab-ci.yml`) runs the same `make` targets, so a red job reproduces locally with one
command. `.agents/context/commands.md` shows how to run daemon, pairing and a simulated phone
together without a real relay.

### Layout

| Path | What |
| --- | --- |
| `cmd/clair/` | The binary. Thin: parse, dispatch, exit. |
| `internal/envelope`, `identity`, `record` | The wire core: keys, sealing, replay counters, tunnel records (RELAY.md §4.1, §5). |
| `internal/relay` (+ `relaytest`) | The relay client: signed requests, SSE streams, batched uploads; an in-memory fake for tests. |
| `internal/hookserver`, `tunnel`, `state`, `daemon`, `ctl` | The daemon: the loopback contract, the per-pair FIFO and held decides, the config directory, the control surface. |
| `internal/claudecfg`, `ojson`, `pairing`, `hostname` | `clair pair` / `unpair`: the QR, the settings.json merge, the statusline shim. |
| `tools/adr`, `tools/phonesim`, `tools/relaysim` | Developer tools: decision records, a phone stand-in, the fake relay on a port. |
| `.agents/` | Context for coding agents — rules, reference, decisions. `AGENTS.md` is the router. |

### Decisions

Architecture decisions are one file each in `.agents/memory/decisions/`, indexed by the
generated `.agents/memory/decisions.md`. Add one with
`go run ./tools/adr new "<title>" -topics a,b`, write the body, then
`go run ./tools/adr index`. Ids are `YYYY-MM.suffix`, minted at random, so parallel worktrees
never collide on a number.
