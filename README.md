# clair agent

`clair` is the host-side agent of [Clair](https://claircode.app), a Wear OS / phone companion for Claude
Code. It runs on the dev machine as a user-level daemon, receives Claude Code's `http` hooks on
`127.0.0.1:7317`, and tunnels them — end-to-end encrypted — through a blind relay to the phone.
The relay and Google's push infrastructure only ever see ciphertext.

The design is `docs/RELAY.md` in the `clair` repository. This repository is the Go
implementation of its "agent" half; the relay (`clair-server`) is separate.

**Status:** the tunnel and pairing are implemented and proven end to end against an in-process
fake relay and a fake phone (`internal/daemon/e2e_test.go`), and as real processes with
`tools/relaysim` and `tools/phonesim`. A background subagent's permission prompt in an interactive
session — which Claude Code shows in the terminal only once the hook lets go — is handed to the
terminal at once while someone is typing at one, and held for the watch otherwise (RELAY.md §4.3;
the daemon reads terminal input idle the way `w` does, no helper, no extra hook). A `claude -p`
run's prompt is always held for the watch, since no terminal would show it. `clair service install` runs the
daemon as your login service (verified on Linux and macOS; the Windows half is written and
tested, not yet run at a signed-in desktop). A `vX.Y.Z` tag publishes the builds to the package registry,
and claircode.app's `install.sh` / `install.ps1` serve them (ADR 2026-09.zvs8). After that the
agent keeps itself current. About every six hours it checks claircode.app, verifies a new release's
signature against the keys built into it, and puts the new binary where the old one is. The new
binary runs from the agent's next start (ADR 2026-09.qk6v). Not yet: the Android side of the relay.

```text
clair daemon      serve Claude Code's hooks on loopback and tunnel them to the phone
clair pair        show a QR for the phone to scan; write the pair and the hooks
clair unpair      revoke the pair, remove the hooks and the keys
clair status      what the running agent is doing
clair service     install, start, stop or remove the daemon as a login service
clair update      install the newest release now (-check only looks)
clair statusline  the statusLine command settings.json points at
clair version
```

Config lives under `os.UserConfigDir()/clair` (`~/.config/clair` on Linux; `CLAIR_CONFIG_DIR`
overrides): `agent.json` (the loopback bearer, the admin token, the relay URL; `"autoUpdate":
false` stops the background update check), `host.key`, and one `pairs/<id>.json` per pair. Flags: `-config-dir`, `-log-level`, `-relay`, `-relay-ca`;
`clair pair` adds `-qr unicode|ascii|none`, `-invert`, `-replace`, `-yes`.

## Running as a service

`clair service install` registers **this binary, where it is**, as a service of the current user
and starts it: a systemd user unit on Linux (logs: `journalctl --user -u clair`), a LaunchAgent
on macOS, and a Scheduled Task on Windows that starts at logon under `conhost --headless`, with the
daemon under a small supervisor of its own that restarts it after a crash (logs:
`daemon.log` under `~/Library/Logs/clair` or `%LocalAppData%\clair`). It is never a system
service, because the daemon reads the user's own terminal input idle.

Put the binary somewhere it will stay before installing. `CLAUDE_CONFIG_DIR` and the proxy
variables are captured from the installing shell. `clair service status` shows the state and the
log location, `-print` shows what would be registered, and `clair service uninstall` removes it,
leaving the pair and the hooks to `clair unpair`. ADR 2026-09.ahq8 records why.

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
| `internal/service`, `logfile` | `clair service`: the systemd unit, LaunchAgent and Scheduled Task; the daemon's own rotated log. |
| `tools/adr`, `tools/phonesim`, `tools/relaysim` | Developer tools: decision records, a phone stand-in, the fake relay on a port. |
| `.agents/` | Context for coding agents — rules, reference, decisions. `AGENTS.md` is the router. |

### Decisions

Architecture decisions are one file each in `.agents/memory/decisions/`, indexed by the
generated `.agents/memory/decisions.md`. Add one with
`go run ./tools/adr new "<title>" -topics a,b`, write the body, then
`go run ./tools/adr index`. Ids are `YYYY-MM.suffix`, minted at random, so parallel worktrees
never collide on a number.

## Contributing and security

Contributions are welcome within the expectations in [`CONTRIBUTING.md`](CONTRIBUTING.md); commits
carry a DCO sign-off. Report vulnerabilities privately, as [`SECURITY.md`](SECURITY.md) describes.

## License

Copyright 2026 Jeffrey Walter Mixon. Licensed under the [Apache License, Version 2.0](LICENSE); see
[`NOTICE`](NOTICE). The binary also contains the Go standard library and four BSD-licensed modules,
whose notices are in [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md).
