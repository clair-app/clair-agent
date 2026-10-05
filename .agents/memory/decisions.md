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
| [2026-09.32b5](decisions/2026-09-32b5-a-parked-pair-resumes-only-when-the-relay-accepts-its-reset.md) | A parked pair resumes only when the relay accepts its reset, and only the relay's own 404 parks it | relay, state, security |
| [2026-09.34qh](decisions/2026-09-34qh-the-agent-reads-terminal-input-idle-time-itself-and-releases-a-bubbled-decide.md) | The agent reads terminal input idle time itself and releases a bubbled decide to the terminal while someone is at it | presence, hooks, tunnel |
| [2026-09.3gre](decisions/2026-09-3gre-a-phone-snippet-may-only-shape-the-agent-s-own-http-hooks.md) | A phone snippet may only shape the agent's own http hooks | hooks, security |
| [2026-09.66m4](decisions/2026-09-66m4-the-cli-on-disk-may-be-newer-than-the-running-daemon.md) | The CLI on disk may be newer than the running daemon, so what they share only grows | daemon, cli, state |
| [2026-09.69ym](decisions/2026-09-69ym-ending-a-pair-is-a-sealed-revoke.md) | Ending a pair is a sealed revoke, then DELETE; the CLI seals it from the pair file the daemon hands over | protocol, state, cli |
| [2026-09.6uv6](decisions/2026-09-6uv6-windows-releases-are-authenticode-signed-through-azure-artifact-signing-and.md) | Windows releases are Authenticode-signed through Azure Artifact Signing and timestamped | release, windows, security |
| [2026-09.6w38](decisions/2026-09-6w38-windows-is-checked-on-the-instance-runner-tagged-windows.md) | Windows is checked on the instance runner tagged windows, as SYSTEM in session 0 | ci, windows, daemon, install |
| [2026-09.72gv](decisions/2026-09-72gv-the-agent-ends-a-held-decide-just-before-claude-code-s-timeout-and-tells-the.md) | The agent ends a held decide just before Claude Code's timeout and tells the phone it expired | tunnel, hooks |
| [2026-09.9ufb](decisions/2026-09-9ufb-a-relay-reported-revoke-parks-a-pair.md) | A relay-reported revoke parks a pair; only the phone's sealed revoke or a week of unbroken reports deletes it | relay, state, security |
| [2026-09.ahq8](decisions/2026-09-ahq8-the-daemon-runs-as-a-per-user-login-service.md) | The daemon runs as a per-user login service, never a system service | daemon, cli, install |
| [2026-09.bckr](decisions/2026-09-bckr-a-phone-snippet-is-filled-in-as-json.md) | A phone snippet is filled in as JSON, matched on the agent's port, trimmed to known events, and replaced by the built-in block at pairing | hooks, security, pairing |
| [2026-09.c93f](decisions/2026-09-c93f-macos-is-checked-on-github-s-hosted-runners-through-a-push-mirror-of-this.md) | macOS is checked on GitHub's hosted runners through a push mirror of this project | ci, macos, daemon, install |
| [2026-09.evep](decisions/2026-09-evep-the-agent-edits-settings-json-through-an-order-preserving-json-object-and.md) | The agent edits settings.json through an order-preserving JSON object and installs clair statusline in place of the shell shim | hooks, claudecfg |
| [2026-09.hu4b](decisions/2026-09-hu4b-the-agent-releases-its-stream-when-it-stops-or-lets-a-pair-go.md) | The agent releases its stream when it stops or lets a pair go | relay, daemon, transport |
| [2026-09.hzwt](decisions/2026-09-hzwt-the-replay-counter-survives-restarts-by-block-reservation.md) | The replay counter survives restarts by block reservation; the mailbox cursor is not persisted | protocol, state |
| [2026-09.kau2](decisions/2026-09-kau2-static-analysis-is-one-pinned-golangci-lint-with-an-explicit-linter-set-and-a.md) | Static analysis is one pinned golangci-lint with an explicit linter set and a dependency allow-list | toolchain, lint, dependencies |
| [2026-09.khcq](decisions/2026-09-khcq-the-agent-speaks-sse-down-and-post-up-only.md) | The agent speaks SSE down and POST up only; streams are bounded and resumed by cursor | relay, transport, protocol |
| [2026-09.mwfw](decisions/2026-09-mwfw-clair-pair-revokes-a-pair-the-relay-completed-on-every-way-out-until-the-pair.md) | clair pair revokes a pair the relay completed on every way out until the pair file is saved | pairing, relay |
| [2026-09.n68c](decisions/2026-09-n68c-the-agent-signs-every-relay-request-with-canonical-v2-and-a-fresh-nonce.md) | The agent signs every relay request with canonical v2 and a fresh nonce, and re-signs once on replay | relay, auth, protocol |
| [2026-09.pz5g](decisions/2026-09-pz5g-on-windows-the-daemon-supervises-itself.md) | On Windows the daemon supervises itself, because Task Scheduler cannot see a crash through conhost | daemon, windows, install |
| [2026-09.qk6v](decisions/2026-09-qk6v-the-agent-updates-itself-in-the-background-from-signed-releases.md) | The agent updates itself in the background from signed releases, and the new binary runs at the next restart | install, release, daemon, security |
| [2026-09.r7kd](decisions/2026-09-r7kd-the-control-surface-shares-the-loopback-listener-under-clair-ctl-with-its-own.md) | The control surface shares the loopback listener under /clair/ctl with its own token, and a pair file has one writer | daemon, state, cli |
| [2026-09.tbsh](decisions/2026-09-tbsh-macos-is-checked-on-the-mac-mini-instance-runner-tagged-macos.md) | macOS is checked on the Mac mini instance runner tagged macos, inside its GUI login | ci, macos, daemon, install |
| [2026-09.ut2g](decisions/2026-09-ut2g-a-phone-snippet-is-rebuilt-from-the-agent-s-own-hook-template.md) | A phone snippet is rebuilt from the agent's own hook template, with each event pinned to its endpoint | hooks, security |
| [2026-09.vnj9](decisions/2026-09-vnj9-tests-are-the-standard-library-and-golden-vectors.md) | Tests are the standard library and golden vectors, not an assertion framework | testing, toolchain |
| [2026-09.w4ww](decisions/2026-09-w4ww-the-agent-answers-a-held-decide-only-with-what-the-permissionrequest-allows.md) | The agent answers a held decide only with what the PermissionRequest allows, checked against the request | hooks, security, tunnel |
| [2026-09.y34x](decisions/2026-09-y34x-settings-json-is-rewritten-under-a-file-lock.md) | settings.json is rewritten under a file lock, keeping its mode, and backed up by copy | hooks, claudecfg |
| [2026-09.zhzc](decisions/2026-09-zhzc-the-qr-is-rendered-with-rsc-io-qr-and-drawn-in-half-blocks-by-the-agent.md) | The QR is rendered with rsc.io/qr and drawn in half-blocks by the agent | pairing, dependencies |
| [2026-09.zvs8](decisions/2026-09-zvs8-releases-are-tag-pipelines-that-upload-to-the-package-registry.md) | releases are tag pipelines that upload to the package registry, and claircode.app serves them pinned by hash | release, install, ci |
| [2026-10.gw8w](decisions/2026-10-gw8w-a-decide-is-a-background-agent-s-when-its-hook-carries-agent-id-in-an.md) | A decide is a background agent's when its hook carries agent_id in an interactive session, as the decide hook's entrypoint header tells | presence, hooks, tunnel |
