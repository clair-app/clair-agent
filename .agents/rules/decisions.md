# Decisions

When an ADR must be read, and how a new one is recorded. Routed from
[`AGENTS.md`](../../AGENTS.md): match the trigger table before touching code, and read the
whole file before recording an architectural choice.

## When to read one

Every row names a **trigger** and a **file**. Follow the rows that match the task; skip the
rest. The traps are recorded in the routed files, not here — if a trigger starts growing
an explanation, that explanation belongs in the ADR.

| If touching | READ |
| --- | --- |
| `go.mod`, `.golangci.yml`'s `depguard` allow-list or linter list, the tool pins in the `Makefile`, or reaching for a library the standard library could replace | [ADR 2026-09.kau2](../memory/decisions/2026-09-kau2-static-analysis-is-one-pinned-golangci-lint-with-an-explicit-linter-set-and-a.md) |
| a `_test.go` that wants `testify`, `gomega` or `go-cmp`, or a golden vector that "needs a small fix" | [ADR 2026-09.vnj9](../memory/decisions/2026-09-vnj9-tests-are-the-standard-library-and-golden-vectors.md) |
| `internal/relay` — a transport, stream reconnection, or the idea of a WebSocket | [ADR 2026-09.khcq](../memory/decisions/2026-09-khcq-the-agent-speaks-sse-down-and-post-up-only.md), then [ADR 2026-09.hu4b](../memory/decisions/2026-09-hu4b-the-agent-releases-its-stream-when-it-stops-or-lets-a-pair-go.md) for when a stream is released |
| the `Authorization` header, the canonical string, a nonce, a 401 `reason`, or a retry around a signed request | [ADR 2026-09.n68c](../memory/decisions/2026-09-n68c-the-agent-signs-every-relay-request-with-canonical-v2-and-a-fresh-nonce.md) |
| the QR payload, its rendering, or `rsc.io/qr` | [ADR 2026-09.zhzc](../memory/decisions/2026-09-zhzc-the-qr-is-rendered-with-rsc-io-qr-and-drawn-in-half-blocks-by-the-agent.md) |
| `n`, `h2pNext`, `p2hLast`, the mailbox cursor, or a pair file's counters | [ADR 2026-09.hzwt](../memory/decisions/2026-09-hzwt-the-replay-counter-survives-restarts-by-block-reservation.md) |
| `/clair/ctl` (a new path such as `stop`), the admin token, the hookserver guard order, or who writes a pair file | [ADR 2026-09.r7kd](../memory/decisions/2026-09-r7kd-the-control-surface-shares-the-loopback-listener-under-clair-ctl-with-its-own.md), then [ADR 2026-09.69ym](../memory/decisions/2026-09-69ym-ending-a-pair-is-a-sealed-revoke.md) for what a release hands over |
| `settings.json`, the hooks block, `statusLine`, or `internal/ojson` | [ADR 2026-09.evep](../memory/decisions/2026-09-evep-the-agent-edits-settings-json-through-an-order-preserving-json-object-and.md), then [ADR 2026-09.y34x](../memory/decisions/2026-09-y34x-settings-json-is-rewritten-under-a-file-lock.md) for how it is written, locked and backed up |
| what a phone snippet may install, `ValidateSnippet`, or a hook option (`headers`, `allowedEnvVars`, a new member) | [ADR 2026-09.ut2g](../memory/decisions/2026-09-ut2g-a-phone-snippet-is-rebuilt-from-the-agent-s-own-hook-template.md), then [ADR 2026-09.3gre](../memory/decisions/2026-09-3gre-a-phone-snippet-may-only-shape-the-agent-s-own-http-hooks.md), and [ADR 2026-10.gw8w](../memory/decisions/2026-10-gw8w-a-decide-is-a-background-agent-s-when-its-hook-carries-agent-id-in-an.md) for the decide hook's one `allowedEnvVars` |
| `Substitute`, a placeholder, the snippet's URL host or port, a new Claude Code hook event, what `clair pair` installs when the phone's snippet is refused, or `Report.Unchanged` | [ADR 2026-09.bckr](../memory/decisions/2026-09-bckr-a-phone-snippet-is-filled-in-as-json.md) |
| the hook template (`RenderHooks`, `httpHook`, `rebuildHook`, a header, an option or a new event), `RefreshHooks`, `ctl.Status.Hooks`, or anything the daemon writes at start | [ADR 2026-10.sm5c](../memory/decisions/2026-10-sm5c-at-each-start-the-daemon-rebuilds-the-clair-hooks-already-in-settings-json-from.md): every paired host takes a template change at its next start, so a newer block must be harmless to an older daemon |
| `clair pair` between the relay's completion and the saved pair file — a new return, the hello-ack, `abandon` — or the signals `cmd/clair` stops on | [ADR 2026-09.mwfw](../memory/decisions/2026-09-mwfw-clair-pair-revokes-a-pair-the-relay-completed-on-every-way-out-until-the-pair.md) |
| `internal/hookout`, what `/hook/decide` answers Claude Code, or a new shape of phone answer (a tool whose input it may edit, a plan mode) | [ADR 2026-09.w4ww](../memory/decisions/2026-09-w4ww-the-agent-answers-a-held-decide-only-with-what-the-permissionrequest-allows.md) |
| a pair ending: `410`, `404`, `event: revoked`, the `revoke` record, `onRevoked`, a dormant pair or `relayRevokedAt` | [ADR 2026-09.9ufb](../memory/decisions/2026-09-9ufb-a-relay-reported-revoke-parks-a-pair.md), then [ADR 2026-09.32b5](../memory/decisions/2026-09-32b5-a-parked-pair-resumes-only-when-the-relay-accepts-its-reset.md) for which 404 parks and what resumes a pair |
| `clair unpair`, `releaseAll`, `ReleasePair`, `TakePair`, or sending a sealed `revoke` from the host | [ADR 2026-09.69ym](../memory/decisions/2026-09-69ym-ending-a-pair-is-a-sealed-revoke.md) |
| `internal/service`, `clair service`, `clair daemon -log-file`, a systemd unit, LaunchAgent plist or task XML, `/clair/ctl/stop`, or the idea of a system service, a Windows service or a daemon run as root | [ADR 2026-09.ahq8](../memory/decisions/2026-09-ahq8-the-daemon-runs-as-a-per-user-login-service.md), then [ADR 2026-09.34qh](../memory/decisions/2026-09-34qh-the-agent-reads-terminal-input-idle-time-itself-and-releases-a-bubbled-decide.md) for why the session matters |
| `internal/presence`, a held decide's lifetime, `permission_mode`, `agent_id`, `X-Clair-Entrypoint`, `X-Clair-Idle-Ms`, `record.Hook.Bubbled`, or the idea of reading another hook field | [ADR 2026-09.34qh](../memory/decisions/2026-09-34qh-the-agent-reads-terminal-input-idle-time-itself-and-releases-a-bubbled-decide.md), then [ADR 2026-10.gw8w](../memory/decisions/2026-10-gw8w-a-decide-is-a-background-agent-s-when-its-hook-carries-agent-id-in-an.md) for what marks a bubbled decide |
| `Hold`'s timer, `holdMargin`, a `cancel` reason, or what the phone is told when a decide times out | [ADR 2026-09.72gv](../memory/decisions/2026-09-72gv-the-agent-ends-a-held-decide-just-before-claude-code-s-timeout-and-tells-the.md) |
| the `release` job, `make dist`, a tag, the package registry, or where installers download from | [ADR 2026-09.zvs8](../memory/decisions/2026-09-zvs8-releases-are-tag-pipelines-that-upload-to-the-package-registry.md) |
| the `sign` or `signature:windows` job, `make dist-signed`, `tools/authenticode`, the Azure signing account or its credentials, or antivirus and SmartScreen warnings on Windows | [ADR 2026-09.6uv6](../memory/decisions/2026-09-6uv6-windows-releases-are-authenticode-signed-through-azure-artifact-signing-and.md) |
| the `macos` CI job, the Mac mini runner, `tools/machocheck`, or checking anything on macOS | [ADR 2026-09.tbsh](../memory/decisions/2026-09-tbsh-macos-is-checked-on-the-mac-mini-instance-runner-tagged-macos.md), which supersedes [ADR 2026-09.c93f](../memory/decisions/2026-09-c93f-macos-is-checked-on-github-s-hosted-runners-through-a-push-mirror-of-this.md) |
| the `windows` CI job, the Windows runner, `.gitattributes` for `testdata/`, or checking anything on Windows | [ADR 2026-09.6w38](../memory/decisions/2026-09-6w38-windows-is-checked-on-the-instance-runner-tagged-windows.md) |
| `internal/supervisor`, `clair daemon -supervise`, `Manager.RestartsOnCrash`, a crash restart or a logoff on Windows | [ADR 2026-09.pz5g](../memory/decisions/2026-09-pz5g-on-windows-the-daemon-supervises-itself.md) |
| `internal/update`, `clair update`, the release keys or signature, `RELEASE_TEST_KEY`, `tools/releasesign`, `autoUpdate`, or the idea of the daemon restarting itself | [ADR 2026-09.qk6v](../memory/decisions/2026-09-qk6v-the-agent-updates-itself-in-the-background-from-signed-releases.md) |
| `internal/ctl`'s JSON, a `/clair/v1` or `/clair/ctl` path, a field of `agent.json` or a pair file, or a flag of `clair daemon`, `hook-event` or `statusline` — removing or changing any of them | [ADR 2026-09.66m4](../memory/decisions/2026-09-66m4-the-cli-on-disk-may-be-newer-than-the-running-daemon.md) |

Add a row when an ADR guards something a future edit is likely to touch; not every ADR
needs one.

## How to record one

1. `go run ./tools/adr new "<the decision, as a sentence>" -topics a,b` (or
   `make adr-new TITLE="…" TOPICS=a,b`). The id is minted for you — `YYYY-MM.suffix`,
   random — so parallel worktrees cannot collide. Never pick one by hand.
2. Write the body in the scaffold's shape: **what was observed** (numbers where there are
   numbers), **what changed** and the alternative a reader would reach for first, **what
   it costs** and the test, gate or invariant that keeps it true.
3. `go run ./tools/adr index` regenerates `.agents/memory/decisions.md`. Never hand-edit
   it. Commit the ADR and the router together — `.githooks/pre-commit` (`make hooks`)
   refuses a commit where they disagree, and CI's `adr-index` job is the backstop.
4. Cite it as `ADR 2026-09.k3f9` in code comments and commit messages; the heading line in
   the file is the grep anchor.
5. Supersede by writing a new ADR and changing the old one's `Status:` line — never by
   deleting or renumbering.

A decision the *phone* side owns (the wire format, the hook contract, the relay API) is
recorded in the `clair` repository's ADRs; this repository's ADRs are about the agent.
