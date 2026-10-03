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
| `lint` | `.golangci.yml` is clean — vet, staticcheck, gosec, revive, gocritic, modernize, depguard … — once per `GOOS` (linux, darwin, windows), so the darwin and Windows files and their tests are type-checked and linted on any host |
| `test` | `go test -race -shuffle=on -count=1` over every package; coverage in `coverage.out` |
| `vuln` | `govulncheck`: no known vulnerability reachable from this module (advisory in CI, blocking here) |
| `adr-check` | `.agents/memory/decisions.md` matches the ADR files |
| `changelog-check` | `CHANGELOG.md` is a Level 2 [Declarative Changelog](https://whatsnew.fyi/spec) with no warnings (`declarative-changelog` through `npx`, so it needs Node.js 20+) |

Then `make build` and `bin/clair version` if the change touches `cmd/clair` or the
linker-injected version.

## Everything else

| Target | Purpose |
| --- | --- |
| `make tools` | Install the pinned `golangci-lint` and `govulncheck` into `./bin` (once per clone, and after a pin bump) |
| `make build` | `./bin/clair` for this host — static, `-trimpath`, version from `git describe`. `VERSION=v0.0.1 RELEASE_TEST_KEY=<public key>` makes a build that updates itself from a local release (below) |
| `make build-all` | Cross-compile linux/darwin/windows × amd64/arm64 into `./dist`, then `tools/machocheck` verifies the darwin builds' code signatures: Apple silicon kills an arm64 binary whose signature is missing or stale |
| `make dist VERSION=vX.Y.Z` | `build-all` for a release: checks the stamped version, refuses a release test key or fewer than two built-in release keys, writes `dist/SHA256SUMS.txt`. The tag pipeline runs it (ADR 2026-09.zvs8) |
| `make dist-signed SIGNED=<dir>` | After `dist`: checks each signed Windows build in `<dir>` is `dist/`'s own build plus a timestamped signature by `SIGNER` (`tools/authenticode`), swaps them in and rewrites `SHA256SUMS.txt`. The tag pipeline's `release` job runs it, then uploads (ADR 2026-09.6uv6) |
| `make sums` | Rewrite `dist/SHA256SUMS.txt` over whatever `dist/` holds |
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
  `GOOS=windows bin/golangci-lint run` lints one other OS's files.
- `go run ./tools/machocheck dist/clair-darwin-*` — re-checks the darwin signatures
  without a rebuild.
- `go run ./tools/authenticode check -signer "Jeffrey Mixon" clair-windows-*.exe` — re-checks a
  released Windows build's signature and timestamp; `authenticode digest` prints the digest the
  signature covers, which a local unsigned build of the same commit shares.
- `go run ./cmd/clair update -check` — asks the running daemon whether a newer release exists
  (a development build says it never updates itself).

## Cutting a release

1. In `CHANGELOG.md` (a [Declarative Changelog](https://whatsnew.fyi/spec)), add
   `## [X.Y.Z](https://github.com/clair-app/clair-agent/releases/tag/vX.Y.Z) — <now, RFC 3339>`
   under `## Unreleased`, with a one-line `>` summary and items that say what changed for the
   user, not the commit subjects. Bump `document.updated`, then `make changelog-check`.
   Never edit a published entry's version or date: together they are its id.
2. `make check` on the commit, then `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. The tag pipeline runs `dist`, then `sign` (the Windows builds, through Azure Artifact Signing),
   `signature:windows` (Windows' own verdict on them), and `release`, which uploads the builds and
   `SHA256SUMS.txt` to `packages/generic/clair/vX.Y.Z/` (ADR 2026-09.6uv6). Only a protected `v*`
   tag gets the signing credentials, so push tags as a Maintainer.
4. In clair-web, `CLAIR_RELEASE_KEY=<primary key.pem> node scripts/agent-release.mjs pin vX.Y.Z`
   hashes the uploaded files into `agent-release.json` and signs them with the offline release
   key. That signature is what every installed agent checks before it updates itself
   (ADR 2026-09.qk6v). Never pin from a local `dist/`. To check an upload, `make dist
   VERSION=vX.Y.Z` on the tag, in a clean clone, with the CI image's Go (`golang:1.26`,
   newest patch): the stamped date is the commit's, so the checksums match `SHA256SUMS.txt` for
   every build but the two Windows ones, which are signed. For those, `go run ./tools/authenticode
   digest` on both files must agree.
   v0.1.0 was built before CI's `.go/` cache was ignored and is stamped `+dirty`; it matches
   only with CI's `GOPATH`, `GOMODCACHE` and `GOCACHE` pointed at an untracked `.go/` in the
   clone (golang@sha256:6c2a5538…, Go 1.26.8).

## Trying the self-update against a local release

A test key, two builds that trust it, and a release served on loopback (ADR 2026-09.qk6v):

```sh
R=$(mktemp -d); export CLAIR_CONFIG_DIR=$R/config CLAUDE_CONFIG_DIR=$R/claude
PUB=$(go run ./tools/releasesign keygen -out $R/k.pem)
for v in v0.0.1 v0.0.2; do
  make build VERSION=$v RELEASE_TEST_KEY=$PUB
  mkdir -p $R/rel/$v && cp bin/clair $R/rel/$v/clair-$v-$(go env GOOS)-$(go env GOARCH)
  (cd $R/rel/$v && sha256sum clair-* > SHA256SUMS.txt)
  go run ./tools/releasesign sign -key $R/k.pem $R/rel/$v
done
echo v0.0.2 > $R/rel/latest.txt
python3 -m http.server 8000 --bind 127.0.0.1 --directory $R/rel &     # the release server
mkdir -p ~/clair-trial && cp $R/rel/v0.0.1/clair-* ~/clair-trial/clair  # not under /tmp: refused
~/clair-trial/clair daemon -listen 127.0.0.1:7417 &                    # v0.0.1
~/clair-trial/clair update -check -releases http://127.0.0.1:8000      # v0.0.2 is available
~/clair-trial/clair update -releases http://127.0.0.1:8000             # staged; the daemon still runs v0.0.1
~/clair-trial/clair version; ~/clair-trial/clair status
```

`"releases": "http://127.0.0.1:8000"` in `agent.json` points the background check there too. A
tampered build, a signature by another key and a `latest.txt` older than the binary are all
refused. `make build` without the variables is the ordinary development build, which never
updates. Remove `~/clair-trial` afterwards.

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
