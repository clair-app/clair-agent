---
id: "2026-09.qk6v"
slug: the-agent-updates-itself-in-the-background-from-signed-releases
title: "The agent updates itself in the background from signed releases, and the new binary runs at the next restart"
date: 2026-09-24
topics: [install, release, daemon, security]
---

# ADR 2026-09.qk6v — The agent updates itself in the background from signed releases, and the new binary runs at the next restart

Status: Accepted (2026-09-24); the swap checked for real on macOS (ADR 2026-09.c93f) and on Windows 11 with Defender on (ADR 2026-09.6w38)

**What was observed.** Upgrading meant re-running `install.sh` or `install.ps1`, which swap the
binary and restart the service (clair-web ADR 2026-09.e7ky). Nobody re-runs an installer, so every
host would drift behind the relay and the phone. The same day, `clair-agent` had no tags,
`agent-release.json` pinned nothing, and ADR 2026-09.ahq8 said that replacing a running
`clair.exe` was not handled.

The trust at stake changes with an updater. An installer trusts claircode.app once, when a person
runs it. An updater trusts every future deploy of the site, silently, on every paired host.
TLS and the `SHA256SUMS.txt` beside the builds come from the same origin, so they say nothing
if that origin is compromised.

**What changed.** `internal/update`, run by the daemon and by `clair update`:

- **What it reads.** `https://claircode.app/releases/` (`update.DefaultReleasesURL`), the tree
  the installers read: `latest.txt`, then `<v>/SHA256SUMS.txt`, `<v>/SHA256SUMS.txt.sig` and
  `<v>/clair-<v>-<os>-<arch>[.exe]`. `agent.json`'s `releases` overrides it, and so does
  `clair update -releases URL` for one check. Only HTTPS is accepted, or HTTP to loopback, for
  redirects too. The proxy comes from the environment and the system trust store is used; the
  relay's `--relay-ca` does not apply. Size caps: `latest.txt` 64 bytes, the checksums 8 KiB, the
  signature 256 bytes, a build 64 MiB.
- **What makes a release genuine.** An Ed25519 signature over `"clair-release-v1\n"` followed by
  the exact bytes of `SHA256SUMS.txt`, as standard base64 in `SHA256SUMS.txt.sig`.
  - The published names carry the version, so the signature binds each version to the hash of
    every build; `latest.txt` is not signed.
  - The keys are compiled in (`update.ReleaseKeys`): a primary and an offline backup, so a lost
    or leaked primary is replaced by a release that the backup signs. `make dist` refuses a
    release with fewer than two (`releasesign builtin`): one without keys could never update
    again.
  - The private halves never reach a server. clair-web's `agent-release.mjs pin` signs on the
    maintainer's machine, and the signature lands in the reviewed pin commit.
  - `ParseSums` is strict: every name carries the version, this host's build appears once, and
    there is no CR and no binary-mode `*`.
  - `testdata/release-signing-vector.json` is shared with clair-web, which signs in Node. Ed25519
    is deterministic, so both sides must produce its bytes.
- **Who updates.** Only a build whose linker-stamped `main.version` is a strict `vX.Y.Z`.
  - `buildVersion()` is not the test. Since Go 1.24, a plain `go build` on a tag stamps the tag
    as the module version, so a developer's build would replace itself.
  - A pre-release, a `git describe` suffix and `-dirty` never update, and are never updated to.
  - The binary is `service.ResolveExe(os.Executable())`, taken once at start: the path the
    service and the hooks already name. A `go run` build and anything under the temporary
    directory are refused, so they never update.
- **Forward only, judged by the disk.**
  1. If the file already hashes to the signed hash, it is already staged.
  2. Otherwise `<binary> version` must report a strict release older than `latest`. A newer
     binary, a local build of the same version and a development build are left alone, with the
     reason in `clair status`.
  3. The running version must also be older than `latest`, so a replayed old `latest.txt` does
     nothing.
- **How it is staged.**
  1. The build downloads to `.clair-update-*.exe` beside the binary. The extension is there
     because Windows runs nothing without one.
  2. The download is hashed against the signed sum, set to mode 0755 and closed.
  3. `<new> version`, with a 30 s timeout, must answer `clair <v> `. That refuses a wrong
     architecture, a darwin build the kernel kills for its signature, and a truncated file. The
     first run of a new binary on macOS can wait on the system's malware scan, and exec retries
     on `ETXTBSY` (golang/go#22315).
  4. Only then is it swapped in, never written in place: macOS kills a process whose signed
     pages change underneath it.
- **How it is swapped.**
  - On Unix, `rename` over the binary makes a new inode, and the running process keeps its own.
  - Windows renames a running image but will not replace or delete it. The running binary moves
    to a unique `.clair-old-<hex>.exe` first, then the download takes its place, with retries
    on a sharing violation and a rollback. The name has to be unique: at a second update before a
    restart, the first aside copy is still the running image.
  - `Sweep` removes the aside copies and any abandoned download at the next start.
- **When it runs.**
  - The first check is 2–10 minutes after start. Each later one is due 6 h ± 30 min after a
    success, or 1 h after a failure.
  - Due times are wall-clock: the loop wakes every 10 minutes and compares
    `time.Now().Round(0)`, because the monotonic clock stops while a laptop sleeps.
  - `agent.json`'s `autoUpdate: false` pauses the loop, and is read before each check.
  - `clair update` posts `/clair/ctl/update` (admin token, ADR 2026-09.r7kd), so the daemon
    replaces its own binary and its status stays true. It shares the loop's lock and falls back
    to checking in-process when no daemon answers, or when one from before this route answers
    404.
- **When it takes effect.** The daemon keeps running its old image. The new binary runs from
  the next start, whatever causes it: a login, a crash restart, `clair service restart`, or
  install.sh. `clair status` and `clair service status` say so. Nothing here restarts anything.
- **The test key.** `make build RELEASE_TEST_KEY=<public key>` links one more key
  (`main.releaseTestKey`), for trying all of this against a local release (`tools/releasesign`).
  - `clair version` then prints a second line, `built with a release test key`.
  - `make dist` refuses the variable and any build that prints that line; clair-web's `pin`
    refuses such a build too.
  - An environment variable, an `agent.json` field or a "loopback-only" key would each stay in
    every production binary as a bypass, so there is none.

The alternatives:

- A separate timer (a systemd timer, a `StartCalendarInterval`, a second Scheduled Task) would
  be three more service definitions, for what one goroutine does.
- Restarting the daemon once staged would end held decides and streams on the updater's
  schedule instead of the user's.
- Trusting HTTPS and the checksums alone is what the installers do, and is not enough for a
  process that acts without being asked.

**What it costs and what it does not cover.**

- **Version skew.** After a staged update, the commands on disk are newer than the running
  daemon: `clair status`, `pair`, the hooks' `hook-event` and `statusline`. What they share only
  grows: ADR 2026-09.66m4.
- **The updater swaps one file.** A release that changes the service registration (a unit, a
  plist, the task XML) or the hooks block must migrate them itself when it starts. The
  registration and the hooks name the path, and the path does not change.
- **There is no rollback.** A release that builds and answers `version` but dies at start
  crash-loops on every host at its next restart. systemd never reaches its start limit at
  `RestartSec=5`, and launchd and the task keep retrying. The guard is the tag pipeline and the
  macOS job (ADR 2026-09.c93f). The remedy is a new release, or install.sh with `autoUpdate`
  off.
- **`install.sh vOld` is upgraded again** within hours unless `autoUpdate` is false.
- **What the site sees.** claircode.app sees each host's IP, agent version and OS/architecture
  (the `User-Agent`) about every six hours.
- **A frozen `latest.txt`** (withholding new releases) goes unnoticed without a signed expiry.
  A leaked key together with a compromised site reaches every host within about six hours; the
  backup key is for rotating it.
- **Unverified on hardware:**
  - Windows: the moment between the two renames, when the path is empty and a hook started
    then fails once. Renaming a running `clair.exe` aside under Defender, a second update
    before the restart, and the sweep are checked by the `windows` job (ADR 2026-09.6w38).
  - macOS: whether a new binary raises "Background Items Added" again. The macOS job records
    `sfltool dumpbtm` before and after.
  - The swap sequence is tested against a fake Windows filesystem (`swap_test.go`), and the real
    exec path on Unix (`stage_unix_test.go`).
- **What holds it:**
  - `internal/update`'s tests: the vector, the refusals, `Check` against a fake release server,
    and the loop in a `synctest` bubble.
  - `cmd/clair/update_test.go`: `clair update` with and without a daemon, the daemon replacing
    its own binary, and `clair status`.
  - The `dist` target's refusals, and the macOS job's self-update step.
