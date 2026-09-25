---
id: "2026-09.6w38"
slug: windows-is-checked-on-the-instance-runner-tagged-windows
title: "Windows is checked on the instance runner tagged windows, as SYSTEM in session 0"
date: 2026-09-25
topics: [ci, windows, daemon, install]
---

# ADR 2026-09.6w38 — Windows is checked on the instance runner tagged windows, as SYSTEM in session 0

Status: Accepted (2026-09-25)

**What was observed.** Until 2026-09-25 nothing ran on Windows. `make lint` type-checked the
`_windows.go` files from Linux, and ADR 2026-09.ahq8 listed the Windows half of the service as
unverified on hardware. Then an instance runner tagged `windows` came online.

Its setup:

- Windows 11 (build 26200) on amd64, with the shell executor and PowerShell 7.6.
- It runs as `NT AUTHORITY\SYSTEM`, a service in session 0, with Defender real-time protection
  on.
- It has git, curl and tar, but no Go, no make, no Python and no C compiler.

A first probe job answered those questions. The first runs of `go test ./...` found three
Windows-only failures, all in the tests or in how the tests were set up:

- **Golden files checked out with CRLF.** Git for Windows converts text on checkout, and only
  `*.go` was pinned to LF.
- **The LaunchAgent's paths joined with `filepath`.** A plist rendered on Windows came out with
  backslashes. It never renders there in production, but the tests render every OS's file on
  every host.
- **Mode-bit assertions.** `0600` and `0700` mean nothing to NTFS.

**What changed.**

- **A `windows` job in `.gitlab-ci.yml`,** on the tag, run when Go code or the CI file changes.
  - It fetches the Go 1.26 that go.dev's JSON names and checks go.dev's SHA-256. It unpacks Go
    into `$CI_BUILDS_DIR\.clair-tools`, outside the checkout, so `git clean` leaves it and later
    runs skip the download.
  - It clones fresh each time (`GIT_STRATEGY: clone`), because a fetch leaves files checked out
    under older attributes in place.
- **The tests run with `-shuffle` and without `-race`,** which needs cgo and a C compiler.
  Linux's `test` job is the race gate.
- **The self-update runs for real** (ADR 2026-09.qk6v), with a test key and releases served on
  loopback by `releasesign serve`:
  - a running `clair.exe` is renamed aside and replaced;
  - a second update lands before the restart;
  - a tampered build and a foreign key are refused;
  - a stop through `/clair/ctl/stop`, then the next start runs the new binary, and the sweep
    removes the aside copies.
- **`**/testdata/** -text`** in `.gitattributes`, `path.Join` for the LaunchAgent's POSIX
  paths, and mode checks skipped on Windows. After these, the whole suite passes there.

The alternative a reader would reach for is GitHub's `windows-latest`, on the mirror that runs
macOS (ADR 2026-09.c93f). It would split one platform's evidence across two CI systems, and its
minutes count double against a private repository. This runner is here, it is GitLab's, and it
runs in seconds once Go is cached.

**What it costs and what it does not cover.**

- **What session 0 cannot show.** A service account has no desktop and no logon, so the job
  cannot check the rest of ADR 2026-09.ahq8:
  - registering a logon-triggered Scheduled Task for a signed-in user, without elevation;
  - `conhost --headless` under Windows Terminal;
  - `GetLastInputInfo` presence;
  - a logoff delivered as SIGTERM.

  Those still need a signed-in user. The daemon here is started with `Start-Process`, not
  through `clair service`.
- **What it found.** When `clair update` asks the daemon, the command itself runs from the
  `clair.exe` being replaced. So that copy is a running image too when it is moved aside, and it
  stays until the sweep, as ADR 2026-09.qk6v's design allows. The job expects both aside copies
  after the second update.
- **The runner is one machine.** While it is offline, a pipeline that needs the job waits.
  - `timeout: 30m` bounds a hung run, but not a job no runner picks up.
  - If the machine goes away, remove the job, or mark it `allow_failure` with a manual start.
  - Go and its module cache persist under `$CI_BUILDS_DIR\.clair-tools` on that machine.
