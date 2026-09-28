---
id: "2026-09.c93f"
slug: macos-is-checked-on-github-s-hosted-runners-through-a-push-mirror-of-this
title: "macOS is checked on GitHub's hosted runners through a push mirror of this project"
date: 2026-09-24
topics: [ci, macos, daemon, install]
---

# ADR 2026-09.c93f — macOS is checked on GitHub's hosted runners through a push mirror of this project

Status: Accepted (2026-09-24); superseded by ADR 2026-09.tbsh (the macOS job runs on the Mac mini instance runner, and the workflow is removed)

**What was observed.** On 2026-09-24 no Mac was at hand, and nothing macOS-specific had ever
run. The darwin builds cross-compiled, but the `_darwin.go` tests had never executed, and the
LaunchAgent half of ADR 2026-09.ahq8 was checked only against a fake `launchctl`. Nothing
checked that the arm64 build carried the code signature Apple silicon needs at exec. The
self-hosted GitLab has no macOS runner, and GitLab's hosted macOS runners exist only on
GitLab.com.

GitHub's hosted macOS images log the runner user in at the GUI, so `gui/501` is a live launchd
domain. EC2 Macs have no such login. Two checks that need no Mac came first, in the same change:

- `make lint` now runs once per `GOOS`. Its first Windows pass found three gosec findings that
  had never been linted.
- `tools/machocheck` verifies the darwin builds' page hashes in `make build-all`.

**What changed.**

- `github.com/clair-app/clair-agent`, private, is a push mirror of this project. It is GitLab
  a remote mirror: SSH, all branches, no divergent refs, and GitHub's published host keys
  pinned. It authenticates with GitLab's mirror key as a write deploy key on that one
  repository. A deploy key works on one repository, never expires, and belongs to no person.
- `.github/workflows/macos.yml` runs on `macos-26` (arm64) on release tags, on pushes to `main`
  that touch code the Mac runs, and on `workflow_dispatch`. Run 36063716695 (commit 27b6ad6,
  image `macos-26-arm64` 20260907, Go 1.26.8) showed:
  - `make test` passes on darwin.
  - `codesign --verify --strict` calls the build "valid on disk" and says it satisfies its
    Designated Requirement. `tools/machocheck` agrees, over 1759 pages of 4096 bytes. The
    checker that guards the Linux-built releases matches Apple's own.
  - `clair service install` bootstraps into `gui/501` and answers within 0.4 s. Pairing through
    `tools/relaysim` and `tools/phonesim` completes, and a decide is answered `allow`.
  - `launchctl kill SIGKILL` is followed by a new pid about 9 s later. That is
    `ThrottleInterval` 10 counted from the previous launch. The restarted daemon answers a
    decide from its pair file.
  - `POST /clair/ctl/stop` leaves `state = not running` and `last exit code = 0`, and nothing
    restarts it in 15 s: `KeepAlive {SuccessfulExit false}` does what ahq8 says.
    `clair service status` then exits 3 (`exitUnreachable`).
  - `sfltool dumpbtm` lists the agent as a `legacy agent`, disposition `[enabled, allowed,
    notified]`. The notified bit means macOS raised "Background Items Added". The item names the
    binary's path.
  - claircode.app's `install.sh` under `/bin/sh` passes three times against a release of the
    commit served on 127.0.0.1: a first install, an upgrade over the running service, and
    `arch -x86_64` under Rosetta, which still installs the arm64 build.

The alternatives: a macOS VM on Linux (Docker-OSX, OSX-KVM) breaks Apple's licence and is
Intel-only. Cirrus CI shut down on 2026-06-01. A rented Mac (Scaleway, a 24 h minimum) shows
what a runner cannot, but costs a day per check and nothing re-runs it.

**What it costs, and what it does not cover.**

- Private-repository macOS minutes count 10x. The job takes under 3 minutes, so a run uses 30 of
  the org's 2,000 a month: about 60 runs. Hence the path filter on `main`. Tags always run.
- Results show on GitHub only; GitLab's pipeline stays the gate and does not wait for them. A
  tag's macOS run is worth reading before pinning a release in clair-web.
- **Push to GitLab, never to the mirror.** The next sync overwrites the mirror.
- The mirror stops silently if the deploy key is removed or the org disables deploy keys again.
  `glab api projects/<id>/remote_mirrors/<id>` shows `last_error`.
- Not covered, and left for a session on real hardware:
  - how the "Background Items Added" notification and the Login Items entry read to a person
  - presence from keystrokes (the runner has no `/dev/ttys*` of its own and reads "no signal")
  - logout, login and reboot
  - a real phone
  - whether `ProcessType Interactive` is warranted
- Held by the workflow itself: every assertion above is a step that fails the run. The
  workflow's header lists what it covers.
