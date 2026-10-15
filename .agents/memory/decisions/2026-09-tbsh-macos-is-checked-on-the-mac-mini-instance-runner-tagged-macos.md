---
id: "2026-09.tbsh"
slug: macos-is-checked-on-the-mac-mini-instance-runner-tagged-macos
title: "macOS is checked on the Mac mini instance runner tagged macos, inside its GUI login"
date: 2026-09-27
topics: [ci, macos, daemon, install]
---

# ADR 2026-09.tbsh — macOS is checked on the Mac mini instance runner tagged macos, inside its GUI login

Status: Accepted (2026-09-27)

**What was observed.** On 2026-09-27 an instance runner tagged `macos` came online, and ADR 2026-09.c93f's list of what only real hardware shows could be worked
through. Its setup:

- A Mac mini, Apple M6, macOS 27.0 (26A428), with Rosetta.
- The shell executor and bash. `gitlab-runner` is a LaunchAgent of the Mac's user, who is logged
  in at the console. So jobs run inside `gui/501`, with that user's `/dev/ttys*`, which GitHub's
  runner never had.
- launchd's `PATH` (`/usr/bin:/bin:/usr/sbin:/sbin`); no Go; Xcode's clang; `jq` from Homebrew.

A session by hand on that Mac came first. It found one bug and confirmed the rest:

- **A first install said it failed.** `curl -fsSL https://claircode.app/install.sh | sh` on a Mac
  with no config started the daemon within a second, then printed "the agent did not answer
  within 10s" and "its service didn't start". `clair service` built its control client from
  `agent.json` before `install` created that file, so the readiness check carried no admin token
  and got 401s until it gave up. That happens on every OS. GitHub's job never saw it, because its
  config directory existed before `install.sh` ran. It is fixed in the same change, and
  `TestServiceInstallOnANewMachine` holds it.
- **Presence works from launchd.** A pty's atime moves to the second a program reads a keystroke
  (Linux moves it every 8 s), and the LaunchAgent's `clair status` follows it.
- **KeepAlive** starts a SIGKILLed daemon again within 250 ms when the last launch was more than
  `ThrottleInterval` ago; GitHub's 9 s was that interval counted from the launch before.
- **Against production:** pairing through `relay.claircode.app` with `tools/phonesim`, and a
  decide answered in 1.6 s. `install.sh v0.2.0`, then `clair update` to v0.3.0 checked against
  the built-in release keys. The new binary passed `codesign --strict` and carried no quarantine.
- **Background Items:** one `legacy agent` entry, `[enabled, allowed, notified]`. Replacing the
  binary, by `install.sh` or the self-update, kept it at generation 1 with no new notification.
  An uninstall and a later install made a new entry, and a new notification.
- **A reboot:** the console login started the agent about 10 s after boot, with its pair and stream back.

**What changed.**

- **A `macos` job in `.gitlab-ci.yml`,** on the tag, run when Go code, the `Makefile` or the CI
  file changes. It covers everything the GitHub workflow did, plus presence from a pty that
  `script(1)` makes and a first install with no config directory. Its script ran on the Mac under
  the runner's environment in 47 s, with Go cached.
- **It fetches the Go 1.26 that go.dev's JSON names** and checks go.dev's SHA-256. Go and its
  caches live in `$CI_BUILDS_DIR/.clair-tools`, outside the checkout, as on Windows
  (ADR 2026-09.6w38).
- **`.github/workflows/macos.yml` is removed.** Nothing macOS-specific runs on GitHub now.

The alternative is keeping the GitHub workflow. Its minutes count 10x against a private
repository, its results show only on GitHub, and its runner has no pty and no login to lose.

**What it costs and what it does not cover.**

- **The Mac is also someone's machine.** A user has one LaunchAgent label, `app.claircode.clair`.
  - The job refuses to run while a real clair agent is installed there. It removes a LaunchAgent
    that a cancelled run left, one whose program is under `$CI_BUILDS_DIR`.
  - Its daemon, relay and release servers take 17317, 13000, 18000 and 18001.
  - `install.sh`'s first install takes 7317, because a user's first install does.
  - The job refuses to start while anything listens on one of those ports.
  - `resource_group: mac-mini` keeps two pipelines apart.
- **`after_script` kills by path.** Everything the job starts in the background runs as
  `$CI_PROJECT_DIR/bin/…` or from `.mac/`. A process started as a relative `bin/relaysim` has no
  such path in its command line, and a trial run left four behind.
- **Every run installs the LaunchAgent three times,** and each install shows "Background Items
  Added" on the Mac's screen.
- **The runner lives inside the login.**
  - A logout stops the runner along with the agent, and the console login comes back only at
    boot.
  - While the Mac is away, a pipeline that needs the job waits. `timeout: 20m` bounds a hung run.
  - If the Mac goes away for good, remove the job or make it `allow_failure` with a manual start.
- **Still not covered:**
  - a logout;
  - a real phone;
  - a person typing in Terminal.app (the `script(1)` pty is the same kernel path);
  - whether `ProcessType Interactive` is warranted;
  - Developer ID signing, which the ad-hoc-signed build does not have, so Background Items
    names no developer.
- Held by the job itself: every assertion is a step that fails the run.
