---
changelog: "0.1"
product:
  name: Clair agent
  vendor: Jeff Mixon
  homepage: https://claircode.app
  id: clair-agent
  description: Runs on your computer and carries Claude Code's prompts, end-to-end encrypted, to the Clair app on your Wear OS watch or Android phone.
  platforms: [linux, macos, windows]
  versioning: semver
  category: developer-tools
document:
  updated: 2026-10-05T22:14:45Z
  canonical: https://github.com/clair-app/clair-agent/blob/main/CHANGELOG.md
---

# Clair agent changelog

This file is a [Declarative Changelog](https://whatsnew.fyi/spec). It starts at 0.3.0.

## Unreleased

## [0.4.0](https://github.com/clair-app/clair-agent/releases/tag/v0.4.0) — 2026-10-05T22:14:45Z

> Permission prompts from background agents now show in your terminal while you're at it, and new
> hook settings reach an existing install when the agent starts.

### Added

- New hook settings now reach an existing install without pairing again. When the agent starts, it
  brings its own hooks in Claude Code's `settings.json` up to date with its version and keeps the hook
  settings you chose in the phone app. Your own hooks and the rest of the file stay as they are,
  Clair hooks you removed aren't added back, and the file is backed up before any change.
  `clair status` shows what the agent found. Claude Code 2.1.289 applies the change to open sessions
  without a restart.

### Changed

- The permission hook in Claude Code's `settings.json` now passes the session's
  `CLAUDE_CODE_ENTRYPOINT` to the agent, so a `claude -p` run's prompts stay on your watch: `-p` has
  no terminal prompt to fall back to. An existing install gets the new hook the next time the agent
  starts.

### Fixed

- Permission prompts from background agents now show in your terminal while you're at it,
  whatever the session's permission mode or the agent's type. Before, only a forked agent in a
  default-mode session got there. Any other agent's prompt, including every one in auto mode, waited
  up to a day for your watch or phone with nothing in the terminal. When you're away, prompts still
  go to your watch. ([#2](https://gitlab.invalid/clair/clair-agent/-/issues/2))

## [0.3.1](https://github.com/clair-app/clair-agent/releases/tag/v0.3.1) — 2026-09-28T03:44:45Z

> A prompt nobody answers now shows as expired on the phone, and a first install no longer reports
> that its service didn't start.

### Fixed

- When nobody answers a prompt before its hook timeout, the phone now shows it as expired. It used
  to say Handled in terminal while the prompt was still open there, or keep it on the phone until
  it went stale. To tell the phone in time, the agent now lets go of a prompt 2 seconds before the
  timeout. ([#1](https://gitlab.invalid/clair/clair-agent/-/issues/1))
- A first `clair service install` on a new machine, which the `install.sh` and `install.ps1`
  one-liners run, no longer reports that the service didn't start. The service was running, but
  the readiness check didn't carry the admin token the install had just created.

## [0.3.0](https://github.com/clair-app/clair-agent/releases/tag/v0.3.0) — 2026-09-26T02:22:25Z

> The Windows builds are code-signed, so antivirus is less likely to hold back `clair.exe`.

### Added

- The Windows builds (amd64 and arm64) are Authenticode-signed by Jeffrey Mixon and timestamped,
  so the signature stays valid after the short-lived signing certificate expires. Avast held back
  the unsigned `clair.exe` and opened console windows when it ran; a signed build is less likely to
  be held. `SHA256SUMS.txt` lists the signed files.
