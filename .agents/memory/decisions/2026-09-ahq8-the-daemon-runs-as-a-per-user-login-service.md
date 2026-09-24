---
id: "2026-09.ahq8"
slug: the-daemon-runs-as-a-per-user-login-service
title: "The daemon runs as a per-user login service, never a system service"
date: 2026-09-23
topics: [daemon, cli, install]
---

# ADR 2026-09.ahq8 — The daemon runs as a per-user login service, never a system service

Status: Accepted (2026-09-23); the macOS and Windows halves await a pass on real hardware

**What was observed.** Until now `clair daemon` ran in a terminal. RELAY.md §6 has `install.sh`
set up "binary + user service, then `clair pair`", and §15 left Windows open, favouring "a
per-user logon Scheduled Task running `conhost --headless clair daemon`".

What decides it is presence (§4.3, ADR 2026-09.34qh). The daemon reads the user's terminal input
idle: the access times of the user's own `/dev/pts/*` or `/dev/ttys*`, or `GetLastInputInfo` on
Windows. `GetLastInputInfo` covers only the calling session's desktop. A Windows service runs in
session 0 and would always read "no signal", so no subagent prompt would ever be handed to the
terminal. The daemon also rewrites the user's `settings.json` and keeps its keys under the user's
config dir. It is the user's process in every way that matters.

**What changed.** `clair service install | uninstall | start | stop | restart | status`
(`internal/service`, `cmd/clair/service.go`) registers this binary with the OS's own manager,
as the user, never elevated:

| OS | Mechanism | Where | Log |
| --- | --- | --- | --- |
| Linux | systemd **user** unit, `Restart=on-failure` | `$XDG_CONFIG_HOME/systemd/user/clair.service` | journald (`journalctl --user -u clair`) |
| macOS | **LaunchAgent** in `gui/<uid>`, `KeepAlive {SuccessfulExit false}`, `ProcessType Interactive` | `~/Library/LaunchAgents/app.claircode.clair.plist` | `~/Library/Logs/clair/daemon.log` via `-log-file` |
| Windows | **Scheduled Task** on the user's logon, `InteractiveToken`, `LeastPrivilege`, no 72 h limit, priority 5, action `conhost.exe --headless "<exe>" daemon …` | task `\clair`; the XML registered from is kept at `%LocalAppData%\clair\clair-task.xml` | `%LocalAppData%\clair\daemon.log` via `-log-file` |

- **The binary is used where it is.** The service runs the resolved `os.Executable()`, the same
  path the hooks in `settings.json` already name. A `go run` build or anything under the temp
  dir is refused. Putting the binary somewhere stable is `install.sh`'s job.
- **The environment the daemon needs is captured at install**, because no manager passes on the
  shell's: `CLAUDE_CONFIG_DIR` (the daemon rewrites `settings.json`), the proxy variables
  (RELAY.md §12), `SSL_CERT_FILE` and `SSL_CERT_DIR`. They go into `Environment=` or
  `EnvironmentVariables`. The config dir goes in as `-config-dir`, and a `-relay-ca` given to
  `install` is passed on. A task cannot carry an environment, so on Windows `install` warns about any of
  these that is set in the shell but not in `HKCU\Environment`.
- **A stop is always clean.** systemd and launchd send SIGTERM, which the daemon already handles.
  `schtasks /End` is `TerminateProcess`: no held decide answered, no `cancel`, no stream released
  (ADR 2026-09.hu4b). So the control surface gained `POST /clair/ctl/stop`, which cancels
  `daemon.Run`'s context and takes the signal's path out (admin token, ADR 2026-09.r7kd). The
  task's `Stop` calls it, waits up to 5 s for the listener to go, then `/End` cleans up. A clean
  exit is not a failure, so no manager restarts a daemon stopped that way.
- **`clair daemon -log-file`** (`internal/logfile`): 10 MiB, one `.1` generation, `0600` in a
  `0700` directory. Nobody reads a LaunchAgent's or a task's stderr, and launchd's
  `StandardErrorPath` grows without bound, so it only catches panics.
- `install` refuses while another daemon answers on `agent.Listen` and the manager says the
  service is not running: that is a `clair daemon` in a terminal, which would win the port. After
  starting, `install` waits for the control surface to answer before it says so. `clair pair`
  does not install anything; its hint names `clair service install`.

**The alternatives.** A real Windows service is the first thing a reader reaches for, and it is
blind to presence, as above. An `HKCU\…\Run` entry needs no Task Scheduler but has no restart
and no clean stop. It is the fallback if a non-elevated logon-trigger registration turns out to
be refused. A root systemd unit or a LaunchDaemon would run outside the user's session and
touch another user's files. `sd_notify` / `Type=notify` would save the poll, but polling the
control surface is one mechanism for all three.

**What it costs and what it does not cover.** Every platform's file is rendered by a pure
function with golden files (`internal/service/testdata`), and every command sequence is tested
against a fake `Runner`, all on Linux CI. `cmd/clair/service_test.go` runs install → status →
stop → uninstall against a fake `systemctl` whose `start` runs a real in-process daemon. On
Linux it was also checked for real: a systemd user unit, a pairing through `tools/phonesim`, a
decide answered, `kill -9` restarted in 5 s, presence read as `pty` from inside the unit, a ctl
stop left the unit inactive.

Still unverified on hardware, and the traps to check:

- **macOS**, none of it: `bootstrap` / `bootout` / `kickstart -k`, whether `ProcessType
  Interactive` is warranted, the "Background Items Added" prompt on macOS 13 and later.
- **Windows**, the whole list:
  - a non-elevated `/Create` with a `LogonTrigger` for the user's own SID;
  - `schtasks /XML` reading the UTF-16LE file with its BOM;
  - `RestartOnFailure` `Count` 999 being in range;
  - `conhost --headless` passing the quoted command line through, and showing no window under
    Windows Terminal as the default terminal;
  - a logoff delivering `CTRL_LOGOFF_EVENT` as SIGTERM through the headless console.
- Replacing a running `clair.exe` for an upgrade is not handled, and belongs with `install.sh`
  and releases.

Where the Windows results differ, this ADR is superseded, not edited.
