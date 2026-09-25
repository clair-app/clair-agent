---
id: "2026-09.pz5g"
slug: on-windows-the-daemon-supervises-itself
title: "On Windows the daemon supervises itself, because Task Scheduler cannot see a crash through conhost"
date: 2026-09-25
topics: [daemon, windows, install]
---

# ADR 2026-09.pz5g — On Windows the daemon supervises itself, because Task Scheduler cannot see a crash through conhost

Status: Accepted (2026-09-25)

**What was observed.** The service ran for real on `win11` on 2026-09-25: Windows 11 build 26200,
the user signed in at the console, and the task installed without elevation. The Scheduled Task
of ADR 2026-09.ahq8 started, stopped and self-updated as designed. A crash did not restart it:

- After `clair.exe` was killed, the task went to Ready with Last Result 0, and nothing came back
  in 150 s.
- `conhost --headless cmd /c exit 3` exits 0: the headless console host never passes on its
  child's exit code.
- So `RestartOnFailure` (count 999, every minute) only ever sees a success. It restarts a launch
  that fails, and nothing else.
- systemd (`Restart=on-failure`) and launchd (`KeepAlive {SuccessfulExit false}`) read the
  daemon's own exit code, and restart it.

**What changed.**

- **`clair daemon -supervise`** (`internal/supervisor`, `cmd/clair/supervise.go`) runs the daemon
  as its own child, with every flag it was given but this one, from the binary's path.
  - An exit that is not clean starts it again, after 5 s, doubling to 5 min while the child
    keeps dying within a minute. A child that ran for a minute resets the pause.
  - A clean exit, which is how a stop through `/clair/ctl/stop` or a handled signal ends,
    ends the supervisor too. So `clair service stop` still stops it.
  - Because the child starts from the path, a crash restart runs a release the self-update
    staged (ADR 2026-09.qk6v).
- **When the supervisor is told to stop,** it asks the daemon to stop through the control
  surface, waits up to 10 s, then ends it.
- **The log.** The supervisor and the daemon's stderr (a panic) are appended to the daemon's
  `-log-file` one write at a time, because the daemon holds and rotates that file.
- **`Manager.RestartsOnCrash`** is false for the task alone, and `clair service install` adds
  `-supervise` there. The task XML keeps `RestartOnFailure` for a launch that fails.

**The alternatives.**

- A repeating task trigger (relaunch every few minutes, `IgnoreNew`) needs no code. But it would
  undo `clair service stop` within minutes unless stop also disabled the task, which changes
  what stop means next to systemd and launchd.
- Dropping `conhost --headless` for a GUI-subsystem build would pass the exit code on. It costs
  a second binary, or a console that flashes a window, and Task Scheduler still restarts only a
  failed launch.
- A real Windows service would be blind to presence (ADR 2026-09.ahq8).

**Verified on `win11` under the real task, and in the `windows` CI job (ADR 2026-09.6w38).**

- Non-elevated install.
- The process tree: `conhost --headless`, then the supervisor, then the daemon, all in the
  user's session.
- A killed daemon is back in 5.2 s, and in 10.1 s when it died again after 2 s.
- A daemon killed after `clair update` staged v0.0.2 came back on v0.0.2 with no service
  restart.
- `clair service stop` ended the supervisor ("daemon stopped cleanly").

**What it costs and what it does not cover.**

- **Two processes.** A kill of the supervisor itself, or of conhost, is not restarted until the
  next logon, as before.
- **No clean stop at sign-out.** Signing the user out of `win11` ended conhost, the supervisor
  and the daemon within 1.6 s. The daemon exited `0x40010004`, the session teardown's termination
  code. The supervisor logged only that the daemon had exited, and the daemon never logged a
  stop. Neither saw a console control event under the headless console.
  - Held decides go unanswered, but Claude Code in that session ends too.
  - No `cancel` goes to the phone.
  - The stream is not released, so the relay ages it out (ADR 2026-09.hu4b).
  - The queue in memory is lost.
  - The replay counters are safe by block reservation (ADR 2026-09.hzwt), and the next start
    sends `reset`.

  Catching `WM_QUERYENDSESSION` / `WM_ENDSESSION` in a hidden top-level window is the known way
  to get that notice. It is not built.
- **One start is not verified:** the task starting at the user's next logon.
