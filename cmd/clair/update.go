package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"time"

	"claircode.app/clair-agent/internal/ctl"
	"claircode.app/clair-agent/internal/daemon"
	"claircode.app/clair-agent/internal/service"
	"claircode.app/clair-agent/internal/state"
	"claircode.app/clair-agent/internal/update"
)

// testKeyLine is the second line of `clair version` for a build that trusts
// a release test key. Both `make dist` and clair-web's `pin` refuse such a
// build.
const testKeyLine = "built with a release test key"

// newUpdater builds the self-updater for this binary, or says why this
// build does not update itself (ADR 2026-09.qk6v). A releases URL
// overrides agent.json's release server; enabled gates the background check.
func newUpdater(d deps, agent state.Agent, releases string, log *slog.Logger, enabled func() bool) (*update.Updater, string) {
	if !update.IsRelease(d.release) {
		return nil, fmt.Sprintf("this is a development build (%s); only a release build updates itself", d.release)
	}
	exe, err := d.exe()
	if err == nil {
		exe, err = service.ResolveExe(exe, d.tempDir)
	}
	if err != nil {
		return nil, fmt.Sprintf("cannot tell where this binary is: %v", err)
	}
	keys := update.ReleaseKeys()
	if d.releaseTestKey != "" {
		k, keyErr := update.ParseKey(d.releaseTestKey)
		if keyErr != nil {
			return nil, fmt.Sprintf("the release test key built in is unreadable: %v", keyErr)
		}
		keys = append(keys, k)
	}
	if releases == "" {
		releases = agent.Releases
	}
	u, err := update.New(update.Options{
		Current:    d.release,
		Exe:        exe,
		Releases:   releases,
		Keys:       keys,
		GOOS:       d.goos,
		GOARCH:     d.goarch,
		RunVersion: d.runVersion,
		Enabled:    enabled,
		Logger:     log,
		Now:        d.now,
		Entropy:    d.entropy,
	})
	if err != nil {
		return nil, err.Error()
	}
	return u, ""
}

// cmdUpdate asks the running daemon to check for a release and stage it, so
// it is the daemon's binary that is replaced and its status stays true; with
// no daemon, or one older than the self-updater, it runs the check itself.
func cmdUpdate(ctx context.Context, d deps, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("clair update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cfg configFlags
	cfg.register(fs)
	check := fs.Bool("check", false, "only say whether a newer release exists")
	releases := fs.String("releases", "", "release server to read this once (default from agent.json, else "+update.DefaultReleasesURL+")")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "clair update: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}
	path := cfg.dir
	if path == "" {
		var err error
		if path, err = state.DefaultDir(d.getenv); err != nil {
			fmt.Fprintf(stderr, "clair update: %v\n", err)
			return exitError
		}
	}
	req := ctl.UpdateRequest{Check: *check, Releases: *releases}
	agent, haveAgent := readAgent(path)
	if haveAgent {
		res, err := controlClient(agent).Update(ctx, req)
		switch {
		case err == nil:
			return printUpdate(stdout, stderr, res, true)
		case errors.Is(err, ctl.ErrUnreachable), errors.Is(err, ctl.ErrNotFound):
			// No daemon, or one from before the self-updater: do it here.
		default:
			fmt.Fprintf(stderr, "clair update: %v\n", err)
			return exitError
		}
	}
	log, err := newLogger(stderr, cfg.logLevel, "warn")
	if err != nil {
		fmt.Fprintf(stderr, "clair update: %v\n", err)
		return exitUsage
	}
	u, off := newUpdater(d, agent, *releases, log, nil)
	if u == nil {
		return printUpdate(stdout, stderr, ctl.UpdateResult{Outcome: ctl.OutcomeOff, Running: d.release, Note: off}, false)
	}
	res, err := u.Check(ctx, update.Request{Stage: !*check})
	return printUpdate(stdout, stderr, daemon.UpdateResult(d.release, res, err), false)
}

// printUpdate reports an update check to a person; viaDaemon says a daemon
// is running, and runs the old binary until it restarts.
func printUpdate(stdout, stderr io.Writer, res ctl.UpdateResult, viaDaemon bool) int {
	switch res.Outcome {
	case ctl.OutcomeUpToDate:
		if res.Running == res.Latest {
			fmt.Fprintf(stdout, "clair %s is the latest release.\n", res.Running)
		} else {
			fmt.Fprintf(stdout, "clair %s is newer than the latest release, %s.\n", res.Running, res.Latest)
		}
	case ctl.OutcomeAvailable:
		fmt.Fprintf(stdout, "clair %s is available (this is %s); `clair update` installs it.\n", res.Latest, res.Running)
	case ctl.OutcomeStaged, ctl.OutcomeAlreadyStaged:
		if res.Outcome == ctl.OutcomeStaged {
			fmt.Fprintf(stdout, "Installed clair %s at %s.\n", res.Latest, res.Path)
		} else {
			fmt.Fprintf(stdout, "clair %s is already installed at %s.\n", res.Latest, res.Path)
		}
		if viaDaemon {
			fmt.Fprintf(stdout, "The agent runs %s until it restarts; `clair service restart` switches now.\n", res.Running)
		} else {
			fmt.Fprintln(stdout, "The agent runs it from its next start.")
		}
	case ctl.OutcomeLeftAlone:
		fmt.Fprintf(stdout, "Nothing installed: %s.\n", res.Note)
	case ctl.OutcomeOff:
		fmt.Fprintf(stderr, "clair update: %s\n", res.Note)
		return exitError
	case ctl.OutcomeFailed:
		fmt.Fprintf(stderr, "clair update: %s\n", res.Error)
		return exitError
	default:
		fmt.Fprintf(stderr, "clair update: the agent answered %q\n", res.Outcome)
		return exitError
	}
	return exitOK
}

// printUpdateStatus is `clair status`'s line about releases; nothing for a
// daemon older than the self-updater.
func printUpdateStatus(w io.Writer, u *ctl.UpdateStatus) {
	if u == nil {
		return
	}
	if u.Off != "" {
		fmt.Fprintf(w, "updates: off — %s\n", u.Off)
		return
	}
	switch {
	case u.Staged != "":
		fmt.Fprintf(w, "updates: clair %s is installed and runs from the next start (`clair service restart`)\n", u.Staged)
	case u.LastError != "":
		fmt.Fprintf(w, "updates: the check at %s failed (%s)\n", u.LastCheckAt.Local().Format(time.DateTime), u.LastError)
	case u.Note != "":
		fmt.Fprintf(w, "updates: %s\n", u.Note)
	case !u.LastCheckAt.IsZero():
		fmt.Fprintf(w, "updates: up to date (latest %s, checked %s)\n", u.Latest, u.LastCheckAt.Local().Format(time.DateTime))
	default:
		fmt.Fprintln(w, "updates: not checked yet")
	}
	if u.Paused {
		fmt.Fprintln(w, "updates: background checks are off (autoUpdate in agent.json); `clair update` checks now")
	}
}

// printSkew says when the running agent is not the release this command
// is: after a self-update, until the agent restarts (ADR 2026-09.66m4).
func printSkew(w io.Writer, self string, st ctl.Status) {
	if !update.IsRelease(self) || !update.IsRelease(st.Version) || self == st.Version {
		return
	}
	if st.Update != nil && st.Update.Staged == self {
		return // the updates line says it
	}
	fmt.Fprintf(w, "note: the agent runs clair %s and this command is %s; `clair service restart` restarts the agent on the installed binary\n", st.Version, self)
}
