package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"claircode.app/clair-agent/internal/ctl"
	"claircode.app/clair-agent/internal/hookserver"
	"claircode.app/clair-agent/internal/relay"
	"claircode.app/clair-agent/internal/service"
	"claircode.app/clair-agent/internal/state"
)

// readyWait bounds how long install, start and restart wait for the daemon
// to answer on the loopback.
const readyWait = 10 * time.Second

func serviceUsage(w io.Writer) {
	fmt.Fprint(w, `usage: clair service <command> [flags]

Run the agent as a login service of this user: a systemd user unit on Linux,
a launchd agent on macOS, a scheduled task on Windows.

commands:
  install    register the service for this binary and start it
  uninstall  stop the service and remove it (the pair and the hooks stay)
  start, stop, restart
  status     the service's state, whether the agent answers, where the logs are

flags:
  -config-dir DIR  config directory the service runs with (default as for clair daemon)
  install -relay-ca FILE  PEM certificate authority the daemon trusts instead of the system store
  install -no-start       register without starting
  install -print          print the unit, plist or task XML and change nothing
`)
}

func cmdService(ctx context.Context, d deps, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		serviceUsage(stderr)
		return exitUsage
	}
	verb := args[0]
	switch verb {
	case "install", "uninstall", "start", "stop", "restart", "status":
	case "help", "-h", "--help":
		serviceUsage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "clair service: unknown command %q\n\n", verb)
		serviceUsage(stderr)
		return exitUsage
	}
	name := "clair service " + verb
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	configDir := fs.String("config-dir", "", "config directory")
	var relayCA *string
	var noStart, printOnly *bool
	if verb == "install" {
		relayCA = fs.String("relay-ca", "", "PEM file with the relay's certificate authority; replaces the system trust store")
		noStart = fs.Bool("no-start", false, "register the service without starting it")
		printOnly = fs.Bool("print", false, "print what would be registered and change nothing")
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "%s: unexpected argument %q\n", name, fs.Arg(0))
		return exitUsage
	}

	dirPath := *configDir
	if dirPath == "" {
		var err error
		if dirPath, err = state.DefaultDir(d.getenv); err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", name, err)
			return exitError
		}
	}
	dirPath, err := filepath.Abs(dirPath)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", name, err)
		return exitError
	}
	// agent.json names the loopback and the admin token; without one the
	// defaults stand in, and nothing answers them.
	agent := state.Agent{Listen: hookserver.ListenDefault}
	if a, ok := readAgent(dirPath); ok && a.Listen != "" {
		agent = a
	}
	control := controlClient(agent)
	s := serviceCmd{name: name, control: control, stdout: stdout, stderr: stderr, release: d.release}
	if s.m, err = newServiceManager(d, control); err != nil {
		return s.fail(err)
	}
	m := s.m
	switch verb {
	case "install":
		return s.install(ctx, d, dirPath, *relayCA, *noStart, *printOnly)
	case "uninstall":
		return s.uninstall(ctx)
	case "start":
		return s.act(ctx, m.Start, "started")
	case "stop":
		return s.act(ctx, m.Stop, "stopped")
	case "restart":
		return s.act(ctx, m.Restart, "restarted")
	default:
		return s.status(ctx, agent)
	}
}

// newServiceManager picks the service manager for this OS; the user's SID
// is looked up only where a task needs it.
func newServiceManager(d deps, control *ctl.Client) (service.Manager, error) {
	home, err := d.home()
	if err != nil {
		return nil, fmt.Errorf("home directory: %w", err)
	}
	env := service.Env{Getenv: d.getenv, Home: home, UID: d.uid, Run: d.runner, Daemon: control}
	if d.goos == "windows" && d.sid != nil {
		if env.SID, err = d.sid(); err != nil {
			return nil, fmt.Errorf("look up this user: %w", err)
		}
	}
	return service.ForOS(d.goos, env)
}

// serviceCmd is one `clair service` invocation.
type serviceCmd struct {
	name           string
	m              service.Manager
	control        *ctl.Client
	stdout, stderr io.Writer
	// release is this binary's linker-stamped version.
	release string
}

// fail reports err, with what to do instead when the manager is missing.
func (s serviceCmd) fail(err error) int {
	fmt.Fprintf(s.stderr, "%s: %v\n", s.name, err)
	if errors.Is(err, service.ErrNoManager) || errors.Is(err, service.ErrUnsupported) {
		fmt.Fprintln(s.stderr, "Run `clair daemon` under your own supervisor instead; `clair service install -print` shows what would be registered.")
	}
	return exitError
}

func (s serviceCmd) install(ctx context.Context, d deps, dirPath, relayCA string, noStart, printOnly bool) int {
	exe, err := d.exe()
	if err != nil {
		return s.fail(fmt.Errorf("locate this binary: %w", err))
	}
	if exe, err = service.ResolveExe(exe, d.tempDir); err != nil {
		return s.fail(err)
	}
	spec := service.Spec{Exe: exe, Args: []string{"daemon", "-config-dir", dirPath}, Env: service.CaptureEnv(d.getenv)}
	if relayCA != "" {
		ca, caErr := filepath.Abs(relayCA)
		if caErr != nil {
			return s.fail(caErr)
		}
		spec.Args = append(spec.Args, "-relay-ca", ca)
	}
	if lf := s.m.LogFile(); lf != "" {
		spec.Args = append(spec.Args, "-log-file", lf)
	}
	if !s.m.RestartsOnCrash() {
		spec.Args = append(spec.Args, "-supervise")
	}
	if printOnly {
		text, renderErr := s.m.Render(spec)
		if renderErr != nil {
			return s.fail(renderErr)
		}
		_, _ = s.stdout.Write(text)
		return exitOK
	}

	// The daemon reads agent.json when it starts; make it exist, with the
	// defaults `clair daemon` would write.
	if _, _, err = openConfig(d, configFlags{dir: dirPath}, state.Agent{Listen: hookserver.ListenDefault, Relay: relay.DefaultBaseURL, LogLevel: "info"}); err != nil {
		return s.fail(err)
	}
	before, err := s.m.State(ctx)
	if err != nil {
		return s.fail(err)
	}
	if !before.Running {
		if _, statusErr := s.control.Status(ctx); statusErr == nil {
			fmt.Fprintf(s.stderr, "%s: a clair daemon is already answering on %s; stop it first (Ctrl-C in its terminal).\n", s.name, s.control.Base)
			return exitError
		}
	}
	for _, kv := range service.MissingFromUserEnv(spec.Env) {
		fmt.Fprintf(s.stderr, "%s: warning: %s is set in this shell only, and a scheduled task will not see it; set it with `setx` and reinstall.\n", s.name, kv)
	}
	changed, err := s.m.Install(ctx, spec)
	if err != nil {
		return s.fail(err)
	}
	if changed {
		fmt.Fprintf(s.stdout, "Installed the %s %s.\n", s.m.Kind(), s.m.Path())
	} else {
		fmt.Fprintf(s.stdout, "The %s %s is already installed as it should be.\n", s.m.Kind(), s.m.Path())
	}
	switch {
	case noStart:
		if changed && before.Running {
			fmt.Fprintln(s.stdout, "The running agent still has the old settings; `clair service restart` applies them.")
		}
		return exitOK
	case before.Running && changed:
		err = s.m.Restart(ctx)
	case !before.Running:
		err = s.m.Start(ctx)
	}
	if err != nil {
		return s.fail(err)
	}
	return s.ready(ctx, "running")
}

func (s serviceCmd) uninstall(ctx context.Context) int {
	err := s.m.Uninstall(ctx)
	if errors.Is(err, service.ErrNotInstalled) {
		fmt.Fprintln(s.stdout, "The clair service is not installed.")
		return exitOK
	}
	if err != nil {
		return s.fail(err)
	}
	fmt.Fprintf(s.stdout, "Removed the %s %s. The pair and the hooks stay; `clair unpair` removes them.\n", s.m.Kind(), s.m.Path())
	return exitOK
}

func (s serviceCmd) act(ctx context.Context, do func(context.Context) error, done string) int {
	if err := do(ctx); err != nil {
		if errors.Is(err, service.ErrNotInstalled) {
			fmt.Fprintf(s.stderr, "%s: the clair service is not installed; `clair service install` sets it up.\n", s.name)
			return exitError
		}
		return s.fail(err)
	}
	if done == "stopped" {
		fmt.Fprintln(s.stdout, "The clair service is stopped.")
		return exitOK
	}
	return s.ready(ctx, done)
}

// ready waits for the daemon to answer on the loopback.
func (s serviceCmd) ready(ctx context.Context, done string) int {
	ctx, cancel := context.WithTimeout(ctx, readyWait)
	defer cancel()
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		st, err := s.control.Status(ctx)
		if err == nil {
			fmt.Fprintf(s.stdout, "The clair service is %s: clair %s on %s. Logs: %s\n", done, st.Version, st.Listen, s.m.Logs())
			if !st.Paired {
				fmt.Fprintln(s.stdout, "Next: `clair pair` to pair a phone.")
			}
			return exitOK
		}
		select {
		case <-ctx.Done():
			fmt.Fprintf(s.stderr, "%s: the agent did not answer on %s within %s; see %s\n", s.name, s.control.Base, readyWait, s.m.Logs())
			return exitError
		case <-tick.C:
		}
	}
}

func (s serviceCmd) status(ctx context.Context, agent state.Agent) int {
	st, err := s.m.State(ctx)
	if err != nil {
		return s.fail(err)
	}
	switch {
	case !st.Installed:
		fmt.Fprintf(s.stdout, "service: not installed (%s %s); `clair service install` sets it up\n", s.m.Kind(), s.m.Path())
	case st.Detail != "":
		fmt.Fprintf(s.stdout, "service: %s %s, %s\n", s.m.Kind(), s.m.Path(), st.Detail)
	default:
		fmt.Fprintf(s.stdout, "service: %s %s\n", s.m.Kind(), s.m.Path())
	}
	status, err := s.control.Status(ctx)
	if err != nil {
		fmt.Fprintf(s.stdout, "agent:   not answering on %s\n", agent.Listen)
	} else {
		fmt.Fprintf(s.stdout, "agent:   clair %s answering on %s, up %s\n", status.Version, status.Listen, (time.Duration(status.UptimeSec) * time.Second).String())
		printSkew(s.stdout, s.release, status)
	}
	if st.Installed {
		fmt.Fprintf(s.stdout, "logs:    %s\n", s.m.Logs())
	}
	if err != nil {
		return exitUnreachable
	}
	return exitOK
}
