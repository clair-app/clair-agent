// Command clair is the host-side agent of Clair: a blind, end-to-end encrypted
// tunnel between Claude Code's http hooks on loopback and the phone, by way of
// a relay that only ever sees ciphertext.
//
// The design is `docs/RELAY.md` in the clair repository; `.agents/context/design.md`
// maps its sections onto this codebase.
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"syscall"
	"time"

	"claircode.app/clair-agent/internal/claudecfg"
	"claircode.app/clair-agent/internal/daemon"
	"claircode.app/clair-agent/internal/hookserver"
	"claircode.app/clair-agent/internal/hostname"
	"claircode.app/clair-agent/internal/logfile"
	"claircode.app/clair-agent/internal/relay"
	"claircode.app/clair-agent/internal/service"
	"claircode.app/clair-agent/internal/state"
)

// Set by the linker from the Makefile (`-X main.version=…`). The build-info
// fallback in [buildVersion] covers a plain `go build` / `go install`.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// Exit statuses.
const (
	exitOK          = 0
	exitError       = 1
	exitUsage       = 2
	exitUnreachable = 3
)

// deps are the process-level things a command needs, injected so `run` can
// be tested without a process: the environment, the clock, entropy, stdin,
// and where this binary and the home directory are; for `clair service`, the
// OS, the user, the temporary directory and a way to run the OS's commands.
type deps struct {
	getenv  func(string) string
	now     func() time.Time
	entropy io.Reader
	stdin   io.Reader
	exe     func() (string, error)
	home    func() (string, error)
	goos    string
	uid     int
	sid     func() (string, error)
	tempDir string
	runner  service.Runner
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is main without the process: arguments in, exit status out, so the
// dispatch is testable without forking. Long-running commands stop on
// SIGINT, SIGTERM and SIGHUP.
func run(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), stopSignals()...)
	defer stop()
	return runWith(ctx, deps{
		getenv: os.Getenv, now: time.Now, entropy: rand.Reader, stdin: os.Stdin, exe: os.Executable, home: os.UserHomeDir,
		goos: runtime.GOOS, uid: os.Getuid(), sid: userSID, tempDir: os.TempDir(), runner: service.Exec,
	}, args, stdout, stderr)
}

// userSID is the current user's id: on Windows, the SID a scheduled task's
// principal names.
func userSID() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	return u.Uid, nil
}

// stopSignals are the signals that end a command through its context, so it
// can clean up — `clair pair` revokes a pair it has not saved (ADR
// 2026-09.mwfw). SIGHUP, a closed terminal, is one unless it is ignored
// (nohup): Notify would undo that and stop a daemon meant to outlive its
// terminal. Windows never delivers SIGHUP.
func stopSignals() []os.Signal {
	sigs := []os.Signal{os.Interrupt, syscall.SIGTERM}
	if !signal.Ignored(syscall.SIGHUP) {
		sigs = append(sigs, syscall.SIGHUP)
	}
	return sigs
}

// runWith is run with its dependencies supplied; ctx ends a long-running command.
func runWith(ctx context.Context, d deps, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "daemon":
		return cmdDaemon(ctx, d, args[1:], stderr)
	case "pair":
		return cmdPair(ctx, d, args[1:], stdout, stderr)
	case "unpair":
		return cmdUnpair(ctx, d, args[1:], stdout, stderr)
	case "status":
		return cmdStatus(ctx, d, args[1:], stdout, stderr)
	case "statusline":
		return cmdStatusline(ctx, d, args[1:], stdout, stderr)
	case "service":
		return cmdService(ctx, d, args[1:], stdout, stderr)
	case "hook-event":
		return cmdHookEvent(ctx, d, args[1:], stderr)
	case "version":
		v, c := buildVersion()
		fmt.Fprintf(stdout, "clair %s (%s, %s)\n", v, c, date)
		return exitOK
	case "help", "-h", "--help":
		usage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "clair: unknown command %q\n\n", args[0])
		usage(stderr)
		return exitUsage
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage: clair <command> [flags]

commands:
  daemon      serve Claude Code's hooks on loopback and tunnel them to the phone
  pair        show a QR for the phone to scan; write the pair and the hooks
  unpair      revoke the pair, remove the hooks and the keys
  status      what the running agent is doing (exit 3 when it is not running)
  service     install, start, stop or remove the agent as a login service
  statusline  the statusLine command settings.json points at: forward usage, run yours
  hook-event  the SessionStart command hook: forward stdin to the agent, never fail
  version     print the agent version
  help        print this message

flags common to daemon, pair, unpair and status:
  -config-dir DIR   config directory (default $CLAIR_CONFIG_DIR, else the OS user config dir + /clair)
  -log-level LEVEL  debug, info, warn or error (default from agent.json, else info)
  -relay URL        relay base URL (default from agent.json)
  -relay-ca FILE    PEM certificate authority to trust instead of the system store

"clair <command> -h" lists a command's own flags.
`)
}

// configFlags are the flags every command that touches the config dir shares.
type configFlags struct {
	dir      string
	logLevel string
}

func (c *configFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&c.dir, "config-dir", "", "config directory")
	fs.StringVar(&c.logLevel, "log-level", "", "log level: debug, info, warn, error")
}

// openConfig resolves and opens the config directory and agent.json,
// creating both on first use.
func openConfig(d deps, flags configFlags, defaults state.Agent) (*state.Dir, state.Agent, error) {
	path := flags.dir
	if path == "" {
		var err error
		if path, err = state.DefaultDir(d.getenv); err != nil {
			return nil, state.Agent{}, err
		}
	}
	dir, err := state.Open(path)
	if err != nil {
		return nil, state.Agent{}, err
	}
	agent, created, err := dir.EnsureAgent(d.entropy, defaults)
	if err != nil {
		return nil, state.Agent{}, err
	}
	if created {
		slog.Default().Debug("agent config created", "dir", path)
	}
	return dir, agent, nil
}

// newLogger builds the text logger every command uses; the level comes from
// the flag, else agent.json, else info.
func newLogger(w io.Writer, flagLevel, fileLevel string) (*slog.Logger, error) {
	name := flagLevel
	if name == "" {
		name = fileLevel
	}
	if name == "" {
		name = "info"
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(name)); err != nil {
		return nil, fmt.Errorf("log level %q: %w", name, err)
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})), nil
}

func cmdDaemon(ctx context.Context, d deps, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("clair daemon", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cfg configFlags
	cfg.register(fs)
	listen := fs.String("listen", "", "loopback address to serve hooks on (default from agent.json, else "+hookserver.ListenDefault+")")
	logFile := fs.String("log-file", "", "write the log to this file, rotated at 10 MiB, instead of stderr")
	var rf relayFlags
	rf.register(fs)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "clair daemon: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}
	// Under launchd or Task Scheduler nobody reads stderr, so with a log
	// file everything this command says goes there, failures included.
	if *logFile != "" {
		lf, err := logfile.Open(*logFile, 0)
		if err != nil {
			fmt.Fprintf(stderr, "clair daemon: %v\n", err)
			return exitError
		}
		defer func() { _ = lf.Close() }()
		stderr = lf
	}
	dir, agent, err := openConfig(d, cfg, state.Agent{Listen: hookserver.ListenDefault, Relay: relay.DefaultBaseURL, LogLevel: "info"})
	if err != nil {
		fmt.Fprintf(stderr, "clair daemon: %v\n", err)
		return exitError
	}
	// Flags that name where things are stay in agent.json, so `clair pair`
	// and `clair status` find the daemon and the relay without repeating them.
	if (rf.url != "" && rf.url != agent.Relay) || (*listen != "" && *listen != agent.Listen) {
		if rf.url != "" {
			agent.Relay = rf.url
		}
		if *listen != "" {
			agent.Listen = *listen
		}
		if saveErr := dir.SaveAgent(agent); saveErr != nil {
			fmt.Fprintf(stderr, "clair daemon: %v\n", saveErr)
			return exitError
		}
	}
	pool, err := rf.pool()
	if err != nil {
		fmt.Fprintf(stderr, "clair daemon: %v\n", err)
		return exitUsage
	}
	log, err := newLogger(stderr, cfg.logLevel, agent.LogLevel)
	if err != nil {
		fmt.Fprintf(stderr, "clair daemon: %v\n", err)
		return exitUsage
	}
	v, _ := buildVersion()
	installer, err := snippetInstaller(d, agent, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "clair daemon: %v\n", err)
		return exitError
	}
	err = daemon.Run(ctx, daemon.Options{
		Dir:       dir,
		Agent:     agent,
		Listen:    *listen,
		Version:   v,
		Logger:    log,
		Now:       d.now,
		Entropy:   d.entropy,
		RelayCA:   pool,
		Installer: installer,
	})
	if err != nil {
		fmt.Fprintf(stderr, "clair daemon: %v\n", err)
		return exitError
	}
	return exitOK
}

// snippetInstaller edits settings.json for this host: this binary's path,
// the loopback endpoint from agent.json, and the sanitised hostname.
func snippetInstaller(d deps, agent state.Agent, stderr io.Writer) (claudecfg.SnippetInstaller, error) {
	settings, err := claudecfg.SettingsPath(d.getenv, d.home)
	if err != nil {
		return claudecfg.SnippetInstaller{}, err
	}
	exe, err := d.exe()
	if err != nil {
		return claudecfg.SnippetInstaller{}, fmt.Errorf("locate this binary: %w", err)
	}
	listen := agent.Listen
	if listen == "" {
		listen = hookserver.ListenDefault
	}
	_, portText, err := net.SplitHostPort(listen)
	if err != nil {
		return claudecfg.SnippetInstaller{}, fmt.Errorf("listen address %q: %w", listen, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return claudecfg.SnippetInstaller{}, fmt.Errorf("listen address %q: %w", listen, err)
	}
	return claudecfg.SnippetInstaller{
		Installer: claudecfg.Installer{SettingsPath: settings, ClairExe: exe, Now: d.now, Stderr: stderr},
		BaseURL:   "http://" + listen,
		Port:      port,
		Token:     agent.Token,
		Host:      hostname.Local(),
	}, nil
}

// cmdStatusline is the statusLine command settings.json points at.
func cmdStatusline(ctx context.Context, d deps, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("clair statusline", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cfg configFlags
	cfg.register(fs)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	settings, err := claudecfg.SettingsPath(d.getenv, d.home)
	if err != nil {
		fmt.Fprintf(stderr, "clair statusline: %v\n", err)
		return exitError
	}
	opts := claudecfg.StatuslineOptions{
		Stdin: d.stdin, Stdout: stdout, Stderr: stderr, SettingsPath: settings, Now: d.now, Host: hostname.Local(),
		Nested: d.getenv(claudecfg.EnvStatuslineNested) != "",
	}
	if exe, err := d.exe(); err == nil {
		opts.Exe = exe
	}
	// Without an agent.json there is nothing to forward to; the user's own
	// statusline still runs. Never create the config directory from here.
	if path := cfg.dir; path != "" {
		opts.AgentURL, opts.Token = agentEndpoint(path)
	} else if path, err := state.DefaultDir(d.getenv); err == nil {
		opts.AgentURL, opts.Token = agentEndpoint(path)
	}
	return claudecfg.RunStatusline(ctx, opts)
}

// cmdHookEvent is the SessionStart command hook (`clair hook-event <path>`).
func cmdHookEvent(ctx context.Context, d deps, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("clair hook-event", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cfg configFlags
	cfg.register(fs)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	opts := claudecfg.HookEventOptions{Stdin: d.stdin, Path: fs.Arg(0), Host: hostname.Local()}
	if path := cfg.dir; path != "" {
		opts.AgentURL, opts.Token = agentEndpoint(path)
	} else if path, err := state.DefaultDir(d.getenv); err == nil {
		opts.AgentURL, opts.Token = agentEndpoint(path)
	}
	return claudecfg.RunHookEvent(ctx, opts)
}

// agentEndpoint reads the daemon's loopback origin and bearer from an
// existing config directory; "" when there is none.
func agentEndpoint(path string) (agentURL, token string) {
	agent, ok := readAgent(path)
	if !ok || agent.Listen == "" {
		return "", ""
	}
	return "http://" + agent.Listen, agent.Token
}

// readAgent reads agent.json from a config directory without creating
// either; ok is false when there is none to read.
func readAgent(path string) (state.Agent, bool) {
	var agent state.Agent
	data, err := os.ReadFile(filepath.Join(path, "agent.json"))
	if err != nil || json.Unmarshal(data, &agent) != nil {
		return state.Agent{}, false
	}
	return agent, true
}

// buildVersion prefers the linker-injected values and falls back to what the
// Go toolchain recorded about the main module and its VCS checkout, so a
// `go install claircode.app/clair-agent/cmd/clair@vX` still reports vX.
func buildVersion() (ver, rev string) {
	ver, rev = version, commit
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ver, rev
	}
	if ver == "dev" && info.Main.Version != "" && info.Main.Version != "(devel)" {
		ver = info.Main.Version
	}
	if rev == "none" {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 7 {
				rev = s.Value[:7]
			}
		}
	}
	return ver, rev
}
