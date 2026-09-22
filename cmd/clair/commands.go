package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"claircode.app/clair-agent/internal/claudecfg"
	"claircode.app/clair-agent/internal/ctl"
	"claircode.app/clair-agent/internal/hookserver"
	"claircode.app/clair-agent/internal/hostname"
	"claircode.app/clair-agent/internal/pairing"
	"claircode.app/clair-agent/internal/relay"
	"claircode.app/clair-agent/internal/state"
)

// relayFlags are the flags every command that talks to the relay shares.
type relayFlags struct {
	url string
	ca  string
}

func (r *relayFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&r.url, "relay", "", "relay base URL (default from agent.json, else "+relay.DefaultBaseURL+")")
	fs.StringVar(&r.ca, "relay-ca", "", "PEM file with the relay's certificate authority; replaces the system trust store")
}

// pool loads --relay-ca, or returns nil for the system store.
func (r *relayFlags) pool() (*x509.CertPool, error) {
	if r.ca == "" {
		return nil, nil //nolint:nilnil // nil pool means the system store, by http.Transport's own convention
	}
	pem, err := os.ReadFile(r.ca)
	if err != nil {
		return nil, fmt.Errorf("read --relay-ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("--relay-ca %s holds no certificate", r.ca)
	}
	return pool, nil
}

// controlClient talks to a running daemon through agent.json's admin token.
func controlClient(agent state.Agent) *ctl.Client {
	listen := agent.Listen
	if listen == "" {
		listen = hookserver.ListenDefault
	}
	return &ctl.Client{Base: "http://" + listen, AdminToken: agent.AdminToken}
}

// defaultQRMode picks half-blocks, except on a Windows console that is not
// Windows Terminal, where UTF-8 output is not a given.
func defaultQRMode(getenv func(string) string) pairing.QRMode {
	if runtime.GOOS == "windows" && getenv("WT_SESSION") == "" {
		return pairing.QRASCII
	}
	return pairing.QRUnicode
}

func cmdPair(ctx context.Context, d deps, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("clair pair", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cfg configFlags
	cfg.register(fs)
	var rf relayFlags
	rf.register(fs)
	qrMode := fs.String("qr", string(defaultQRMode(d.getenv)), "how to draw the QR: unicode, ascii or none")
	invert := fs.Bool("invert", false, "draw the QR for a light terminal background")
	replace := fs.Bool("replace", false, "replace an existing pair without asking (new keys on both sides)")
	yes := fs.Bool("yes", false, "do not ask before pairing with the phone that completed the code")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "clair pair: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}
	mode := pairing.QRMode(*qrMode)
	if mode != pairing.QRUnicode && mode != pairing.QRASCII && mode != pairing.QRNone {
		fmt.Fprintf(stderr, "clair pair: -qr must be unicode, ascii or none\n")
		return exitUsage
	}
	dir, agent, err := openConfig(d, cfg, state.Agent{Listen: hookserver.ListenDefault, Relay: relay.DefaultBaseURL, LogLevel: "info"})
	if err != nil {
		fmt.Fprintf(stderr, "clair pair: %v\n", err)
		return exitError
	}
	if rf.url != "" && rf.url != agent.Relay {
		agent.Relay = rf.url
		if saveErr := dir.SaveAgent(agent); saveErr != nil {
			fmt.Fprintf(stderr, "clair pair: %v\n", saveErr)
			return exitError
		}
	}
	pool, err := rf.pool()
	if err != nil {
		fmt.Fprintf(stderr, "clair pair: %v\n", err)
		return exitUsage
	}
	installer, err := snippetInstaller(d, agent, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "clair pair: %v\n", err)
		return exitError
	}
	v, _ := buildVersion()
	opts := pairing.Options{
		Dir:      dir,
		RelayURL: agent.Relay,
		NewRelay: func(baseURL string, auth ed25519.PrivateKey) (pairing.Relay, error) {
			return relay.New(auth, relay.Options{BaseURL: baseURL, RootCAs: pool, UserAgent: "clair-agent/" + v, Now: d.now})
		},
		Daemon: controlClient(agent),
		Install: func(snippet json.RawMessage) error {
			if snippet == nil {
				_, err := installer.Install(claudecfg.RenderHooks(claudecfg.SnippetConfig{
					BaseURL: installer.BaseURL, Token: installer.Token, Host: installer.Host, IncludeSessionStart: true, ClairExe: installer.ClairExe,
				}))
				return err
			}
			return installer.InstallSnippet(snippet)
		},
		Uninstall:    installer.Uninstall,
		Stdout:       stdout,
		Stderr:       stderr,
		Term:         pairing.OpenTerminal(),
		QR:           mode,
		Invert:       *invert,
		Replace:      *replace,
		Yes:          *yes,
		Now:          d.now,
		Entropy:      d.entropy,
		Hostname:     hostname.Local(),
		AgentVersion: v,
	}
	if err := pairing.Pair(ctx, opts); err != nil {
		fmt.Fprintf(stderr, "clair pair: %v\n", err)
		return exitError
	}
	return exitOK
}

func cmdUnpair(ctx context.Context, d deps, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("clair unpair", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cfg configFlags
	cfg.register(fs)
	var rf relayFlags
	rf.register(fs)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	dir, agent, err := openConfig(d, cfg, state.Agent{Listen: hookserver.ListenDefault, Relay: relay.DefaultBaseURL, LogLevel: "info"})
	if err != nil {
		fmt.Fprintf(stderr, "clair unpair: %v\n", err)
		return exitError
	}
	pool, err := rf.pool()
	if err != nil {
		fmt.Fprintf(stderr, "clair unpair: %v\n", err)
		return exitUsage
	}
	installer, err := snippetInstaller(d, agent, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "clair unpair: %v\n", err)
		return exitError
	}
	v, _ := buildVersion()
	opts := pairing.Options{
		Dir: dir,
		NewRelay: func(baseURL string, auth ed25519.PrivateKey) (pairing.Relay, error) {
			return relay.New(auth, relay.Options{BaseURL: baseURL, RootCAs: pool, UserAgent: "clair-agent/" + v, Now: d.now})
		},
		Daemon:    controlClient(agent),
		Uninstall: installer.Uninstall,
		Stdout:    stdout,
		Stderr:    stderr,
	}
	if err := pairing.Unpair(ctx, opts); err != nil {
		fmt.Fprintf(stderr, "clair unpair: %v\n", err)
		return exitError
	}
	return exitOK
}

func cmdStatus(ctx context.Context, d deps, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("clair status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cfg configFlags
	cfg.register(fs)
	asJSON := fs.Bool("json", false, "print the daemon's status as JSON")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	path := cfg.dir
	if path == "" {
		var err error
		if path, err = state.DefaultDir(d.getenv); err != nil {
			fmt.Fprintf(stderr, "clair status: %v\n", err)
			return exitError
		}
	}
	dir, err := state.Open(path)
	if err != nil {
		fmt.Fprintf(stderr, "clair status: %v\n", err)
		return exitError
	}
	agent, err := dir.LoadAgent()
	if errors.Is(err, state.ErrNotFound) {
		fmt.Fprintln(stdout, "clair is not set up on this machine; run `clair pair`.")
		return exitUnreachable
	}
	if err != nil {
		fmt.Fprintf(stderr, "clair status: %v\n", err)
		return exitError
	}
	st, err := controlClient(agent).Status(ctx)
	if err != nil {
		if errors.Is(err, ctl.ErrUnreachable) {
			fmt.Fprintf(stdout, "no agent is running on %s; start it with `clair daemon`.\n", agent.Listen)
			return exitUnreachable
		}
		fmt.Fprintf(stderr, "clair status: %v\n", err)
		return exitError
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(st); err != nil {
			fmt.Fprintf(stderr, "clair status: %v\n", err)
			return exitError
		}
		return exitOK
	}
	printStatus(stdout, st)
	return exitOK
}

// printStatus renders ctl.Status for a person.
func printStatus(w io.Writer, st ctl.Status) {
	fmt.Fprintf(w, "clair %s — listening on %s, relay %s, up %s\n", st.Version, st.Listen, st.Relay, (time.Duration(st.UptimeSec) * time.Second).String())
	if st.Presence != nil {
		fmt.Fprintf(w, "terminal input: idle %s (%s)\n", (time.Duration(st.Presence.IdleMs) * time.Millisecond).Round(time.Second), st.Presence.Source)
	} else {
		fmt.Fprintln(w, "terminal input: no signal — subagent prompts are never handed to the terminal")
	}
	if !st.Paired {
		if st.Unpaired != "" {
			fmt.Fprintf(w, "not paired (%s) — run `clair pair`\n", st.Unpaired)
		} else {
			fmt.Fprintln(w, "not paired — run `clair pair`")
		}
		return
	}
	for i := range st.Pairs {
		p := &st.Pairs[i]
		fmt.Fprintf(w, "paired with %q (fingerprint %s)\n", p.PhoneName, p.Fingerprint)
		phone := p.Phone
		if !p.PhoneSeenAt.IsZero() {
			phone += " since " + p.PhoneSeenAt.Local().Format("15:04:05")
		}
		fmt.Fprintf(w, "  phone: %s   queue: %d records (%d bytes)   held decides: %d\n", phone, p.QueueRecords, p.QueueBytes, p.Held)
		fmt.Fprintf(w, "  uploader: %s%s   stream: %s%s   clock skew: %ds\n", p.Uploader.State, lastError(p.Uploader), p.Stream.State, lastError(p.Stream), p.SkewSec)
		if p.IdleThresholdSec > 0 {
			fmt.Fprintf(w, "  subagent prompts go to the terminal while input is under %ds idle\n", p.IdleThresholdSec)
		} else {
			fmt.Fprintln(w, "  subagent prompts are always held for the phone")
		}
	}
}

func lastError(l ctl.Link) string {
	if l.LastError == "" {
		return ""
	}
	return " (" + l.LastError + ")"
}
