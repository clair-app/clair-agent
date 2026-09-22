// Package daemon wires the agent's long-running process: the loopback hook
// listener, the tunnel to the relay, and the control surface the CLI talks
// to. `clair daemon` is a thin caller of Run.
package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"claircode.app/clair-agent/internal/ctl"
	"claircode.app/clair-agent/internal/hookserver"
	"claircode.app/clair-agent/internal/hostname"
	"claircode.app/clair-agent/internal/relay"
	"claircode.app/clair-agent/internal/state"
	"claircode.app/clair-agent/internal/tunnel"
)

// drainTimeout is how long shutdown lets the tunnel release held decides and
// flush its queues before the listener closes (draft).
const drainTimeout = 2 * time.Second

// Installer applies hook configuration on the host. The claudecfg package
// provides it; nil means "log and move on".
type Installer interface {
	// InstallSnippet writes a hooks block the phone sent (RELAY.md §6.5).
	InstallSnippet(snippet json.RawMessage) error
	// Uninstall removes the hooks and the statusline once nothing is paired.
	Uninstall() error
}

// NewRelay builds a relay client for a base URL; the daemon's default is
// relay.New with the options below, tests substitute a fake.
type NewRelay func(baseURL string, auth ed25519.PrivateKey) (tunnel.Relay, error)

// Options configure Run.
type Options struct {
	// Dir is the opened config directory; Agent its agent.json.
	Dir   *state.Dir
	Agent state.Agent
	// Listen overrides Agent.Listen when set.
	Listen  string
	Version string
	Logger  *slog.Logger
	Now     func() time.Time
	Entropy io.Reader
	// RelayCA pins the relay's certificate authority (`--relay-ca`); nil
	// trusts the system store.
	RelayCA *x509.CertPool
	// NewRelay overrides how relay clients are built.
	NewRelay  NewRelay
	Installer Installer
	// Ready, when set, receives the bound address once the listener is up.
	Ready chan<- string
}

// Run serves until ctx ends, then drains the tunnel and closes the listener.
// It returns nil on a clean shutdown.
func Run(ctx context.Context, o Options) error {
	if o.Dir == nil || o.Entropy == nil {
		return errors.New("daemon: a config directory and an entropy source are required")
	}
	d := &daemon{opts: o, log: o.Logger, now: o.Now, clients: make(map[string]tunnel.Relay), loaded: make(map[string]struct{})}
	if d.log == nil {
		d.log = slog.New(slog.DiscardHandler)
	}
	if d.now == nil {
		d.now = time.Now
	}
	if d.opts.NewRelay == nil {
		d.opts.NewRelay = d.defaultRelay
	}
	d.startedAt = d.now()
	d.hostname = hostname.Local()
	listen := o.Listen
	if listen == "" {
		listen = o.Agent.Listen
	}
	if listen == "" {
		listen = hookserver.ListenDefault
	}
	if !hookserver.IsLoopback(listen) {
		d.log.Warn("listening beyond loopback exposes the hook bearer to the network", "listen", listen)
	}

	d.tunnel = tunnel.New(tunnel.Options{
		Counters: o.Dir,
		Hooks:    tunnel.Hooks{OnSnippet: d.onSnippet, OnRevoked: d.onRevoked},
		Logger:   d.log,
		Now:      d.now,
		Entropy:  o.Entropy,
	})
	srv, err := hookserver.New(hookserver.Options{
		Token:      o.Agent.Token,
		AdminToken: o.Agent.AdminToken,
		Sink:       d.tunnel,
		Control:    d,
		Logger:     d.log,
		Now:        d.now,
		Entropy:    o.Entropy,
	})
	if err != nil {
		return fmt.Errorf("daemon: %w", err)
	}
	ln, err := hookserver.Listen(ctx, listen)
	if err != nil {
		return fmt.Errorf("daemon: %w", err)
	}
	d.listen = ln.Addr().String()

	// The tunnel and the listener outlive ctx by design: ctx says "stop",
	// and stopping is drain, then close, then wait.
	tunnelCtx, stopTunnel := context.WithCancel(context.WithoutCancel(ctx))
	defer stopTunnel()
	serveCtx, stopServe := context.WithCancel(context.WithoutCancel(ctx))
	defer stopServe()
	var wg sync.WaitGroup
	tunnelDone := make(chan error, 1)
	wg.Go(func() { tunnelDone <- d.tunnel.Run(tunnelCtx) })
	if loadErr := d.Reload(ctx); loadErr != nil {
		d.log.Warn("pairs not loaded; hooks are answered locally until `clair pair`", "error", loadErr.Error())
	}
	serveDone := make(chan error, 1)
	wg.Go(func() { serveDone <- srv.Serve(serveCtx, ln) })
	d.log.Info("agent listening", "listen", d.listen, "relay", o.Agent.Relay, "version", o.Version, "pairs", d.pairCount())
	if o.Ready != nil {
		o.Ready <- d.listen
	}

	select {
	case <-ctx.Done():
		d.log.Info("agent stopping")
		drainCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), drainTimeout)
		d.tunnel.Drain(drainCtx)
		cancel()
		stopServe()
		err = <-serveDone
	case err = <-serveDone:
		d.log.Error("listener stopped", "error", describe(err))
	}
	stopTunnel()
	<-tunnelDone
	wg.Wait()
	return err
}

// daemon is the running state behind the Controller interface.
type daemon struct {
	opts      Options
	log       *slog.Logger
	now       func() time.Time
	startedAt time.Time
	listen    string
	hostname  string
	tunnel    *tunnel.Tunnel

	mu      sync.Mutex
	clients map[string]tunnel.Relay
	loaded  map[string]struct{}
}

func (d *daemon) defaultRelay(baseURL string, auth ed25519.PrivateKey) (tunnel.Relay, error) {
	return relay.New(auth, relay.Options{
		BaseURL:   baseURL,
		RootCAs:   d.opts.RelayCA,
		UserAgent: "clair-agent/" + d.opts.Version,
		Now:       d.now,
		Logger:    d.log,
	})
}

// relayFor returns the client for a relay URL, building it once per host
// key; a re-pair with new keys rebuilds them.
func (d *daemon) relayFor(baseURL string, auth ed25519.PrivateKey) (tunnel.Relay, error) {
	// An ed25519.PrivateKey is seed ‖ public key; the public half keys the cache.
	key := baseURL + "|" + string(auth[ed25519.SeedSize:])
	d.mu.Lock()
	defer d.mu.Unlock()
	if c, ok := d.clients[key]; ok {
		return c, nil
	}
	c, err := d.opts.NewRelay(baseURL, auth)
	if err != nil {
		return nil, err
	}
	d.clients[key] = c
	return c, nil
}

func (d *daemon) pairCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.loaded)
}

// Status reports the daemon's state.
func (d *daemon) Status(context.Context) ctl.Status {
	pairs := d.tunnel.Snapshot()
	return ctl.Status{
		Version:   d.opts.Version,
		Listen:    d.listen,
		Relay:     d.opts.Agent.Relay,
		UptimeSec: int64(d.now().Sub(d.startedAt) / time.Second),
		Paired:    len(pairs) > 0,
		Pairs:     pairs,
		Unpaired:  d.tunnel.Unpaired(),
	}
}

// Reload re-reads host.key and the pair files and makes the tunnel match.
func (d *daemon) Reload(context.Context) error {
	keys, err := d.opts.Dir.LoadHostKey()
	if errors.Is(err, state.ErrNotFound) {
		d.setLoaded(nil)
		return nil
	}
	if err != nil {
		return err
	}
	pairs, err := d.opts.Dir.ListPairs()
	if err != nil {
		return err
	}
	configs := make([]tunnel.PairConfig, 0, len(pairs))
	for i := range pairs {
		p := &pairs[i]
		traffic, err := p.Keys()
		if err != nil {
			return err
		}
		client, err := d.relayFor(p.Relay, keys.Auth())
		if err != nil {
			return fmt.Errorf("daemon: relay for pair %s: %w", p.PairID, err)
		}
		configs = append(configs, tunnel.PairConfig{
			ID:              p.PairID,
			Keys:            traffic,
			Relay:           client,
			PhoneName:       p.PhoneName,
			H2PNext:         p.H2PNext,
			P2HLast:         p.P2HLast,
			PendingHelloAck: p.PendingHelloAck,
			Hostname:        d.hostname,
			AgentVersion:    d.opts.Version,
		})
	}
	d.setLoaded(configs)
	return nil
}

func (d *daemon) setLoaded(configs []tunnel.PairConfig) {
	d.mu.Lock()
	d.loaded = make(map[string]struct{}, len(configs))
	for _, c := range configs {
		d.loaded[c.ID] = struct{}{}
	}
	d.mu.Unlock()
	d.tunnel.SetPairs(configs)
}

// ReleasePair stops a pair and deletes its file so the CLI may write a new
// one (the pair-file ownership handoff).
func (d *daemon) ReleasePair(_ context.Context, pairID string) error {
	d.mu.Lock()
	_, ok := d.loaded[pairID]
	if ok {
		delete(d.loaded, pairID)
	}
	remaining := make([]tunnel.PairConfig, 0, len(d.loaded))
	d.mu.Unlock()
	if !ok {
		return ctl.ErrNotFound
	}
	// SetPairs keeps known ids untouched, so a config with just the id is
	// enough to say "keep these".
	snapshot := d.tunnel.Snapshot()
	for i := range snapshot {
		if snapshot[i].PairID != pairID {
			remaining = append(remaining, tunnel.PairConfig{ID: snapshot[i].PairID})
		}
	}
	d.tunnel.SetPairs(remaining)
	if err := d.opts.Dir.DeletePair(pairID); err != nil {
		return err
	}
	d.log.Info("pair released", "pair", pairID)
	return nil
}

// onSnippet installs a hooks block the phone sent.
func (d *daemon) onSnippet(pairID string, snippet json.RawMessage) {
	if d.opts.Installer == nil {
		d.log.Info("snippet ignored: no installer", "pair", pairID, "bytes", len(snippet))
		return
	}
	if err := d.opts.Installer.InstallSnippet(snippet); err != nil {
		d.log.Warn("snippet not installed", "pair", pairID, "error", err.Error())
		return
	}
	d.log.Info("hooks rewritten from the phone's snippet; restart Claude Code", "pair", pairID)
}

// onRevoked forgets a pair the phone or the relay ended; with no pair left
// the hooks and the host key go too, and the daemon keeps serving 204s
// until `clair pair` (RELAY.md §6.6).
func (d *daemon) onRevoked(pairID, reason string) {
	d.mu.Lock()
	delete(d.loaded, pairID)
	remaining := len(d.loaded)
	d.mu.Unlock()
	if err := d.opts.Dir.DeletePair(pairID); err != nil {
		d.log.Warn("revoked pair file not removed", "pair", pairID, "error", err.Error())
	}
	d.log.Warn("pair ended; run `clair pair` to pair again", "pair", pairID, "reason", reason)
	if remaining > 0 {
		return
	}
	if d.opts.Installer != nil {
		if err := d.opts.Installer.Uninstall(); err != nil {
			d.log.Warn("hooks not removed", "error", err.Error())
		}
	}
	if err := d.opts.Dir.DeleteHostKey(); err != nil {
		d.log.Warn("host key not removed", "error", err.Error())
	}
}

func describe(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
