// Package tunnel carries the loopback hooks to the phone and the phone's
// answers back (RELAY.md §4.2, §7.4): one bounded FIFO per pair, sealed at
// enqueue time, an uploader that drains it in batches with one upload in
// flight, a receiver that applies the phone's envelopes in cursor order and
// acknowledges them once applied, and the held decides that wait for a
// response record. It is the daemon's Sink.
package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"claircode.app/clair-agent/internal/ctl"
	"claircode.app/clair-agent/internal/envelope"
	"claircode.app/clair-agent/internal/record"
	"claircode.app/clair-agent/internal/relay"
)

// Knobs. Those marked draft are starting points (RELAY.md's status line).
const (
	// The FIFO holds at most queueMaxRecords sealed envelopes or
	// queueMaxBytes of them (RELAY.md §4.2, draft); over that the oldest
	// `no` records are shed, then `soon`, never `now`.
	queueMaxRecords = 2000
	queueMaxBytes   = 16 << 20
	// One upload carries at most the relay's batch limit.
	uploadBatchMax = relay.BatchMaxEnvelopes
	// Retry delays of the uploader and the receiver double from
	// backoffInitial to backoffMax (RELAY.md §13, draft).
	backoffInitial = time.Second
	backoffMax     = 60 * time.Second
	// Acks are coalesced: the highest applied cursor is sent at most every
	// ackInterval (§7.4, draft).
	ackInterval = time.Second
	// The received high-water mark is persisted every counterFlushEvery
	// records or counterFlushInterval, and on stop (revision G1, draft).
	counterFlushEvery    = 64
	counterFlushInterval = 30 * time.Second
	// The final ack and persist on shutdown get stopFlushTimeout; Drain
	// looks at the queues every drainPoll.
	stopFlushTimeout = 2 * time.Second
	drainPoll        = 50 * time.Millisecond
)

// ErrNoPair is returned by Enqueue when nothing is paired; the hook is still
// answered 204.
var ErrNoPair = errors.New("tunnel: no pair")

// errTooLarge marks a record that cannot be sealed under the relay's cap.
var errTooLarge = errors.New("tunnel: record too large for an envelope")

// Relay is the slice of the relay client the tunnel uses; *relay.Client
// satisfies it and tests fake it.
type Relay interface {
	Upload(ctx context.Context, pair string, envs []envelope.Envelope) (relay.Receipt, error)
	Ack(ctx context.Context, pair string, cursor relay.Cursor) error
	Stream(ctx context.Context, pair string, last relay.Cursor, h relay.Handler) error
	Skew() time.Duration
}

// Counters persists the per-pair counters (state.Dir satisfies it).
type Counters interface {
	// ReserveH2P persists the sender counter's new limit before the block
	// below it is used.
	ReserveH2P(pairID string, limit uint64) error
	// SaveP2HLast persists the highest n accepted from the phone.
	SaveP2HLast(pairID string, n uint64) error
	// ClearPendingHelloAck records that the hello-ack reached the relay.
	ClearPendingHelloAck(pairID string) error
}

// PairConfig is one pair to run.
type PairConfig struct {
	ID        string
	Keys      *envelope.Keys
	Relay     Relay
	PhoneName string
	// H2PNext and P2HLast seed the counters from the pair file.
	H2PNext uint64
	P2HLast uint64
	// PendingHelloAck makes the hello-ack the first record sent.
	PendingHelloAck bool
	// Hostname and AgentVersion fill the hello-ack.
	Hostname     string
	AgentVersion string
}

// Hooks are the daemon's callbacks. Each runs on its own goroutine, so a
// callback may call back into the tunnel.
type Hooks struct {
	// OnSnippet delivers a hooks block the phone sent (RELAY.md §6.5).
	OnSnippet func(pairID string, snippet json.RawMessage)
	// OnRevoked fires once when a pair is gone: revoked by the phone, or
	// refused by the relay with 404/410. The tunnel has already stopped it.
	OnRevoked func(pairID, reason string)
	// OnPresence reports the phone's stream state (§7.6).
	OnPresence func(pairID string, connected bool, at time.Time)
}

// Options configure a Tunnel.
type Options struct {
	Counters Counters
	Hooks    Hooks
	Logger   *slog.Logger
	Now      func() time.Time
	// Entropy mints envelope ids and nonces.
	Entropy io.Reader
	// MaxRecords and MaxBytes override the FIFO bounds; 0 keeps the defaults.
	MaxRecords int
	MaxBytes   int
}

// Tunnel runs the pairs. Run owns every goroutine.
type Tunnel struct {
	opts Options
	log  *slog.Logger
	now  func() time.Time

	mu       sync.Mutex
	ctx      context.Context //nolint:containedctx // Run's context, so SetPairs can start goroutines under it
	running  bool
	pairs    map[string]*pair
	pending  []PairConfig
	unpaired string
	wg       sync.WaitGroup
}

// New builds a tunnel; Run starts it.
func New(opts Options) *Tunnel {
	t := &Tunnel{opts: opts, log: opts.Logger, now: opts.Now, pairs: make(map[string]*pair)}
	if t.log == nil {
		t.log = slog.New(slog.DiscardHandler)
	}
	if t.now == nil {
		t.now = time.Now
	}
	if t.opts.MaxRecords <= 0 {
		t.opts.MaxRecords = queueMaxRecords
	}
	if t.opts.MaxBytes <= 0 {
		t.opts.MaxBytes = queueMaxBytes
	}
	return t
}

// Run serves the pairs until ctx ends and every goroutine has stopped.
func (t *Tunnel) Run(ctx context.Context) error {
	if t.opts.Counters == nil || t.opts.Entropy == nil {
		return errors.New("tunnel: counters and entropy are required")
	}
	t.mu.Lock()
	t.ctx = ctx
	t.running = true
	pending := t.pending
	t.pending = nil
	for _, cfg := range pending {
		t.startLocked(ctx, cfg)
	}
	t.mu.Unlock()
	<-ctx.Done()
	t.mu.Lock()
	for _, p := range t.pairs {
		p.cancel()
	}
	t.running = false
	t.mu.Unlock()
	t.wg.Wait()
	return nil
}

// SetPairs makes the running set match pairs: new ids start, missing ids
// stop (their holds are released), known ids are left alone. Before Run it
// records them for Run to start.
func (t *Tunnel) SetPairs(pairs []PairConfig) {
	want := make(map[string]PairConfig, len(pairs))
	for _, cfg := range pairs {
		want[cfg.ID] = cfg
	}
	var stopped []*pair
	t.mu.Lock()
	if !t.running {
		t.pending = pairs
		t.mu.Unlock()
		return
	}
	for id, p := range t.pairs {
		if _, keep := want[id]; !keep {
			p.cancel()
			delete(t.pairs, id)
			stopped = append(stopped, p)
		}
	}
	for id, cfg := range want {
		if _, have := t.pairs[id]; !have {
			t.startLocked(t.ctx, cfg)
		}
	}
	t.mu.Unlock()
	for _, p := range stopped {
		p.abortHolds()
		p.wg.Wait()
	}
}

// Enqueue satisfies hookserver.Sink for fire-and-forget hooks: the record is
// sealed and queued for every pair. With no pair it is dropped.
func (t *Tunnel) Enqueue(req record.Record, hookEvent string) error {
	pairs := t.livePairs()
	if len(pairs) == 0 {
		return ErrNoPair
	}
	for _, p := range pairs {
		if err := p.enqueue(req, hookEvent, 0); err != nil && !errors.Is(err, errTooLarge) {
			t.log.Warn("record not queued", "pair", p.cfg.ID, "req_id", req.ReqID, "error", err.Error())
		}
	}
	return nil
}

// Hold satisfies hookserver.Sink for decides: the record is queued as `now`
// and the call waits for a response record, the timeout, or the client.
func (t *Tunnel) Hold(ctx context.Context, req record.Record, hookEvent string, timeout time.Duration) (record.Record, bool, error) {
	pairs := t.livePairs()
	if len(pairs) == 0 {
		return record.Record{}, false, nil
	}
	h := newHold()
	queued := false
	for _, p := range pairs {
		p.register(req.ReqID, h)
		if err := p.enqueue(req, hookEvent, timeout); err == nil {
			queued = true
		} else if !errors.Is(err, errTooLarge) {
			t.log.Warn("decide not queued", "pair", p.cfg.ID, "req_id", req.ReqID, "error", err.Error())
		}
	}
	unregister := func() {
		for _, p := range pairs {
			p.unregister(req.ReqID)
		}
	}
	if !queued {
		unregister()
		return record.Record{}, false, nil
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case a := <-h.ch:
		unregister()
		return a.resp, a.ok, nil
	case <-timer.C:
		unregister()
		t.log.Info("decide expired", "req_id", req.ReqID, "timeout_s", int64(timeout/time.Second))
		return record.Record{}, false, nil
	case <-ctx.Done():
		unregister()
		// Claude Code gave up on the hook (revision G2): tell the phone so
		// the action closes instead of waiting a day.
		for _, p := range pairs {
			p.enqueueControl(record.Record{Kind: record.KindControl, Control: record.ControlCancel, ReqID: req.ReqID})
		}
		t.log.Info("decide cancelled by the client", "req_id", req.ReqID)
		return record.Record{}, false, ctx.Err()
	}
}

// Drain prepares for shutdown: every held decide is answered "no decision"
// and told to the phone as a cancel, then the uploaders get until ctx ends
// to empty their queues.
func (t *Tunnel) Drain(ctx context.Context) {
	for _, p := range t.livePairs() {
		for _, reqID := range p.abortHolds() {
			p.enqueueControl(record.Record{Kind: record.KindControl, Control: record.ControlCancel, ReqID: reqID})
		}
	}
	ticker := time.NewTicker(drainPoll)
	defer ticker.Stop()
	for {
		empty := true
		for _, p := range t.livePairs() {
			if p.depth() > 0 {
				empty = false
			}
		}
		if empty {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Snapshot reports every pair for `clair status`.
func (t *Tunnel) Snapshot() []ctl.PairStatus {
	pairs := t.livePairs()
	out := make([]ctl.PairStatus, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, p.status())
	}
	return out
}

// Unpaired is why the last pair went away, for `clair status`.
func (t *Tunnel) Unpaired() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.unpaired
}

func (t *Tunnel) livePairs() []*pair {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]*pair, 0, len(t.pairs))
	for _, p := range t.pairs {
		out = append(out, p)
	}
	return out
}

// startLocked starts a pair's goroutines under Run's context (parent). The
// caller holds t.mu.
func (t *Tunnel) startLocked(parent context.Context, cfg PairConfig) {
	ctx, cancel := context.WithCancel(parent)
	p := &pair{
		t:       t,
		cfg:     cfg,
		ctx:     ctx,
		cancel:  cancel,
		holds:   make(map[string]*hold),
		kick:    make(chan struct{}, 1),
		ackSig:  make(chan struct{}, 1),
		high:    envelope.NewHighWater(cfg.P2HLast),
		batchN:  uploadBatchMax,
		flushed: t.now(),
		phone:   "unknown",
	}
	p.counter = envelope.NewCounter(cfg.H2PNext, func(limit uint64) error {
		return t.opts.Counters.ReserveH2P(cfg.ID, limit)
	})
	t.pairs[cfg.ID] = p
	t.unpaired = ""
	// The first records after a start: the hello-ack `clair pair` could not
	// deliver, then reset, so the phone closes every decide it still holds
	// for us (RELAY.md §4.2).
	if cfg.PendingHelloAck {
		p.helloAckID = p.enqueueControl(record.Record{Kind: record.KindControl, Control: record.ControlHelloAck, Hostname: cfg.Hostname, AgentVersion: cfg.AgentVersion})
	}
	p.enqueueControl(record.Record{Kind: record.KindControl, Control: record.ControlReset})
	for _, loop := range []func(context.Context){p.uploader, p.receiver, p.acker} {
		p.wg.Add(1)
		t.wg.Go(func() {
			defer p.wg.Done()
			loop(ctx)
		})
	}
	t.log.Info("pair started", "pair", cfg.ID, "phone", cfg.PhoneName)
}

// remove takes a pair out of the running set after it revoked itself. The
// pair's goroutines are winding down on their own; nobody waits here.
func (t *Tunnel) remove(p *pair, reason string) {
	t.mu.Lock()
	if t.pairs[p.cfg.ID] == p {
		delete(t.pairs, p.cfg.ID)
		if len(t.pairs) == 0 {
			t.unpaired = reason
		}
	}
	t.mu.Unlock()
	if t.opts.Hooks.OnRevoked != nil {
		t.wg.Go(func() { t.opts.Hooks.OnRevoked(p.cfg.ID, reason) })
	}
}

// backoff is the delay before retry attempt n, doubling from backoffInitial
// to backoffMax.
func backoff(attempt int) time.Duration {
	return min(backoffInitial<<min(max(attempt, 0), 6), backoffMax)
}

// sleep waits for d or the context.
func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// answer is what a held decide receives: the phone's response, or "no
// decision" when the hold was aborted.
type answer struct {
	resp record.Record
	ok   bool
}

// hold is one decide waiting on the phone. Its channel has room for one
// answer, so the first resolver wins and later ones do not block. Every pair
// the decide was queued with holds a reference; the hold is abandoned — the
// caller gets "no decision" — only when the last of them lets go.
type hold struct {
	ch      chan answer
	mu      sync.Mutex
	holders int
}

func newHold() *hold { return &hold{ch: make(chan answer, 1)} }

func (h *hold) deliver(a answer) {
	select {
	case h.ch <- a:
	default:
	}
}

func (h *hold) acquire() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.holders++
}

// release drops one pair's reference; the last one abandons the hold.
func (h *hold) release() {
	h.mu.Lock()
	h.holders--
	last := h.holders <= 0
	h.mu.Unlock()
	if last {
		h.deliver(answer{})
	}
}

func describe(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("%v", err)
}
