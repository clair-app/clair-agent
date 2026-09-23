// Package tunnel carries the loopback hooks to the phone and the phone's
// answers back (RELAY.md §4.2, §7.4): one bounded FIFO per pair, sealed at
// enqueue time, an uploader that drains it in batches with one upload in
// flight, a receiver that applies the phone's envelopes in cursor order and
// acknowledges them once applied, and the held decides that wait for a
// response record — or, for a background subagent's prompt while someone is
// at a terminal, are handed back to the terminal at once (RELAY.md §4.3). It
// is the daemon's Sink.
package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"strconv"
	"sync"
	"time"

	"claircode.app/clair-agent/internal/ctl"
	"claircode.app/clair-agent/internal/envelope"
	"claircode.app/clair-agent/internal/presence"
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
	// A stream that stayed up for streamHealthy resets the receiver's
	// backoff (draft).
	streamHealthy = time.Minute
	// A pair the relay reports gone is parked and re-checked from
	// dormantRecheckMin, doubling to dormantRecheckMax; after dormantGrace
	// of unbroken reports it ends (ADR 2026-09.9ufb). The relay keeps a
	// revoked pair's tombstone answering 410 for 30 days, well past it.
	dormantRecheckMin = time.Minute
	dormantRecheckMax = 15 * time.Minute
	dormantGrace      = 7 * 24 * time.Hour
	// A call that only tidies the relay — releasing a stream the agent
	// closed, deleting a pair the phone revoked — gets relayTidyTimeout,
	// once: stopping never waits on the relay for longer (ADR 2026-09.hu4b,
	// draft).
	relayTidyTimeout = 2 * time.Second
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
	// While a decide is held, presence is sampled again every presencePoll
	// (RELAY.md §4.3, draft): a change is reported to the phone, and a
	// bubbled decide is released once someone is at a terminal.
	presencePoll = 10 * time.Second
)

// ErrNoPair is returned by Enqueue when nothing is paired; the hook is still
// answered 204.
var ErrNoPair = errors.New("tunnel: no pair")

// errTooLarge marks a record that cannot be sealed under the relay's cap.
var errTooLarge = errors.New("tunnel: record too large for an envelope")

// errDormant marks a record refused because its pair is parked.
var errDormant = errors.New("tunnel: pair dormant")

// Relay is the slice of the relay client the tunnel uses; *relay.Client
// satisfies it and tests fake it.
type Relay interface {
	Upload(ctx context.Context, pair string, envs []envelope.Envelope) (relay.Receipt, error)
	Ack(ctx context.Context, pair string, cursor relay.Cursor) error
	Stream(ctx context.Context, pair string, last relay.Cursor, h relay.Handler) error
	ReleaseStream(ctx context.Context, pair string) error
	Revoke(ctx context.Context, pair string) error
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
	// IdleThreshold is the phone's presence threshold (§4.3): a bubbled
	// decide is released to the terminal while the host's terminal input has
	// been idle for less than it. Zero never releases.
	IdleThreshold time.Duration
	// RelayRevokedAt is when the relay began reporting the pair gone, from
	// the pair file; the grace period counts from it across restarts.
	RelayRevokedAt time.Time
}

// Hooks are the daemon's callbacks. Each runs on its own goroutine, so a
// callback may call back into the tunnel — except OnDormant.
type Hooks struct {
	// OnSnippet delivers a hooks block the phone sent (RELAY.md §6.5).
	OnSnippet func(pairID string, snippet json.RawMessage)
	// OnRevoked fires once when a pair is over: revoked by the phone's own
	// sealed record, or reported gone by the relay for dormantGrace without
	// a break. The tunnel has already stopped it.
	OnRevoked func(pairID, reason string)
	// OnDormant records when the relay began reporting a pair gone, or with
	// the zero time that it accepts the pair again, so the grace period
	// survives a restart. It runs synchronously, in order, on the pair's
	// goroutine, and must not call back into the tunnel.
	OnDormant func(pairID string, since time.Time)
	// OnPresence reports the phone's stream state (§7.6).
	OnPresence func(pairID string, connected bool, at time.Time)
	// OnPolicy delivers a policy record the phone sent (§4.3) after the
	// tunnel applied it, so the daemon can persist it.
	OnPolicy func(pairID string, policy record.Presence)
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
	// Presence samples the host's terminal input idle (§4.3): stamped on
	// every request record, and the release rule for bubbled decides. Nil
	// stamps nothing and never releases.
	Presence presence.Sampler
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

	// The decides waiting on the phone, for the watcher that re-samples
	// presence while there are any (§4.3). pmu is never held with mu.
	pmu         sync.Mutex
	open        map[*hold]struct{}
	lastPresent bool
	lastKnown   bool
}

// New builds a tunnel; Run starts it.
func New(opts Options) *Tunnel {
	t := &Tunnel{opts: opts, log: opts.Logger, now: opts.Now, pairs: make(map[string]*pair), open: make(map[*hold]struct{})}
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
	for i := range pending {
		t.startLocked(ctx, pending[i])
	}
	if t.opts.Presence != nil {
		t.wg.Go(func() { t.watcher(ctx) })
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
// stop (their holds are released, their streams released at the relay),
// known ids are left alone. It returns once the stopped pairs' goroutines
// have, so their files are the caller's. Before Run it records them for Run
// to start.
func (t *Tunnel) SetPairs(pairs []PairConfig) {
	want := make(map[string]*PairConfig, len(pairs))
	for i := range pairs {
		want[pairs[i].ID] = &pairs[i]
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
			t.startLocked(t.ctx, *cfg)
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
func (t *Tunnel) Enqueue(req record.Record, hook record.Hook) error {
	pairs := t.activePairs()
	if len(pairs) == 0 {
		return ErrNoPair
	}
	req = stamp(req, t.sample())
	for _, p := range pairs {
		wake := record.Wake(req.Path, hook.Event, p.holding())
		if err := p.enqueue(req, wake, record.TTL(wake, 0)); err != nil && !errors.Is(err, errTooLarge) && !errors.Is(err, errDormant) {
			t.log.Warn("record not queued", "pair", p.cfg.ID, "req_id", req.ReqID, "error", err.Error())
		}
	}
	return nil
}

// Hold satisfies hookserver.Sink for decides: the record is queued as `now`
// and the call waits for a response record, the timeout, or the client.
// A bubbled decide is the exception (RELAY.md §4.3): Claude Code draws it in
// the terminal only once this returns without a decision, so while someone
// is at a terminal it is not held at all — the phone gets the request and a
// `cancel` — and one held while nobody was is released the moment someone
// comes back.
func (t *Tunnel) Hold(ctx context.Context, req record.Record, hook record.Hook, timeout time.Duration) (record.Record, bool, error) {
	pairs := t.activePairs()
	if len(pairs) == 0 {
		return record.Record{}, false, nil
	}
	sample := t.sample()
	req = stamp(req, sample)
	bubbled := hook.Mode == record.ModeBubble
	threshold := thresholdOf(pairs)
	if bubbled && sample.Present(threshold) {
		for _, p := range pairs {
			if err := p.enqueue(req, envelope.WakeSoon, record.TTL(envelope.WakeSoon, 0)); err != nil && !errors.Is(err, errTooLarge) && !errors.Is(err, errDormant) {
				t.log.Warn("decide not queued", "pair", p.cfg.ID, "req_id", req.ReqID, "error", err.Error())
			}
		}
		cancelAll(pairs, req.ReqID, record.CancelTerminal)
		t.log.Info("decide released to the terminal", "req_id", req.ReqID, "idle_ms", sample.Idle.Milliseconds())
		return record.Record{}, false, nil
	}
	h := newHold(bubbled)
	queued := false
	for _, p := range pairs {
		p.register(req.ReqID, h)
		if err := p.enqueue(req, envelope.WakeNow, record.TTL(envelope.WakeNow, timeout)); err == nil {
			queued = true
		} else if !errors.Is(err, errTooLarge) && !errors.Is(err, errDormant) {
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
	t.watch(h, sample.Present(threshold), sample.Known)
	defer t.unwatch(h)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case a := <-h.ch:
		unregister()
		if a.released {
			cancelAll(pairs, req.ReqID, record.CancelTerminal)
			t.log.Info("held decide released to the terminal", "req_id", req.ReqID)
		}
		return a.resp, a.ok, nil
	case <-timer.C:
		unregister()
		t.log.Info("decide expired", "req_id", req.ReqID, "timeout_s", int64(timeout/time.Second))
		return record.Record{}, false, nil
	case <-ctx.Done():
		unregister()
		// Claude Code gave up on the hook (revision G2): tell the phone so
		// the action closes instead of waiting a day.
		cancelAll(pairs, req.ReqID, record.CancelClient)
		t.log.Info("decide cancelled by the client", "req_id", req.ReqID)
		return record.Record{}, false, ctx.Err()
	}
}

// cancelAll tells every pair a held decide is over, and why.
func cancelAll(pairs []*pair, reqID, reason string) {
	for _, p := range pairs {
		p.enqueueControl(record.Record{Kind: record.KindControl, Control: record.ControlCancel, ReqID: reqID, Reason: reason})
	}
}

// sample reads presence, or nothing when the host has no sampler.
func (t *Tunnel) sample() presence.Sample {
	if t.opts.Presence == nil {
		return presence.Sample{}
	}
	return t.opts.Presence.Sample()
}

// stamp adds the idle header to a request record when there is a reading;
// the caller's map is left alone.
func stamp(req record.Record, s presence.Sample) record.Record {
	if !s.Known {
		return req
	}
	headers := maps.Clone(req.Headers)
	if headers == nil {
		headers = make(map[string]string, 2)
	}
	headers[record.IdleHeader] = strconv.FormatInt(s.Idle.Milliseconds(), 10)
	req.Headers = headers
	return req
}

// thresholdOf is the presence threshold in force: the most eager phone's.
// A phone that switched the rule off contributes nothing.
func thresholdOf(pairs []*pair) time.Duration {
	var out time.Duration
	for _, p := range pairs {
		out = max(out, p.threshold())
	}
	return out
}

// watch adds a hold to the watcher's set; the first one seeds the flip
// detection with the reading taken when its decide arrived.
func (t *Tunnel) watch(h *hold, present, known bool) {
	t.pmu.Lock()
	defer t.pmu.Unlock()
	if len(t.open) == 0 {
		t.lastPresent, t.lastKnown = present, known
	}
	t.open[h] = struct{}{}
}

func (t *Tunnel) unwatch(h *hold) {
	t.pmu.Lock()
	defer t.pmu.Unlock()
	delete(t.open, h)
}

// watcher re-samples presence while decides are held (§4.3): a change is
// sent to every pair as a presence request, and bubbled holds are released
// once someone is at a terminal. With nothing held it only ticks.
func (t *Tunnel) watcher(ctx context.Context) {
	ticker := time.NewTicker(presencePoll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		t.pmu.Lock()
		idle := len(t.open) == 0
		t.pmu.Unlock()
		if idle {
			continue
		}
		pairs := t.livePairs()
		threshold := thresholdOf(pairs)
		s := t.sample()
		present := s.Present(threshold)
		t.pmu.Lock()
		if len(t.open) == 0 {
			t.pmu.Unlock()
			continue
		}
		flipped := s.Known && t.lastKnown && present != t.lastPresent
		t.lastPresent, t.lastKnown = present, s.Known
		var release []*hold
		if present {
			for h := range t.open {
				if h.bubbled {
					release = append(release, h)
					delete(t.open, h)
				}
			}
		}
		t.pmu.Unlock()
		// The presence record goes first, so the phone reads the change
		// before the cancels the released holds send.
		if flipped {
			t.log.Info("presence changed while a decide is held", "present", present, "idle_ms", s.Idle.Milliseconds())
			for _, p := range pairs {
				p.enqueuePresence(s)
			}
		}
		for _, h := range release {
			h.deliver(answer{released: true})
		}
	}
}

// Drain prepares for shutdown: every held decide is answered "no decision"
// and told to the phone as a cancel, then the uploaders get until ctx ends
// to empty their queues.
func (t *Tunnel) Drain(ctx context.Context) {
	for _, p := range t.livePairs() {
		for _, reqID := range p.abortHolds() {
			p.enqueueControl(record.Record{Kind: record.KindControl, Control: record.ControlCancel, ReqID: reqID, Reason: record.CancelStop})
		}
	}
	ticker := time.NewTicker(drainPoll)
	defer ticker.Stop()
	for {
		// A parked pair's queue holds at most its probe, not worth the wait.
		empty := true
		for _, p := range t.activePairs() {
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

// activePairs is the pairs hooks go to: the running ones not parked.
func (t *Tunnel) activePairs() []*pair {
	pairs := t.livePairs()
	out := pairs[:0]
	for _, p := range pairs {
		if !p.dormant() {
			out = append(out, p)
		}
	}
	return out
}

// startLocked starts a pair's goroutines under Run's context (parent). The
// caller holds t.mu.
func (t *Tunnel) startLocked(parent context.Context, cfg PairConfig) {
	ctx, cancel := context.WithCancel(parent)
	p := &pair{
		t:             t,
		cfg:           cfg,
		ctx:           ctx,
		cancel:        cancel,
		holds:         make(map[string]*hold),
		kick:          make(chan struct{}, 1),
		ackSig:        make(chan struct{}, 1),
		high:          envelope.NewHighWater(cfg.P2HLast),
		batchN:        uploadBatchMax,
		flushed:       t.now(),
		phone:         "unknown",
		idleThreshold: cfg.IdleThreshold,
		revokedSince:  cfg.RelayRevokedAt,
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

// answer is what a held decide receives: the phone's response, "no
// decision" when the hold was aborted, or released when the watcher handed
// a bubbled decide to the terminal.
type answer struct {
	resp     record.Record
	ok       bool
	released bool
}

// hold is one decide waiting on the phone. Its channel has room for one
// answer, so the first resolver wins and later ones do not block. Every pair
// the decide was queued with holds a reference; the hold is abandoned — the
// caller gets "no decision" — only when the last of them lets go. A bubbled
// hold is one the watcher may release (§4.3).
type hold struct {
	ch      chan answer
	bubbled bool
	mu      sync.Mutex
	holders int
}

func newHold(bubbled bool) *hold { return &hold{ch: make(chan answer, 1), bubbled: bubbled} }

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
