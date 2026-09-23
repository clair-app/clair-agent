package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"sync"
	"time"

	"claircode.app/clair-agent/internal/ctl"
	"claircode.app/clair-agent/internal/envelope"
	"claircode.app/clair-agent/internal/presence"
	"claircode.app/clair-agent/internal/record"
	"claircode.app/clair-agent/internal/relay"
)

// item is one sealed envelope waiting in the FIFO.
type item struct {
	env  envelope.Envelope
	wake envelope.Wake
	size int
	// reqID is the request record's id, so a decide whose envelope the
	// relay refuses can be let go of at once (AG-17); "" for control records.
	reqID string
}

// pair is one running pair: its queue, its held decides, its counters and
// the three goroutines that move envelopes.
type pair struct {
	t      *Tunnel
	cfg    PairConfig
	ctx    context.Context //nolint:containedctx // the pair's lifetime; cancel stops its goroutines
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// dormantMu orders quarantine and resume, persistence included, so the
	// pair file never keeps a start time the pair has since left.
	dormantMu sync.Mutex

	mu         sync.Mutex
	queue      []item
	queueBytes int
	holds      map[string]*hold
	counter    *envelope.Counter
	high       *envelope.HighWater
	revoked    bool
	// dormantSince is when the relay began reporting the pair gone, while
	// the pair is parked; zero otherwise. revokedSince is the same start as
	// persisted, which a parked pair resumes counting from after a restart.
	dormantSince  time.Time
	dormantReason string
	revokedSince  time.Time
	helloAckID    string
	batchN        int
	unflushed     int
	flushed       time.Time
	pendingAck    relay.Cursor
	ackSig        chan struct{}
	kick          chan struct{}

	phone       string
	phoneSeenAt time.Time
	upLink      ctl.Link
	streamLink  ctl.Link
	// idleThreshold is the phone's presence threshold (§4.3), from the pair
	// file and then from policy records.
	idleThreshold time.Duration
}

// enqueue seals a request record for this pair and queues it with the given
// hint and lifetime.
func (p *pair) enqueue(req record.Record, wake envelope.Wake, ttlSec int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.revoked {
		return nil
	}
	if !p.dormantSince.IsZero() {
		return errDormant
	}
	it, err := p.sealLocked(req, wake, ttlSec)
	if err != nil {
		return err
	}
	p.pushLocked(it)
	return nil
}

// enqueuePresence tells the phone the host's terminal input idle changed
// while a decide is held (§4.3): a request the agent itself originates, with
// the idle both as the header every request carries and as the body.
func (p *pair) enqueuePresence(s presence.Sample) {
	id, err := envelope.NewID(p.t.now(), p.t.opts.Entropy)
	if err != nil {
		p.t.log.Warn("presence not queued", "pair", p.cfg.ID, "error", err.Error())
		return
	}
	ms := strconv.FormatInt(s.Idle.Milliseconds(), 10)
	req := record.Record{
		Kind:    record.KindRequest,
		ReqID:   id,
		Path:    record.PathPresence,
		Headers: map[string]string{record.IdleHeader: ms},
		Body:    json.RawMessage(`{"idleMs":` + ms + `}`),
	}
	wake := record.Wake(req.Path, "", true)
	if err := p.enqueue(req, wake, record.TTL(wake, record.TTLSoon)); err != nil {
		p.t.log.Warn("presence not queued", "pair", p.cfg.ID, "error", err.Error())
	}
}

// holding reports whether a decide is waiting on this pair (the wake table's
// "while a decide is held").
func (p *pair) holding() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.holds) > 0
}

// threshold is the presence threshold in force for this pair.
func (p *pair) threshold() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.idleThreshold
}

// setPolicy applies a policy record from the phone (§4.3).
func (p *pair) setPolicy(policy record.Presence) {
	p.mu.Lock()
	if policy.IdleThresholdSec != nil {
		p.idleThreshold = time.Duration(*policy.IdleThresholdSec) * time.Second
	}
	threshold := p.idleThreshold
	p.mu.Unlock()
	p.t.log.Info("policy received", "pair", p.cfg.ID, "idle_threshold_s", int64(threshold/time.Second))
	if p.t.opts.Hooks.OnPolicy != nil {
		p.t.wg.Go(func() { p.t.opts.Hooks.OnPolicy(p.cfg.ID, policy) })
	}
}

// enqueueControl seals and queues a control record; it returns the envelope
// id, or "" when the pair is revoked.
func (p *pair) enqueueControl(rec record.Record) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.revoked || !p.dormantSince.IsZero() {
		return ""
	}
	it, err := p.sealLocked(rec, record.ControlWake, record.TTL(record.ControlWake, 0))
	if err != nil {
		p.t.log.Warn("control record not queued", "pair", p.cfg.ID, "control", string(rec.Control), "error", err.Error())
		return ""
	}
	p.pushLocked(it)
	return it.env.ID
}

// sealLocked assigns n, marshals and seals a record; the caller holds p.mu.
func (p *pair) sealLocked(rec record.Record, wake envelope.Wake, ttlSec int) (item, error) {
	n, err := p.counter.Next()
	if err != nil {
		return item{}, err
	}
	rec.N = n
	plain, err := record.Marshal(&rec)
	if err != nil {
		return item{}, err
	}
	id, err := envelope.NewID(p.t.now(), p.t.opts.Entropy)
	if err != nil {
		return item{}, err
	}
	env, err := envelope.Seal(p.cfg.Keys.Key(envelope.DirH2P), envelope.Header{
		Pair: p.cfg.ID, ID: id, Dir: envelope.DirH2P, Wake: wake, TTLSec: ttlSec,
	}, plain, p.t.opts.Entropy)
	if err != nil {
		if errors.Is(err, envelope.ErrTooLarge) {
			p.t.log.Warn("record dropped: too large for an envelope", "pair", p.cfg.ID, "req_id", rec.ReqID, "bytes", len(plain), "max", envelope.MaxRecordBytes)
			return item{}, errTooLarge
		}
		return item{}, err
	}
	wire, err := json.Marshal(env)
	if err != nil {
		return item{}, err
	}
	if len(wire) > envelope.MaxEnvelopeJSON {
		p.t.log.Warn("record dropped: envelope over the relay cap", "pair", p.cfg.ID, "req_id", rec.ReqID, "bytes", len(wire))
		return item{}, errTooLarge
	}
	it := item{env: env, wake: wake, size: len(wire)}
	if rec.Kind == record.KindRequest {
		it.reqID = rec.ReqID
	}
	return it, nil
}

// pushLocked appends an item, shedding older churn to make room (RELAY.md
// §4.2): oldest `no` first, then oldest `soon`; `now` is never shed, and
// when nothing sheddable remains an incoming `no` or `soon` is dropped
// instead. The caller holds p.mu.
func (p *pair) pushLocked(it item) {
	maxRecords, maxBytes := p.t.opts.MaxRecords, p.t.opts.MaxBytes
	over := func() bool { return len(p.queue) >= maxRecords || p.queueBytes+it.size > maxBytes }
	for _, shed := range []envelope.Wake{envelope.WakeNo, envelope.WakeSoon} {
		for over() {
			i := slices.IndexFunc(p.queue, func(q item) bool { return q.wake == shed })
			if i < 0 {
				break
			}
			p.t.log.Debug("record shed", "pair", p.cfg.ID, "envelope_id", p.queue[i].env.ID, "wake", string(shed))
			p.queueBytes -= p.queue[i].size
			p.queue = slices.Delete(p.queue, i, i+1)
		}
	}
	if over() && it.wake != envelope.WakeNow {
		p.t.log.Debug("record dropped: queue full", "pair", p.cfg.ID, "envelope_id", it.env.ID, "wake", string(it.wake))
		return
	}
	p.queue = append(p.queue, it)
	p.queueBytes += it.size
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

// peekLocked returns the head of the queue that fits one upload; the caller holds p.mu.
func (p *pair) peekLocked() []envelope.Envelope {
	var out []envelope.Envelope
	size := 0
	for i := range p.queue {
		it := &p.queue[i]
		if len(out) >= p.batchN || (len(out) > 0 && size+it.size > relay.BatchMaxBytes) {
			break
		}
		out = append(out, it.env)
		size += it.size
	}
	return out
}

// removeLocked drops the named envelopes from the queue and returns the
// request ids they carried; the caller holds p.mu.
func (p *pair) removeLocked(ids []string) (reqIDs []string) {
	if len(ids) == 0 {
		return nil
	}
	gone := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		gone[id] = struct{}{}
	}
	kept := p.queue[:0]
	for i := range p.queue {
		it := &p.queue[i]
		if _, ok := gone[it.env.ID]; ok {
			p.queueBytes -= it.size
			if it.reqID != "" {
				reqIDs = append(reqIDs, it.reqID)
			}
			continue
		}
		kept = append(kept, *it)
	}
	clear(p.queue[len(kept):])
	p.queue = kept
	return reqIDs
}

func (p *pair) depth() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.queue)
}

func (p *pair) register(reqID string, h *hold) {
	p.mu.Lock()
	defer p.mu.Unlock()
	h.acquire()
	p.holds[reqID] = h
}

// unregister forgets a hold that has been answered or abandoned by its caller.
func (p *pair) unregister(reqID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.holds, reqID)
}

// dropHolds lets go of the held decides whose requests will never reach the
// phone: the last pair to do so answers "no decision" now, instead of at the
// decide's timeout (AG-17). The phone never saw them, so no cancel follows.
func (p *pair) dropHolds(reqIDs []string) {
	for _, reqID := range reqIDs {
		p.mu.Lock()
		h, ok := p.holds[reqID]
		if ok {
			delete(p.holds, reqID)
		}
		p.mu.Unlock()
		if ok {
			p.t.log.Info("held decide let go: the relay refused its envelope", "pair", p.cfg.ID, "req_id", reqID)
			h.release()
		}
	}
}

// resolve hands a response to its held decide; a late one is dropped.
func (p *pair) resolve(rec *record.Record) {
	p.mu.Lock()
	h, ok := p.holds[rec.ReqID]
	if ok {
		delete(p.holds, rec.ReqID)
	}
	p.mu.Unlock()
	if !ok {
		p.t.log.Info("late response dropped", "pair", p.cfg.ID, "req_id", rec.ReqID)
		return
	}
	h.deliver(answer{resp: *rec, ok: true})
}

// abortHolds lets go of every held decide — the last pair to do so answers
// it "no decision" — and returns their ids.
func (p *pair) abortHolds() []string {
	p.mu.Lock()
	holds := p.holds
	p.holds = make(map[string]*hold)
	p.mu.Unlock()
	ids := make([]string, 0, len(holds))
	for reqID, h := range holds {
		h.release()
		ids = append(ids, reqID)
	}
	return ids
}

// revoke ends the pair: holds are released, the queue dropped, the
// goroutines cancelled, and the daemon told once.
func (p *pair) revoke(reason string) {
	p.mu.Lock()
	if p.revoked {
		p.mu.Unlock()
		return
	}
	p.revoked = true
	p.queue, p.queueBytes = nil, 0
	p.mu.Unlock()
	p.abortHolds()
	p.t.log.Warn("pair revoked", "pair", p.cfg.ID, "reason", reason)
	p.t.remove(p, reason)
	p.cancel()
}

// quarantine parks a pair the relay reports gone: a 410 or `event: revoked`
// (the pair was revoked) or a 404 (the relay does not know it). None of that
// is authenticated — whoever answers for the relay can say it — so the pair
// file, the keys and the hooks stay (ADR 2026-09.9ufb): the pair's holds are
// let go, its queue dropped, hooks skip it, and the receiver asks again,
// slowly. Only the phone's own sealed revoke ends a pair at once; reports
// that hold without a break for dormantGrace end it too, since a real revoke
// keeps answering 410 for the tombstone's 30 days.
func (p *pair) quarantine(reason string) {
	p.dormantMu.Lock()
	defer p.dormantMu.Unlock()
	now := p.t.now()
	p.mu.Lock()
	if p.revoked {
		p.mu.Unlock()
		return
	}
	fresh := p.dormantSince.IsZero()
	persist := fresh && p.revokedSince.IsZero()
	if fresh {
		p.dormantSince = p.revokedSince
		if p.dormantSince.IsZero() {
			p.dormantSince = now
		}
		p.dormantReason = reason
		p.revokedSince = p.dormantSince
		p.queue, p.queueBytes = nil, 0
	}
	since := p.dormantSince
	p.mu.Unlock()
	if now.Sub(since) >= dormantGrace {
		p.revoke(reason + ", without a break since " + since.UTC().Format(time.RFC3339))
		return
	}
	if !fresh {
		return
	}
	p.abortHolds()
	p.t.log.Warn("pair dormant: the relay reports it gone; keys and hooks kept until the phone confirms, `clair unpair`, or the grace ends",
		"pair", p.cfg.ID, "reason", reason, "since", since, "delete_after", since.Add(dormantGrace))
	if persist && p.t.opts.Hooks.OnDormant != nil {
		p.t.opts.Hooks.OnDormant(p.cfg.ID, since)
	}
}

// resume takes a pair out of quarantine once the relay serves it again,
// and forgets a persisted start the relay has since contradicted.
func (p *pair) resume() {
	p.dormantMu.Lock()
	defer p.dormantMu.Unlock()
	p.mu.Lock()
	was := !p.dormantSince.IsZero()
	persisted := !p.revokedSince.IsZero()
	p.dormantSince, p.dormantReason, p.revokedSince = time.Time{}, "", time.Time{}
	p.mu.Unlock()
	if persisted && p.t.opts.Hooks.OnDormant != nil {
		p.t.opts.Hooks.OnDormant(p.cfg.ID, time.Time{})
	}
	if was {
		p.t.log.Info("pair resumed: the relay serves it again", "pair", p.cfg.ID)
		// The phone may still show decides let go of while parked.
		p.enqueueControl(record.Record{Kind: record.KindControl, Control: record.ControlReset})
	}
}

func (p *pair) dormant() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.dormantSince.IsZero()
}

// goneReason words a relay's "no such pair" for logs and `clair status`;
// never the relay's own text.
func goneReason(err error) string {
	if errors.Is(err, relay.ErrNotFound) {
		return "the relay does not know the pair"
	}
	return "the relay reports the pair revoked"
}

// uploader drains the queue: one upload in flight, batches as the relay
// allows, backoff on failure, halving the batch on 413.
func (p *pair) uploader(ctx context.Context) {
	attempt := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.kick:
		}
		for {
			p.mu.Lock()
			batch := p.peekLocked()
			p.mu.Unlock()
			if len(batch) == 0 {
				break
			}
			receipt, err := p.cfg.Relay.Upload(ctx, p.cfg.ID, batch)
			p.applyReceipt(receipt)
			if err == nil {
				attempt = 0
				p.setLink(&p.upLink, "connected", nil)
				continue
			}
			if ctx.Err() != nil {
				return
			}
			switch {
			case errors.Is(err, relay.ErrRevoked), errors.Is(err, relay.ErrNotFound):
				// The queue is dropped; the uploader idles until a resume.
				p.quarantine(goneReason(err))
				if p.isRevoked() {
					return
				}
				continue
			case errors.Is(err, relay.ErrTooLarge):
				// Halving is bounded (log2 of the batch), and a lone envelope
				// is dropped, so this path always progresses.
				var dropped []string
				p.mu.Lock()
				if len(batch) == 1 {
					p.t.log.Warn("envelope dropped: relay says too large", "pair", p.cfg.ID, "envelope_id", batch[0].ID)
					dropped = p.removeLocked([]string{batch[0].ID})
				} else {
					p.batchN = max(1, len(batch)/2)
				}
				p.mu.Unlock()
				p.dropHolds(dropped)
				continue
			case errors.Is(err, relay.ErrBadRequest):
				// Our own envelope is malformed for the relay; retrying would
				// loop forever. Drop the batch and say so loudly.
				ids := make([]string, len(batch))
				for i, e := range batch {
					ids[i] = e.ID
				}
				p.mu.Lock()
				dropped := p.removeLocked(ids)
				p.mu.Unlock()
				p.t.log.Error("batch dropped: relay rejected it", "pair", p.cfg.ID, "count", len(batch), "error", err.Error())
				p.dropHolds(dropped)
				continue
			}
			wait := backoff(attempt)
			if serr, ok := errors.AsType[*relay.StatusError](err); ok && serr.RetryAfter > wait {
				wait = serr.RetryAfter
			}
			attempt++
			p.setLink(&p.upLink, "backoff", err)
			p.t.log.Warn("upload failed, retrying", "pair", p.cfg.ID, "attempt", attempt, "after_ms", wait.Milliseconds(), "error", err.Error())
			if sleep(ctx, wait) != nil {
				return
			}
		}
		p.setLink(&p.upLink, "idle", nil)
	}
}

// applyReceipt removes what the relay accepted (or already had) from the
// queue and clears the pending hello-ack once it is through.
func (p *pair) applyReceipt(r relay.Receipt) {
	ids := make([]string, 0, len(r.Accepted)+len(r.Duplicates))
	for _, a := range r.Accepted {
		ids = append(ids, a.ID)
	}
	ids = append(ids, r.Duplicates...)
	p.mu.Lock()
	p.removeLocked(ids)
	if len(ids) > 0 {
		p.batchN = uploadBatchMax
	}
	helloAck := p.helloAckID != "" && slices.Contains(ids, p.helloAckID)
	if helloAck {
		p.helloAckID = ""
	}
	p.mu.Unlock()
	if helloAck {
		if err := p.t.opts.Counters.ClearPendingHelloAck(p.cfg.ID); err != nil {
			p.t.log.Warn("hello-ack delivery not recorded", "pair", p.cfg.ID, "error", err.Error())
		}
	}
}

// receiver keeps the phone's stream open; the relay client reconnects by
// itself, so a return here is a refusal or a handler error.
func (p *pair) receiver(ctx context.Context) {
	defer p.flushHigh(true)
	attempt, rechecks := 0, 0
	for {
		if !p.dormant() {
			p.setLink(&p.streamLink, "connected", nil)
		}
		began := p.t.now()
		err := p.cfg.Relay.Stream(ctx, p.cfg.ID, "", p.handle)
		if ctx.Err() != nil {
			return
		}
		// A stream that held up for a while earned a fresh start: without
		// this, one failure a day would creep the delay to its cap (AG-18).
		if p.t.now().Sub(began) >= streamHealthy {
			attempt = 0
		}
		if !p.dormant() {
			rechecks = 0
		}
		var wait time.Duration
		if errors.Is(err, relay.ErrRevoked) || errors.Is(err, relay.ErrNotFound) {
			p.quarantine(goneReason(err))
			if p.isRevoked() {
				return
			}
			wait = min(dormantRecheckMin<<min(rechecks, 4), dormantRecheckMax)
			rechecks++
			p.setLink(&p.streamLink, "dormant", err)
			p.t.log.Info("pair dormant, asking the relay again later", "pair", p.cfg.ID, "after_ms", wait.Milliseconds())
		} else {
			wait = backoff(attempt)
			attempt++
			p.setLink(&p.streamLink, "backoff", err)
			p.t.log.Warn("stream stopped, retrying", "pair", p.cfg.ID, "attempt", attempt, "after_ms", wait.Milliseconds(), "error", describe(err))
		}
		if sleep(ctx, wait) != nil {
			return
		}
	}
}

// handle applies one stream event.
func (p *pair) handle(_ context.Context, ev relay.Event) error {
	switch ev.Kind {
	case relay.EventPresence:
		// The relay opens every stream it serves with presence: a parked
		// pair it serves again is back.
		p.resume()
		p.setPresence(ev.Presence)
		return nil
	case relay.EventRevoked:
		p.quarantine(goneReason(relay.ErrRevoked))
		return nil
	case relay.EventEnvelope:
		p.resume()
		p.applyEnvelope(ev)
		return nil
	default:
		return nil
	}
}

func (p *pair) setPresence(pr *relay.Presence) {
	if pr == nil || pr.Peer != "phone" {
		return
	}
	connected := pr.State == "connected"
	p.mu.Lock()
	p.phone = pr.State
	p.phoneSeenAt = pr.At
	p.mu.Unlock()
	p.t.log.Info("phone presence", "pair", p.cfg.ID, "state", pr.State)
	if p.t.opts.Hooks.OnPresence != nil {
		p.t.opts.Hooks.OnPresence(p.cfg.ID, connected, pr.At)
	}
}

// applyEnvelope validates, opens and applies one envelope from the phone,
// then acknowledges its cursor whatever happened to it: a bad row is the
// sender's loss, not a reason to hold the mailbox.
func (p *pair) applyEnvelope(ev relay.Event) {
	defer p.ack(ev.Cursor)
	env := *ev.Envelope
	if err := env.Validate(p.cfg.ID, envelope.DirP2H); err != nil {
		p.t.log.Warn("envelope dropped: invalid", "pair", p.cfg.ID, "cursor", string(ev.Cursor), "error", err.Error())
		return
	}
	plain, err := envelope.Open(p.cfg.Keys.Key(envelope.DirP2H), env)
	if err != nil {
		p.t.log.Warn("envelope dropped: not ours", "pair", p.cfg.ID, "envelope_id", env.ID, "error", err.Error())
		return
	}
	rec, err := record.Unmarshal(plain)
	if err != nil {
		p.t.log.Warn("record dropped: unreadable", "pair", p.cfg.ID, "envelope_id", env.ID, "error", err.Error())
		return
	}
	if err := p.high.Accept(rec.N); err != nil {
		p.t.log.Warn("record dropped: replay", "pair", p.cfg.ID, "envelope_id", env.ID, "n", rec.N)
		return
	}
	p.apply(rec)
	p.flushHigh(false)
}

func (p *pair) apply(rec *record.Record) {
	switch rec.Kind {
	case record.KindResponse:
		p.resolve(rec)
	case record.KindControl:
		switch rec.Control {
		case record.ControlSnippet:
			p.t.log.Info("snippet received", "pair", p.cfg.ID, "bytes", len(rec.Snippet))
			if p.t.opts.Hooks.OnSnippet != nil {
				snippet := slices.Clone(rec.Snippet)
				p.t.wg.Go(func() { p.t.opts.Hooks.OnSnippet(p.cfg.ID, snippet) })
			}
		case record.ControlRevoke:
			p.revoke("revoked by the phone")
		case record.ControlPolicy:
			if rec.Presence != nil {
				p.setPolicy(*rec.Presence)
			}
		default:
			p.t.log.Debug("control ignored", "pair", p.cfg.ID, "control", string(rec.Control))
		}
	default:
		p.t.log.Debug("record ignored", "pair", p.cfg.ID, "kind", string(rec.Kind))
	}
}

// flushHigh persists the received high-water mark lazily, or now when force.
func (p *pair) flushHigh(force bool) {
	p.mu.Lock()
	p.unflushed++
	due := force || p.unflushed >= counterFlushEvery || p.t.now().Sub(p.flushed) >= counterFlushInterval
	if due {
		p.unflushed = 0
		p.flushed = p.t.now()
	}
	p.mu.Unlock()
	if !due {
		return
	}
	if err := p.t.opts.Counters.SaveP2HLast(p.cfg.ID, p.high.Last()); err != nil && !p.isRevoked() {
		p.t.log.Warn("received counter not persisted", "pair", p.cfg.ID, "error", err.Error())
	}
}

func (p *pair) isRevoked() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.revoked
}

// ack records the highest applied cursor for the acker.
func (p *pair) ack(c relay.Cursor) {
	if c == "" {
		return
	}
	p.mu.Lock()
	p.pendingAck = c
	p.mu.Unlock()
	select {
	case p.ackSig <- struct{}{}:
	default:
	}
}

// acker sends the pending cursor at most every ackInterval, and once more
// on stop.
func (p *pair) acker(ctx context.Context) {
	ticker := time.NewTicker(ackInterval)
	defer ticker.Stop()
	flush := func(ctx context.Context) {
		p.mu.Lock()
		c := p.pendingAck
		p.pendingAck = ""
		p.mu.Unlock()
		if c == "" {
			return
		}
		if err := p.cfg.Relay.Ack(ctx, p.cfg.ID, c); err != nil {
			// A cursor the relay refuses outright will be refused every
			// second forever; the next applied event brings a new one (AG-18).
			if errors.Is(err, relay.ErrBadRequest) {
				p.t.log.Warn("ack dropped: relay refused the cursor", "pair", p.cfg.ID, "cursor", string(c), "error", err.Error())
				return
			}
			p.mu.Lock()
			if p.pendingAck == "" {
				p.pendingAck = c
			}
			p.mu.Unlock()
			if ctx.Err() == nil {
				p.t.log.Warn("ack failed", "pair", p.cfg.ID, "cursor", string(c), "error", err.Error())
			}
		}
	}
	for {
		select {
		case <-ctx.Done():
			flushCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), stopFlushTimeout)
			flush(flushCtx)
			cancel()
			return
		case <-p.ackSig:
		case <-ticker.C:
		}
		flush(ctx)
	}
}

func (p *pair) setLink(link *ctl.Link, state string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	link.State = state
	link.LastError = describe(err)
	if err == nil {
		link.LastOKAt = p.t.now()
	}
}

func (p *pair) status() ctl.PairStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	return ctl.PairStatus{
		PairID:           p.cfg.ID,
		PhoneName:        p.cfg.PhoneName,
		Fingerprint:      p.cfg.Keys.Fingerprint(),
		Phone:            p.phone,
		PhoneSeenAt:      p.phoneSeenAt,
		QueueRecords:     len(p.queue),
		QueueBytes:       p.queueBytes,
		Held:             len(p.holds),
		Uploader:         p.upLink,
		Stream:           p.streamLink,
		SkewSec:          int64(p.cfg.Relay.Skew() / time.Second),
		IdleThresholdSec: int64(p.idleThreshold / time.Second),
		Dormant:          p.dormantStatusLocked(),
	}
}

func (p *pair) dormantStatusLocked() *ctl.Dormant {
	if p.dormantSince.IsZero() {
		return nil
	}
	return &ctl.Dormant{Reason: p.dormantReason, Since: p.dormantSince, DeleteAfter: p.dormantSince.Add(dormantGrace)}
}
