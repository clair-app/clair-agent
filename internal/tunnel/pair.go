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
	// probeID is the `reset` a parked pair queued once the relay served its
	// stream again; the relay accepting it is what resumes the pair.
	probeID    string
	batchN     int
	unflushed  int
	flushed    time.Time
	pendingAck relay.Cursor
	ackSig     chan struct{}
	kick       chan struct{}

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
	if policy.IdleThresholdSec != nil {
		sec := presence.ClampThresholdSec(*policy.IdleThresholdSec)
		policy.IdleThresholdSec = &sec
	}
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
// goroutines cancelled, and the daemon told once. It reports whether this
// call ended it; a pair already over is left alone.
func (p *pair) revoke(reason string) bool {
	p.mu.Lock()
	if p.revoked {
		p.mu.Unlock()
		return false
	}
	p.revoked = true
	p.queue, p.queueBytes, p.probeID = nil, 0, ""
	p.mu.Unlock()
	p.abortHolds()
	p.t.log.Warn("pair revoked", "pair", p.cfg.ID, "reason", reason)
	p.t.remove(p, reason)
	p.cancel()
	return true
}

// forgetOnRelay deletes a pair the phone ended with its sealed revoke once
// the pair has stopped — its last ack, the record's, sent — so the relay
// keeps nothing for it even if the phone's own DELETE never landed. The
// phone's DELETE usually has, so a 410 is the expected answer; it is best
// effort and bounded (ADR 2026-09.69ym).
func (p *pair) forgetOnRelay() {
	p.wg.Wait()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(p.ctx), relayTidyTimeout)
	defer cancel()
	switch err := p.cfg.Relay.Revoke(ctx, p.cfg.ID); {
	case err == nil:
		p.t.log.Info("pair deleted at the relay too", "pair", p.cfg.ID)
	case gone(err):
		p.t.log.Debug("the relay had the pair revoked already", "pair", p.cfg.ID)
	default:
		p.t.log.Info("pair not deleted at the relay; its idle sweep will", "pair", p.cfg.ID, "error", err.Error())
	}
}

// quarantine parks a pair the relay reports gone: a 410 or `event: revoked`
// (the pair was revoked) or a 404 `pair_not_found` (the relay does not know
// it). None of that is authenticated — whoever answers for the relay can say
// it — so the pair file, the keys and the hooks stay (ADR 2026-09.9ufb): the
// pair's holds are let go, its queue and pending ack dropped, hooks skip it,
// and the receiver asks again, slowly. Only the phone's own sealed revoke
// ends a pair at once; reports that hold without a break for dormantGrace
// end it too, since a real revoke keeps answering 410 for the tombstone's 30
// days. A 404 without the relay's code is an edge's, not a report.
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
		p.pendingAck = ""
	}
	// A parked pair queues nothing but its probe, which the relay just
	// refused if it was in flight: without dropping it here the uploader
	// would post it again at once.
	p.queue, p.queueBytes, p.probeID = nil, 0, ""
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

// probe queues a parked pair's `reset` once the relay serves its stream
// again. A served stream proves nothing on its own: the relay drains a
// revoked pair's retained rows — the phone's sealed revoke among them — to
// the side that did not revoke it before it says `revoked`. An accepted
// upload does prove the pair live, since the relay refuses every upload to a
// revoked pair; and `reset` is what a resumed pair sends first anyway, since
// the phone may still show decides let go of while it was parked. So the
// pair stays parked, and a drained revoke ends it without a reset or a
// resume in between, until the relay accepts this one (ADR 2026-09.32b5).
func (p *pair) probe() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.revoked || p.dormantSince.IsZero() || p.probeID != "" {
		return
	}
	it, err := p.sealLocked(record.Record{Kind: record.KindControl, Control: record.ControlReset}, record.ControlWake, record.TTL(record.ControlWake, 0))
	if err != nil {
		p.t.log.Warn("parked pair not probed", "pair", p.cfg.ID, "error", err.Error())
		return
	}
	p.pushLocked(it)
	p.probeID = it.env.ID
	p.t.log.Info("the relay serves a parked pair again; asking it to take a reset", "pair", p.cfg.ID)
}

// served records that the relay accepted an upload for the pair. A parked
// pair resumes when that upload was its probe — one in flight when it was
// parked proves nothing — and a start persisted from an earlier run is
// forgotten, since the relay has since contradicted it.
func (p *pair) served(probed bool) {
	p.dormantMu.Lock()
	defer p.dormantMu.Unlock()
	p.mu.Lock()
	parked := !p.dormantSince.IsZero()
	persisted := !p.revokedSince.IsZero()
	if p.revoked || (parked && !probed) || (!parked && !persisted) {
		p.mu.Unlock()
		return
	}
	p.dormantSince, p.dormantReason, p.revokedSince = time.Time{}, "", time.Time{}
	p.mu.Unlock()
	if persisted && p.t.opts.Hooks.OnDormant != nil {
		p.t.opts.Hooks.OnDormant(p.cfg.ID, time.Time{})
	}
	if parked {
		p.setLink(&p.streamLink, "connected", nil)
		p.t.log.Info("pair resumed: the relay took its reset", "pair", p.cfg.ID)
	}
}

func (p *pair) dormant() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.dormantSince.IsZero()
}

// gone reports whether the relay says the pair is over: a 410 or `event:
// revoked`, or its own 404 `pair_not_found`. Any other 404 is an edge's or a
// proxy's and is retried like any failure (ADR 2026-09.32b5).
func gone(err error) bool {
	return errors.Is(err, relay.ErrRevoked) || errors.Is(err, relay.ErrPairNotFound)
}

// goneReason words a relay's "no such pair" for logs and `clair status`;
// never the relay's own text.
func goneReason(err error) string {
	if errors.Is(err, relay.ErrPairNotFound) {
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
			case gone(err):
				// The queue is dropped; the uploader idles until a probe.
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
// queue, clears the pending hello-ack once it is through, and resumes a
// parked pair whose probe it took.
func (p *pair) applyReceipt(r relay.Receipt) {
	ids := make([]string, 0, len(r.Accepted)+len(r.Duplicates))
	for _, a := range r.Accepted {
		ids = append(ids, a.ID)
	}
	ids = append(ids, r.Duplicates...)
	if len(ids) == 0 {
		return
	}
	p.mu.Lock()
	p.removeLocked(ids)
	p.batchN = uploadBatchMax
	helloAck := p.helloAckID != "" && slices.Contains(ids, p.helloAckID)
	if helloAck {
		p.helloAckID = ""
	}
	probed := p.probeID != "" && slices.Contains(ids, p.probeID)
	if probed {
		p.probeID = ""
	}
	p.mu.Unlock()
	if helloAck {
		if err := p.t.opts.Counters.ClearPendingHelloAck(p.cfg.ID); err != nil {
			p.t.log.Warn("hello-ack delivery not recorded", "pair", p.cfg.ID, "error", err.Error())
		}
	}
	p.served(probed)
}

// receiver keeps the phone's stream open; the relay client reconnects by
// itself, so a return here is a refusal or a handler error. When the pair
// stops it lets go of the stream at the relay too.
func (p *pair) receiver(ctx context.Context) {
	defer p.flushHigh(true)
	defer p.releaseStream(ctx)
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
		if gone(err) {
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

// releaseStream tells the relay the pair let go of its stream, so the phone
// sees the host idle at once instead of when the closed stream's heartbeat
// ages out; best effort, bounded by relayTidyTimeout (ADR 2026-09.hu4b). A
// pair that ended or is parked has no presence to give back.
func (p *pair) releaseStream(ctx context.Context) {
	p.mu.Lock()
	idle := p.revoked || !p.dormantSince.IsZero()
	p.mu.Unlock()
	if idle {
		return
	}
	releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), relayTidyTimeout)
	defer cancel()
	if err := p.cfg.Relay.ReleaseStream(releaseCtx, p.cfg.ID); err != nil {
		p.t.log.Info("stream not released; the relay ages it out", "pair", p.cfg.ID, "error", err.Error())
	}
}

// handle applies one stream event. The relay opens every stream it serves
// with presence, so a parked pair's presence or envelope probes whether it
// is back; the envelope is applied first, so a drained sealed revoke ends
// the pair before any probe is queued.
func (p *pair) handle(_ context.Context, ev relay.Event) error {
	switch ev.Kind {
	case relay.EventPresence:
		p.setPresence(ev.Presence)
		p.probe()
		return nil
	case relay.EventRevoked:
		// A pair the phone's drained revoke already ended ignores it.
		p.quarantine(goneReason(relay.ErrRevoked))
		return nil
	case relay.EventEnvelope:
		p.applyEnvelope(ev)
		p.probe()
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
			if p.revoke("revoked by the phone") {
				p.t.wg.Go(p.forgetOnRelay)
			}
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

// acker sends the pending cursor when one is applied, retries a failed one
// with backoff, and sends it once more on stop.
func (p *pair) acker(ctx context.Context) {
	ticker := time.NewTicker(ackInterval)
	defer ticker.Stop()
	final := func() {
		flushCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), stopFlushTimeout)
		defer cancel()
		p.flushAck(flushCtx)
	}
	attempt := 0
	for {
		select {
		case <-ctx.Done():
			final()
			return
		case <-p.ackSig:
		case <-ticker.C:
		}
		if !p.flushAck(ctx) {
			attempt = 0
			continue
		}
		// Retried every tick, one failing ack was a request a second for as
		// long as the relay kept failing it — a parked pair's for a week.
		// Cursors applied meanwhile coalesce into the retry.
		wait := backoff(attempt)
		attempt++
		if sleep(ctx, wait) != nil {
			final()
			return
		}
	}
}

// flushAck sends the pending cursor and reports whether it failed in a way
// worth another try, in which case it is pending again. A cursor the relay
// refuses outright (AG-18), or for a pair it reports gone and so holds no
// rows of ours for, is dropped: the next applied event brings a new one.
func (p *pair) flushAck(ctx context.Context) (retry bool) {
	p.mu.Lock()
	c := p.pendingAck
	p.pendingAck = ""
	p.mu.Unlock()
	if c == "" {
		return false
	}
	err := p.cfg.Relay.Ack(ctx, p.cfg.ID, c)
	switch {
	case err == nil:
		return false
	case errors.Is(err, relay.ErrBadRequest):
		p.t.log.Warn("ack dropped: relay refused the cursor", "pair", p.cfg.ID, "cursor", string(c), "error", err.Error())
		return false
	case gone(err):
		p.t.log.Info("ack dropped: the relay reports the pair gone", "pair", p.cfg.ID, "cursor", string(c))
		return false
	}
	p.mu.Lock()
	if p.pendingAck == "" {
		p.pendingAck = c
	}
	p.mu.Unlock()
	if ctx.Err() == nil {
		p.t.log.Warn("ack failed, retrying", "pair", p.cfg.ID, "cursor", string(c), "error", err.Error())
	}
	return true
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
