package pairing

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"claircode.app/clair-agent/internal/envelope"
	"claircode.app/clair-agent/internal/identity"
	"claircode.app/clair-agent/internal/record"
	"claircode.app/clair-agent/internal/relay"
	"claircode.app/clair-agent/internal/state"
)

// goodbyeTimeout bounds each relay call of one released pair's goodbye — the
// sealed revoke's upload, then the DELETE — and pairs say goodbye at once, so
// an unreachable relay delays unpairing by at most twice this (ADR
// 2026-09.69ym, draft).
const goodbyeTimeout = 3 * time.Second

// farewell is one released pair to say goodbye to at the relay.
type farewell struct {
	pairID, relay string
	// revoke is the pair's sealed `revoke`, nil when there is none to send: the
	// relay already reports the pair gone, the file had already gone, or it
	// could not be sealed (note says why).
	revoke *envelope.Envelope
	note   string
}

// farewellFor seals a taken pair's `revoke`, unless the relay already reports
// the pair gone (its persisted start): then only the DELETE goes.
func (o Options) farewellFor(existing, taken *state.Pair) farewell {
	f := farewell{pairID: existing.PairID, relay: existing.Relay}
	if taken == nil || taken.RelayRevokedAt != nil {
		return f
	}
	env, err := o.sealRevoke(taken)
	if err != nil {
		f.note = fmt.Sprintf("clair: the phone of pair %s was not told directly (%v); it learns from the relay.", f.pairID, err)
		return f
	}
	f.revoke = &env
	return f
}

// sealRevoke seals a pair's `revoke` from the file the CLI took (RELAY.md r9
// §6.6): its n is the file's H2PNext, above every n the daemon may have used
// (ADR 2026-09.hzwt), and with the file gone no counter will ever hand it out.
func (o Options) sealRevoke(p *state.Pair) (envelope.Envelope, error) {
	keys, err := p.Keys()
	if err != nil {
		return envelope.Envelope{}, err
	}
	return o.sealControl(keys, p.PairID, record.Record{N: max(p.H2PNext, 1), Kind: record.KindControl, Control: record.ControlRevoke})
}

// sayGoodbye tells the relay, for every released pair at once: the sealed
// `revoke` first, so the phone ends the pair on the host's own word, and
// only once the relay took it the DELETE, which would refuse the upload
// after it (ADR 2026-09.69ym). Best effort: what fails is said on stderr and
// never stops the unpairing, which is local.
func (o Options) sayGoodbye(ctx context.Context, host *identity.Keys, farewells []farewell) {
	var wg sync.WaitGroup
	for i := range farewells {
		wg.Go(func() { o.goodbye(ctx, host, &farewells[i]) })
	}
	wg.Wait()
	for i := range farewells {
		if farewells[i].note != "" {
			fmt.Fprintln(o.Stderr, farewells[i].note)
		}
	}
}

// goodbye is one pair's: its notes land in f.note.
func (o Options) goodbye(ctx context.Context, host *identity.Keys, f *farewell) {
	timeout := o.GoodbyeTimeout
	if timeout <= 0 {
		timeout = goodbyeTimeout
	}
	client, err := o.NewRelay(f.relay, host.Auth())
	if err != nil {
		f.note = fmt.Sprintf("clair: the relay was not told that pair %s ended: %v", f.pairID, err)
		return
	}
	if f.revoke != nil {
		upCtx, cancel := context.WithTimeout(ctx, timeout)
		_, err = client.Upload(upCtx, f.pairID, []envelope.Envelope{*f.revoke})
		cancel()
		switch {
		case gone(err):
			return // the relay has the pair ended already; a DELETE changes nothing
		case err != nil:
			f.note = fmt.Sprintf("clair: the phone of pair %s was not told directly (%v); it learns from the relay.", f.pairID, err)
		}
	}
	delCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := client.Revoke(delCtx, f.pairID); err != nil && !gone(err) {
		f.note = fmt.Sprintf("clair: the relay did not revoke %s: %v", f.pairID, err)
	}
}

// gone reports whether the relay says the pair is over already: a 410, or
// its own 404 `pair_not_found` (ADR 2026-09.32b5).
func gone(err error) bool {
	return errors.Is(err, relay.ErrRevoked) || errors.Is(err, relay.ErrPairNotFound)
}
