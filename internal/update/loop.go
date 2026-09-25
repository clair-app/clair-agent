package update

import (
	"context"
	"encoding/binary"
	"io"
	"time"
)

// The background schedule (draft). The first check waits out the start-up
// rush; the rest spread over the day so hosts don't ask at the same moment.
// Due times are wall-clock: the monotonic clock stops while a laptop sleeps,
// so a six-hour timer could take days of use to fire. The loop wakes often
// and compares the wall clock instead.
const (
	firstDelay   = 2 * time.Minute
	firstSpread  = 8 * time.Minute
	checkEvery   = 6 * time.Hour
	checkSpread  = 30 * time.Minute // either side of checkEvery
	retryAfter   = time.Hour
	wakeInterval = 10 * time.Minute
)

// Run checks for, and stages, a new release in the background until ctx
// ends. A failure is logged and retried later; nothing it finds stops the
// daemon.
func (u *Updater) Run(ctx context.Context) {
	u.runLoop(ctx, func(ctx context.Context) error {
		_, err := u.Check(ctx, Request{Stage: true})
		return err
	})
}

// runLoop is Run with the check supplied, so the schedule is tested without
// a release server.
func (u *Updater) runLoop(ctx context.Context, check func(context.Context) error) {
	now := u.now().Round(0)
	next := now.Add(firstDelay + spread(u.opts.Entropy, firstSpread))
	for {
		wait := min(wakeInterval, next.Sub(now))
		timer := time.NewTimer(max(wait, time.Second))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		now = u.now().Round(0)
		if !due(now, next) {
			continue
		}
		if u.opts.Enabled != nil && !u.opts.Enabled() {
			next = now.Add(checkEvery)
			continue
		}
		err := check(ctx)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			u.log.Warn("update check failed; retrying later", "error", err.Error(), "retry_in", retryAfter.String())
			next = now.Add(retryAfter)
		default:
			next = now.Add(checkEvery - checkSpread + spread(u.opts.Entropy, 2*checkSpread))
		}
	}
}

// due reports whether the wall clock has reached next.
func due(now, next time.Time) bool {
	return !now.Round(0).Before(next.Round(0))
}

// spread is a duration in [0, span) from entropy; 0 when entropy fails.
func spread(entropy io.Reader, span time.Duration) time.Duration {
	var b [8]byte
	if span <= 0 || entropy == nil {
		return 0
	}
	if _, err := io.ReadFull(entropy, b[:]); err != nil {
		return 0
	}
	return time.Duration(binary.BigEndian.Uint64(b[:]) % uint64(span)) //nolint:gosec // span is positive and under a day
}
