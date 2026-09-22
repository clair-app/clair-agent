package envelope

import (
	"errors"
	"fmt"
	"sync"
)

// ErrReplay is a record whose `n` is not above the highest one accepted.
var ErrReplay = errors.New("envelope: replayed record")

// Counter allocates the sender's `n` for one (pair, direction). RELAY.md §5.4
// makes the receiver reject `n` at or below the highest it accepted, so `n`
// must keep rising across restarts. The counter reserves blocks of
// CounterBlock values through reserve, which the caller persists *before*
// Next hands out the first value of the block; after a restart the caller
// passes the last persisted limit back in and the counter continues above it.
// A crash wastes at most one block, and gaps are allowed.
type Counter struct {
	mu      sync.Mutex
	next    uint64
	limit   uint64
	reserve func(limit uint64) error
}

// NewCounter continues from reserved, the limit the caller last persisted (0
// for a fresh pair; values start at 1). The reserve callback receives the new
// exclusive limit before a block is used and must not return until that limit
// is durable.
func NewCounter(reserved uint64, reserve func(limit uint64) error) *Counter {
	return &Counter{next: max(reserved, 1), limit: reserved, reserve: reserve}
}

// Next returns the next `n`. When the reserved block is exhausted it reserves
// another first; if that fails no value is handed out and the error is
// returned, so a failed persist never produces a reusable `n`.
func (c *Counter) Next() (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.next >= c.limit {
		limit := c.next + CounterBlock
		if err := c.reserve(limit); err != nil {
			return 0, fmt.Errorf("envelope: reserve counters: %w", err)
		}
		c.limit = limit
	}
	n := c.next
	c.next++
	return n, nil
}

// HighWater is the receiver's highest accepted `n` for one (pair, direction).
type HighWater struct {
	mu   sync.Mutex
	last uint64
}

// NewHighWater starts from last, the highest `n` previously accepted (0 for a
// fresh pair).
func NewHighWater(last uint64) *HighWater {
	return &HighWater{last: last}
}

// Accept records n as seen, or returns ErrReplay when n is not above the
// highest accepted so far. Gaps are fine (§5.4: TTL-expired churn, shed records).
func (h *HighWater) Accept(n uint64) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if n <= h.last {
		return fmt.Errorf("%w: n=%d, highest accepted %d", ErrReplay, n, h.last)
	}
	h.last = n
	return nil
}

// Last is the highest accepted `n`, for the caller to persist.
func (h *HighWater) Last() uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.last
}
