package envelope

import (
	"errors"
	"sync"
	"testing"
)

// recorder is a reserve callback that remembers every limit it was asked to
// persist and can be told to fail.
type recorder struct {
	mu     sync.Mutex
	limits []uint64
	fail   error
}

func (r *recorder) reserve(limit uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil {
		return r.fail
	}
	r.limits = append(r.limits, limit)
	return nil
}

func TestCounterReservesBlocksBeforeUse(t *testing.T) {
	t.Parallel()

	var rec recorder
	c := NewCounter(0, rec.reserve)
	for want := uint64(1); want <= CounterBlock+1; want++ {
		got, err := c.Next()
		if err != nil {
			t.Fatalf("Next #%d: %v", want, err)
		}
		if got != want {
			t.Fatalf("Next #%d = %d", want, got)
		}
	}
	if want := []uint64{1 + CounterBlock, 1 + 2*CounterBlock}; len(rec.limits) != 2 || rec.limits[0] != want[0] || rec.limits[1] != want[1] {
		t.Fatalf("reserved limits = %v, want %v", rec.limits, want)
	}
}

func TestCounterContinuesAbovePersistedLimit(t *testing.T) {
	t.Parallel()

	var rec recorder
	c := NewCounter(1+CounterBlock, rec.reserve)
	got, err := c.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if want := uint64(1 + CounterBlock); got != want {
		t.Fatalf("first Next after restart = %d, want %d", got, want)
	}
	if want := uint64(1 + 2*CounterBlock); len(rec.limits) != 1 || rec.limits[0] != want {
		t.Fatalf("reserved limits = %v, want [%d]", rec.limits, want)
	}
}

func TestCounterHandsOutNothingWhenReserveFails(t *testing.T) {
	t.Parallel()

	boom := errors.New("disk full")
	rec := recorder{fail: boom}
	c := NewCounter(0, rec.reserve)
	if _, err := c.Next(); !errors.Is(err, boom) {
		t.Fatalf("Next with a failing reserve: err = %v, want %v", err, boom)
	}
	rec.mu.Lock()
	rec.fail = nil
	rec.mu.Unlock()
	got, err := c.Next()
	if err != nil {
		t.Fatalf("Next after reserve recovered: %v", err)
	}
	if got != 1 {
		t.Fatalf("Next after reserve recovered = %d, want 1: the failed call must not have consumed a value", got)
	}
}

func TestCounterIsSafeForConcurrentUse(t *testing.T) {
	t.Parallel()

	var rec recorder
	c := NewCounter(0, rec.reserve)
	const workers, perWorker = 16, 1000
	seen := make([]uint64, 0, workers*perWorker)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			local := make([]uint64, 0, perWorker)
			for range perWorker {
				n, err := c.Next()
				if err != nil {
					t.Errorf("Next: %v", err)
					return
				}
				local = append(local, n)
			}
			mu.Lock()
			seen = append(seen, local...)
			mu.Unlock()
		})
	}
	wg.Wait()
	unique := make(map[uint64]struct{}, len(seen))
	for _, n := range seen {
		if _, dup := unique[n]; dup {
			t.Fatalf("n=%d was handed out twice", n)
		}
		unique[n] = struct{}{}
	}
	if len(unique) != workers*perWorker {
		t.Fatalf("got %d values, want %d", len(unique), workers*perWorker)
	}
}

func TestHighWater(t *testing.T) {
	t.Parallel()

	h := NewHighWater(5)
	if err := h.Accept(5); !errors.Is(err, ErrReplay) {
		t.Errorf("Accept(5) after 5: err = %v, want ErrReplay", err)
	}
	if err := h.Accept(6); err != nil {
		t.Errorf("Accept(6): %v", err)
	}
	if err := h.Accept(100); err != nil {
		t.Errorf("Accept(100) with a gap: %v", err)
	}
	if err := h.Accept(7); !errors.Is(err, ErrReplay) {
		t.Errorf("Accept(7) after 100: err = %v, want ErrReplay", err)
	}
	if got := h.Last(); got != 100 {
		t.Errorf("Last = %d, want 100", got)
	}
	if err := NewHighWater(0).Accept(0); !errors.Is(err, ErrReplay) {
		t.Errorf("Accept(0) on a fresh high-water mark: err = %v, want ErrReplay", err)
	}
}
