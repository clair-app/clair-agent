package update

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// zeros is an entropy source that spreads nothing, so the schedule is exact.
type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func loopUpdater(t *testing.T, now func() time.Time, enabled func() bool) *Updater {
	t.Helper()
	u, err := New(Options{Current: "v0.1.0", Exe: someExe(), Entropy: zeros{}, Now: now, Enabled: enabled})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return u
}

// checkLog records when the loop checked, relative to the bubble's start.
type checkLog struct {
	mu    sync.Mutex
	start time.Time
	at    []time.Duration
	fail  bool
}

func (c *checkLog) check(context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = append(c.at, time.Since(c.start))
	if c.fail {
		return errors.New("release server down")
	}
	return nil
}

func (c *checkLog) times() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.at...)
}

// runFor runs the loop in the bubble for d, then stops it.
func runFor(u *Updater, c *checkLog, d time.Duration) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		u.runLoop(ctx, c.check)
		close(done)
	}()
	time.Sleep(d)
	cancel()
	<-done
}

func TestLoopSchedule(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		fail bool
		want []time.Duration
	}{
		// With no spread: first after 2 min, then every 5 h 30 min.
		{name: "checks after start, then every six hours less the spread", want: []time.Duration{2 * time.Minute, 2*time.Minute + 5*time.Hour + 30*time.Minute}},
		{name: "a failure is retried within the hour", fail: true, want: []time.Duration{2 * time.Minute, 62 * time.Minute, 122 * time.Minute, 182 * time.Minute, 242 * time.Minute, 302 * time.Minute, 362 * time.Minute}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				c := &checkLog{start: time.Now(), fail: tt.fail}
				u := loopUpdater(t, time.Now, nil)
				runFor(u, c, 6*time.Hour+10*time.Minute)
				if got := c.times(); !equalDurations(got, tt.want) {
					t.Fatalf("checks at %v, want %v", got, tt.want)
				}
			})
		})
	}
}

// A laptop that sleeps: the wall clock jumps while the timers do not move.
// The next wake after the jump sees the check due.
func TestLoopFollowsTheWallClock(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var mu sync.Mutex
		slept := time.Duration(0)
		now := func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return time.Now().Add(slept)
		}
		c := &checkLog{start: time.Now()}
		u := loopUpdater(t, now, nil)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			u.runLoop(ctx, c.check)
			close(done)
		}()
		time.Sleep(5 * time.Minute) // the first check ran at 2 min
		mu.Lock()
		slept = 8 * time.Hour // suspended through the next due time
		mu.Unlock()
		time.Sleep(20 * time.Minute)
		cancel()
		<-done
		want := []time.Duration{2 * time.Minute, 12 * time.Minute}
		if got := c.times(); !equalDurations(got, want) {
			t.Fatalf("checks at %v (bubble time), want %v", got, want)
		}
	})
}

func TestLoopDisabled(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var mu sync.Mutex
		on := false
		enabled := func() bool {
			mu.Lock()
			defer mu.Unlock()
			return on
		}
		c := &checkLog{start: time.Now()}
		u := loopUpdater(t, time.Now, enabled)
		runFor(u, c, 3*time.Hour)
		if got := c.times(); len(got) != 0 {
			t.Fatalf("checks while turned off at %v", got)
		}
		if u.Status().Enabled {
			t.Error("Status says enabled while agent.json turns it off")
		}
	})
}

func TestDue(t *testing.T) {
	t.Parallel()

	next := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	if due(next.Add(-time.Second), next) {
		t.Error("due a second early")
	}
	if !due(next, next) || !due(next.Add(time.Hour), next) {
		t.Error("not due at or after the time")
	}
}

func TestSpread(t *testing.T) {
	t.Parallel()

	if got := spread(zeros{}, time.Hour); got != 0 {
		t.Errorf("spread(zeros) = %v", got)
	}
	if got := spread(bytes.NewReader(nil), time.Hour); got != 0 {
		t.Errorf("spread without entropy = %v", got)
	}
	ff := bytes.NewReader(bytes.Repeat([]byte{0xff}, 8))
	if got := spread(ff, time.Hour); got < 0 || got >= time.Hour {
		t.Errorf("spread = %v, want [0, 1h)", got)
	}
}

func equalDurations(a, b []time.Duration) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
