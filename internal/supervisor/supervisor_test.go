package supervisor

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// fakeChild exits with whatever the test sends it; Kill makes it exit 1.
type fakeChild struct {
	exit   chan int
	mu     sync.Mutex
	killed bool
}

func newFakeChild() *fakeChild { return &fakeChild{exit: make(chan int, 1)} }

func (c *fakeChild) Wait() (int, error) { return <-c.exit, nil }

func (c *fakeChild) Kill() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.killed {
		c.killed = true
		c.exit <- 1
	}
	return nil
}

func (c *fakeChild) wasKilled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.killed
}

// starts records when each child started, relative to the bubble's start.
type starts struct {
	mu       sync.Mutex
	begin    time.Time
	at       []time.Duration
	children chan *fakeChild
}

func newStarts() *starts {
	return &starts{begin: time.Now(), children: make(chan *fakeChild, 16)}
}

func (s *starts) start() (Child, error) {
	c := newFakeChild()
	s.mu.Lock()
	s.at = append(s.at, time.Since(s.begin))
	s.mu.Unlock()
	s.children <- c
	return c, nil
}

func (s *starts) times() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Duration(nil), s.at...)
}

func TestACleanExitEndsTheSupervisor(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		s := newStarts()
		done := make(chan int, 1)
		go func() { done <- Run(context.Background(), Options{Start: s.start}) }()
		(<-s.children).exit <- 0
		if code := <-done; code != 0 {
			t.Fatalf("Run = %d, want 0", code)
		}
		if n := len(s.times()); n != 1 {
			t.Errorf("started %d times, want once", n)
		}
	})
}

// A child that keeps dying at once is started again after 5 s, then 10, 20,
// 40 …; one that ran for a minute resets the pause.
func TestCrashesAreRestartedWithAGrowingPause(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		s := newStarts()
		done := make(chan int, 1)
		go func() { done <- Run(context.Background(), Options{Start: s.start}) }()
		for range 4 { // four quick crashes
			(<-s.children).exit <- 1
		}
		c := <-s.children // runs for two minutes, then crashes
		time.Sleep(2 * time.Minute)
		c.exit <- 2
		(<-s.children).exit <- 0
		<-done
		sec := time.Second
		want := []time.Duration{0, 5 * sec, 15 * sec, 35 * sec, 75 * sec, 75*sec + 2*time.Minute + 5*sec}
		if got := s.times(); !equal(got, want) {
			t.Fatalf("started at %v, want %v", got, want)
		}
	})
}

func TestThePauseIsCapped(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		s := newStarts()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan int, 1)
		go func() { done <- Run(ctx, Options{Start: s.start}) }()
		for range 9 {
			(<-s.children).exit <- 1
		}
		<-s.children
		got := s.times()
		if gap := got[9] - got[8]; gap != MaxDelay {
			t.Errorf("pause after nine crashes = %v, want the cap %v", gap, MaxDelay)
		}
		cancel()
		<-done
	})
}

// Told to stop, the supervisor asks the daemon to stop cleanly and waits.
func TestStopAsksTheDaemon(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		s := newStarts()
		ctx, cancel := context.WithCancel(context.Background())
		var asked bool
		stop := func(ctx context.Context) error {
			asked = true
			(<-s.children).exit <- 0
			return ctx.Err()
		}
		done := make(chan int, 1)
		go func() { done <- Run(ctx, Options{Start: s.start, Stop: stop}) }()
		synctest.Wait()
		cancel()
		if code := <-done; code != 0 || !asked {
			t.Fatalf("Run = %d with stop asked %v, want 0 and asked", code, asked)
		}
	})
}

func TestADaemonThatWillNotStopIsEnded(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		s := newStarts()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan int, 1)
		go func() {
			done <- Run(ctx, Options{Start: s.start, Stop: func(context.Context) error { return errors.New("connection refused") }})
		}()
		c := <-s.children
		synctest.Wait()
		t0 := time.Now()
		cancel()
		if code := <-done; code != 1 || !c.wasKilled() {
			t.Fatalf("Run = %d, killed %v; want 1 and killed", code, c.wasKilled())
		}
		if waited := time.Since(t0); waited != StopWait {
			t.Errorf("killed after %v, want %v", waited, StopWait)
		}
	})
}

func TestAStartThatFailsIsRetried(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var mu sync.Mutex
		tries := 0
		ctx, cancel := context.WithCancel(context.Background())
		start := func() (Child, error) {
			mu.Lock()
			defer mu.Unlock()
			tries++
			return nil, errors.New("file not found")
		}
		done := make(chan int, 1)
		go func() { done <- Run(ctx, Options{Start: start}) }()
		time.Sleep(MinDelay + 2*MinDelay + time.Second)
		cancel()
		if code := <-done; code != 0 {
			t.Errorf("Run = %d, want 0 once told to stop", code)
		}
		mu.Lock()
		defer mu.Unlock()
		if tries != 3 {
			t.Errorf("tried %d times in 16 s, want 3 (at 0, 5 and 15 s)", tries)
		}
	})
}

func equal(a, b []time.Duration) bool {
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
