// Package supervisor starts the daemon again when it dies. On Windows the
// service manager cannot: the scheduled task runs `conhost --headless`, which
// exits 0 whatever its child does, so Task Scheduler sees a crash as a clean
// stop and its RestartOnFailure never fires (ADR 2026-09.pz5g).
//
// `clair daemon -supervise` runs the daemon as its own child. An exit that is
// not clean starts it again after a pause that grows while it keeps dying
// young; a clean exit, which is what a stop through the control surface or a
// handled signal ends in, ends the supervisor too, so a stopped service stays
// stopped. The child is started from the binary's path each time, so a crash
// restart runs a release the self-update staged (ADR 2026-09.qk6v).
package supervisor

import (
	"context"
	"log/slog"
	"time"
)

// The restart schedule (draft), close to the systemd unit's RestartSec=5.
const (
	// MinDelay is the pause before the first restart, and after a child
	// that ran for Healthy.
	MinDelay = 5 * time.Second
	// MaxDelay caps the pause while the child keeps dying young.
	MaxDelay = 5 * time.Minute
	// Healthy is how long a child must run for its exit to count as a new
	// failure rather than another turn of a crash loop.
	Healthy = time.Minute
	// StopWait bounds a clean stop the supervisor asked for before the child
	// is ended.
	StopWait = 10 * time.Second
)

// Child is a started daemon.
type Child interface {
	// Wait blocks until the child exits and returns its exit code; err is
	// for a child that could not be waited on at all.
	Wait() (code int, err error)
	// Kill ends the child at once.
	Kill() error
}

// Options configure Run.
type Options struct {
	// Start starts a daemon.
	Start func() (Child, error)
	// Stop asks the running daemon to stop cleanly (the control surface's
	// stop). The supervisor calls it when it is told to stop itself: at a
	// logoff Windows sends the console event to processes that never loaded
	// user32.dll, and the daemon has (presence reads GetLastInputInfo).
	Stop   func(ctx context.Context) error
	Logger *slog.Logger
	// Now and Sleep are the clock; nil means the real one.
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
}

// Run supervises until the daemon exits cleanly or ctx ends, and returns the
// exit status for the supervisor: 0 for a clean end.
func Run(ctx context.Context, o Options) int {
	log := o.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	sleep := o.Sleep
	if sleep == nil {
		sleep = sleepCtx
	}
	delay := MinDelay
	for {
		started := now()
		code, stopped := runOnce(ctx, o, log)
		if stopped {
			return code
		}
		if now().Sub(started) >= Healthy {
			delay = MinDelay
		}
		log.Warn("daemon exited; starting it again", "exit_code", code, "ran", now().Sub(started).Round(time.Second).String(), "retry_in", delay.String())
		if sleep(ctx, delay) != nil {
			return 0
		}
		delay = min(2*delay, MaxDelay)
	}
}

// runOnce starts one child and waits for it. When the supervisor is done,
// stopped is set and code is its exit status; otherwise code is the child's
// failure.
func runOnce(ctx context.Context, o Options, log *slog.Logger) (code int, stopped bool) {
	child, err := o.Start()
	if err != nil {
		log.Error("daemon did not start", "error", err.Error())
		if ctx.Err() != nil {
			return 0, true
		}
		return -1, false
	}
	type exit struct {
		code int
		err  error
	}
	exited := make(chan exit, 1)
	go func() {
		c, waitErr := child.Wait()
		exited <- exit{c, waitErr}
	}()
	select {
	case e := <-exited:
		if e.err == nil && e.code == 0 {
			log.Info("daemon stopped cleanly; the supervisor stops too")
			return 0, true
		}
		if e.err != nil {
			log.Error("daemon lost", "error", e.err.Error())
		}
		return e.code, false
	case <-ctx.Done():
	}

	log.Info("stopping the daemon")
	stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), StopWait)
	defer cancel()
	if o.Stop != nil {
		if err := o.Stop(stopCtx); err != nil {
			log.Debug("stop through the control surface failed", "error", err.Error())
		}
	}
	select {
	case e := <-exited:
		if e.err == nil && e.code == 0 {
			return 0, true
		}
		return 1, true
	case <-stopCtx.Done():
		log.Warn("daemon did not stop in time; ending it", "waited", StopWait.String())
		_ = child.Kill()
		<-exited
		return 1, true
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
