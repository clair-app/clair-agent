// Package usage reads the account's per-model weekly limits from Claude Code
// itself, for an account whose statusline reports no seven-day window: a Team
// plan has only a model's own week, Fable's (ADR 2026-10.mhj3). The agent
// asks a headless `claude -p` with the SDK's get_usage control request — no
// turn, no tokens, no transcript — so Claude Code keeps the credentials, and
// sends what it read as a request of its own, [record.PathUsage].
package usage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

const (
	// Interval is how often a probe may run at most, counted from the attempt,
	// so a failing one backs off too: a week moves slowly, and each probe is a
	// Claude Code start (about 1.6 s, ADR 2026-10.mhj3).
	Interval = 10 * time.Minute
	// One probe's bound, Claude Code's start included.
	probeTimeout = 30 * time.Second
	// The id of the one control request a probe sends.
	requestID = "clair-usage"
)

// request is the line a probe writes to Claude Code's stdin.
var request = []byte(`{"type":"control_request","request_id":"` + requestID + `","request":{"subtype":"get_usage","skip_behaviors":true}}` + "\n")

// ErrNoAnswer is a probe whose output held no answer to its request.
var ErrNoAnswer = errors.New("usage: no get_usage answer")

// ErrNoPlan is an answer without plan rate limits: an API key, a third-party
// provider, or a token without the profile scope.
var ErrNoPlan = errors.New("usage: no plan rate limits")

// Week is one model's weekly window, as the phone reads it.
type Week struct {
	// Model is the server's display name for the model, e.g. "Fable".
	Model string `json:"model"`
	// UsedPercentage is 0–100.
	UsedPercentage float64 `json:"used_percentage"`
	// ResetsAt is the reset in Unix seconds; zero, and absent on the wire,
	// when the server did not say.
	ResetsAt int64 `json:"resets_at,omitempty"`
}

// Report is the body of the agent's usage request.
type Report struct {
	// SevenDayModels is never nil: an empty list says the account lists no
	// model's own week.
	SevenDayModels []Week `json:"seven_day_models"`
}

// Runner runs Claude Code once with stdin and returns its stdout. An error
// with output still has the output read: the answer may precede a failing
// exit.
type Runner func(ctx context.Context, stdin []byte) ([]byte, error)

// Probe asks Claude Code for the account's usage and returns each model's
// own weekly window.
func Probe(ctx context.Context, run Runner) ([]Week, error) {
	out, runErr := run(ctx, request)
	weeks, err := Parse(out)
	if errors.Is(err, ErrNoAnswer) && runErr != nil {
		return nil, fmt.Errorf("usage: run claude: %w", runErr)
	}
	return weeks, err
}

// answer is the one line of Claude Code's stream-json output a probe reads.
type answer struct {
	Type     string `json:"type"`
	Response struct {
		Subtype   string `json:"subtype"`
		RequestID string `json:"request_id"`
		Error     string `json:"error"`
		Response  struct {
			RateLimits *rateLimits `json:"rate_limits"`
		} `json:"response"`
	} `json:"response"`
}

// rateLimits is the part of get_usage's rate_limits a probe reads.
type rateLimits struct {
	// ModelScoped is Claude Code's own projection of the per-model weekly
	// rows; nil when it did not make one, empty when there are none.
	ModelScoped *[]struct {
		DisplayName string   `json:"display_name"`
		Utilization *float64 `json:"utilization"`
		ResetsAt    *string  `json:"resets_at"`
	} `json:"model_scoped"`
	// Limits are the server's rows, read when there is no projection.
	Limits []struct {
		Kind     string   `json:"kind"`
		Percent  *float64 `json:"percent"`
		ResetsAt *string  `json:"resets_at"`
		Scope    *struct {
			Model *struct {
				DisplayName string `json:"display_name"`
			} `json:"model"`
		} `json:"scope"`
	} `json:"limits"`
}

// Parse reads the answer to a probe's request from Claude Code's stream-json
// output. The request is experimental and its shape may change: a row it
// cannot read is skipped, and an answer it cannot find is ErrNoAnswer.
func Parse(out []byte) ([]Week, error) {
	for line := range bytes.Lines(out) {
		if !bytes.Contains(line, []byte(`"control_response"`)) {
			continue
		}
		var a answer
		if json.Unmarshal(line, &a) != nil || a.Type != "control_response" || a.Response.RequestID != requestID {
			continue
		}
		if a.Response.Subtype != "success" {
			return nil, fmt.Errorf("usage: get_usage refused: %s", a.Response.Error)
		}
		rl := a.Response.Response.RateLimits
		if rl == nil {
			return nil, ErrNoPlan
		}
		return rl.weeks(), nil
	}
	return nil, ErrNoAnswer
}

func (rl *rateLimits) weeks() []Week {
	weeks := []Week{}
	if rl.ModelScoped != nil {
		for _, r := range *rl.ModelScoped {
			weeks = appendWeek(weeks, r.DisplayName, r.Utilization, r.ResetsAt)
		}
		return weeks
	}
	for _, r := range rl.Limits {
		if r.Kind != "weekly_scoped" || r.Scope == nil || r.Scope.Model == nil {
			continue
		}
		weeks = appendWeek(weeks, r.Scope.Model.DisplayName, r.Percent, r.ResetsAt)
	}
	return weeks
}

func appendWeek(weeks []Week, model string, percent *float64, resetsAt *string) []Week {
	if model == "" || percent == nil {
		return weeks
	}
	w := Week{Model: model, UsedPercentage: min(max(*percent, 0), 100)}
	if resetsAt != nil {
		if t, err := time.Parse(time.RFC3339Nano, *resetsAt); err == nil {
			w.ResetsAt = t.Unix()
		}
	}
	return append(weeks, w)
}

// Options configure a Poller.
type Options struct {
	// Probe reads the account's model weeks; the daemon's runs Claude Code.
	Probe func(ctx context.Context) ([]Week, error)
	// Send hands a Report's JSON to the tunnel. It must not block on I/O.
	Send   func(body []byte)
	Now    func() time.Time
	Logger *slog.Logger
	// Interval overrides [Interval]; 0 keeps it.
	Interval time.Duration
}

// Poller probes when told the week is missing, at most once per interval and
// one probe at a time.
type Poller struct {
	o    Options
	kick chan struct{}
}

// New builds a poller; Probe and Send are required.
func New(o Options) *Poller {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Interval <= 0 {
		o.Interval = Interval
	}
	return &Poller{o: o, kick: make(chan struct{}, 1)}
}

// WeekMissing says a statusline came with a five-hour window and no seven-day
// one. It never blocks: a kick already waiting stands for this one.
func (p *Poller) WeekMissing() {
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

// Run probes on each kick that comes an interval or more after the last
// attempt, until ctx ends. The daemon owns it; a probe in flight ends with
// ctx.
func (p *Poller) Run(ctx context.Context) {
	var last time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.kick:
		}
		now := p.o.Now()
		if !last.IsZero() && now.Sub(last) < p.o.Interval {
			continue
		}
		last = now
		p.probe(ctx)
	}
}

func (p *Poller) probe(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	weeks, err := p.o.Probe(ctx)
	if err != nil {
		p.o.Logger.Warn("usage probe failed", "error", err.Error())
		return
	}
	body, err := json.Marshal(Report{SevenDayModels: weeks})
	if err != nil {
		p.o.Logger.Error("usage report not encoded", "error", err.Error())
		return
	}
	p.o.Logger.Debug("usage probe read", "models", len(weeks))
	p.o.Send(body)
}
