package usage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// The Fable week the user's Team account reported on 2026-10-12, in Unix
// seconds: 2026-10-17T16:00:00.285488Z.
const fableReset = 1792252800

func TestParseTeamAccount(t *testing.T) {
	t.Parallel()

	// Claude Code 2.1.296's answer on a Team plan, whose statusline has no
	// seven_day: the request id changed to the probe's, the init line cut down.
	out, err := os.ReadFile(filepath.Join("testdata", "get_usage_team.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(out)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []Week{{Model: "Fable", UsedPercentage: 4, ResetsAt: fableReset}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Parse = %+v, want %+v", got, want)
	}
}

func TestParse(t *testing.T) {
	t.Parallel()

	answer := func(rateLimits string) string {
		return `{"type":"control_response","response":{"subtype":"success","request_id":"clair-usage","response":{"rate_limits":` + rateLimits + `}}}` + "\n"
	}
	tests := []struct {
		name    string
		out     string
		want    []Week
		wantErr error
	}{
		{
			name: "an empty projection is no model week, whatever the rows say",
			out:  answer(`{"model_scoped":[],"limits":[{"kind":"weekly_scoped","percent":4,"scope":{"model":{"display_name":"Fable"}}}]}`),
			want: []Week{},
		},
		{
			name: "no projection falls back to the server's weekly rows with a model",
			out: answer(`{"limits":[{"kind":"session","percent":19,"scope":null},` +
				`{"kind":"weekly_scoped","percent":4,"resets_at":"2026-10-17T16:00:00.285488+00:00","scope":{"model":{"display_name":"Fable"}}},` +
				`{"kind":"weekly_scoped","percent":7,"scope":{"surface":"cowork"}}]}`),
			want: []Week{{Model: "Fable", UsedPercentage: 4, ResetsAt: fableReset}},
		},
		{
			name: "a row with no figure or name is skipped and an unreadable reset left out",
			out:  answer(`{"model_scoped":[{"display_name":"Fable","utilization":null},{"display_name":"","utilization":3},{"display_name":"Opus","utilization":120.5,"resets_at":"soon"}]}`),
			want: []Week{{Model: "Opus", UsedPercentage: 100}},
		},
		{
			name:    "an answer to another request is not the probe's",
			out:     `{"type":"control_response","response":{"subtype":"success","request_id":"other","response":{"rate_limits":{"model_scoped":[]}}}}` + "\n",
			wantErr: ErrNoAnswer,
		},
		{
			name:    "no plan limits",
			out:     answer(`null`),
			wantErr: ErrNoPlan,
		},
		{
			name:    "nothing but noise",
			out:     "not json\n{\"type\":\"system\"}\n",
			wantErr: ErrNoAnswer,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Parse([]byte(tt.out))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Parse error = %v, want %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Parse = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestParseRefusal(t *testing.T) {
	t.Parallel()

	out := `{"type":"control_response","response":{"subtype":"error","request_id":"clair-usage","error":"get_usage is not supported in this context"}}`
	if _, err := Parse([]byte(out)); err == nil || errors.Is(err, ErrNoAnswer) {
		t.Fatalf("Parse error = %v, want the refusal", err)
	}
}

func TestProbe(t *testing.T) {
	t.Parallel()

	answer := []byte(`{"type":"control_response","response":{"subtype":"success","request_id":"clair-usage","response":{"rate_limits":{"model_scoped":[]}}}}`)
	exitErr := errors.New("exit status 1")
	tests := []struct {
		name    string
		out     []byte
		err     error
		wantErr error
	}{
		{name: "an answer before a failing exit is still read", out: answer, err: exitErr},
		{name: "a failing run with no answer is the run's error", err: exitErr, wantErr: exitErr},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdin []byte
			run := func(_ context.Context, in []byte) ([]byte, error) {
				stdin = in
				return tt.out, tt.err
			}
			_, err := Probe(t.Context(), run)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Probe error = %v, want %v", err, tt.wantErr)
			}
			want := `{"type":"control_request","request_id":"clair-usage","request":{"subtype":"get_usage","skip_behaviors":true}}` + "\n"
			if string(stdin) != want {
				t.Fatalf("stdin = %q, want %q", stdin, want)
			}
		})
	}
}

// fakeProbe counts probes and answers as told.
type fakeProbe struct {
	mu    sync.Mutex
	calls int
	weeks []Week
	err   error
}

func (f *fakeProbe) probe(context.Context) ([]Week, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.weeks, f.err
}

func (f *fakeProbe) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func TestPollerProbesAtMostOncePerInterval(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		probe := &fakeProbe{weeks: []Week{{Model: "Fable", UsedPercentage: 4, ResetsAt: fableReset}}}
		var mu sync.Mutex
		var sent [][]byte
		p := New(Options{Probe: probe.probe, Send: func(b []byte) {
			mu.Lock()
			sent = append(sent, b)
			mu.Unlock()
		}})
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			p.Run(ctx)
			close(done)
		}()

		p.WeekMissing()
		synctest.Wait()
		p.WeekMissing()
		synctest.Wait()
		if got := probe.count(); got != 1 {
			t.Fatalf("probes after two kicks = %d, want 1", got)
		}
		time.Sleep(Interval - time.Second)
		p.WeekMissing()
		synctest.Wait()
		if got := probe.count(); got != 1 {
			t.Fatalf("probes just inside the interval = %d, want 1", got)
		}
		time.Sleep(time.Second)
		p.WeekMissing()
		synctest.Wait()
		if got := probe.count(); got != 2 {
			t.Fatalf("probes once the interval passed = %d, want 2", got)
		}

		cancel()
		<-done
		mu.Lock()
		defer mu.Unlock()
		want := []byte(`{"seven_day_models":[{"model":"Fable","used_percentage":4,"resets_at":1792252800}]}`)
		if len(sent) != 2 || !bytes.Equal(sent[0], want) {
			t.Fatalf("sent %q, want twice %s", sent, want)
		}
	})
}

func TestPollerBacksOffAFailedProbeAndSendsNothing(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		probe := &fakeProbe{err: ErrNoClaude}
		sends := 0
		p := New(Options{Probe: probe.probe, Send: func([]byte) { sends++ }})
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			p.Run(ctx)
			close(done)
		}()

		p.WeekMissing()
		synctest.Wait()
		time.Sleep(time.Minute)
		p.WeekMissing()
		synctest.Wait()
		cancel()
		<-done
		if got := probe.count(); got != 1 || sends != 0 {
			t.Fatalf("probes = %d, sends = %d; want 1 probe and nothing sent", got, sends)
		}
	})
}

func TestPollerSendsAnEmptyListForNoModelWeek(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		probe := &fakeProbe{weeks: []Week{}}
		var sent []byte
		p := New(Options{Probe: probe.probe, Send: func(b []byte) { sent = b }})
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			p.Run(ctx)
			close(done)
		}()
		p.WeekMissing()
		synctest.Wait()
		cancel()
		<-done
		if want := `{"seven_day_models":[]}`; string(sent) != want {
			t.Fatalf("sent %s, want %s", sent, want)
		}
	})
}

func TestWeekMissingNeverBlocks(t *testing.T) {
	t.Parallel()

	p := New(Options{Probe: (&fakeProbe{}).probe, Send: func([]byte) {}})
	for range 3 {
		p.WeekMissing()
	}
}
