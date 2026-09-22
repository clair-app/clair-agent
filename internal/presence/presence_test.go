package presence

import (
	"testing"
	"time"
)

func TestPresent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		s         Sample
		threshold time.Duration
		want      bool
	}{
		{"under the threshold", Sample{Idle: 30 * time.Second, Known: true}, 2 * time.Minute, true},
		{"at the threshold", Sample{Idle: 2 * time.Minute, Known: true}, 2 * time.Minute, false},
		{"over the threshold", Sample{Idle: time.Hour, Known: true}, 2 * time.Minute, false},
		{"no signal", Sample{Idle: 0, Known: false}, 2 * time.Minute, false},
		{"switched off", Sample{Idle: 0, Known: true}, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.s.Present(tt.threshold); got != tt.want {
				t.Errorf("Present(%v) = %v, want %v", tt.threshold, got, tt.want)
			}
		})
	}
}

func TestFunc(t *testing.T) {
	t.Parallel()
	f := Func(func() Sample { return Sample{Idle: time.Second, Known: true, Source: "fake"} })
	if s := f.Sample(); !s.Known || s.Idle != time.Second || s.Source != "fake" {
		t.Errorf("Func.Sample() = %+v", s)
	}
}

// TestLocalDoesNotPanic is all that can be said of the host's sampler on
// every platform: a reading, known or not, with a non-negative idle time.
func TestLocalDoesNotPanic(t *testing.T) {
	t.Parallel()
	s := Local().Sample()
	if s.Known && s.Idle < 0 {
		t.Errorf("Local().Sample() = %+v, want a non-negative idle time", s)
	}
	if s.Known && s.Source == "" {
		t.Errorf("Local().Sample() = %+v, want a source", s)
	}
}
