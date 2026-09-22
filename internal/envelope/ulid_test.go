package envelope

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestNewIDEncodesTimeThenEntropy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ms      int64
		entropy []byte
		want    string
	}{
		{name: "all zero", ms: 0, entropy: make([]byte, 10), want: strings.Repeat("0", IDLength)},
		{name: "spec example timestamp", ms: 1469918176385, entropy: make([]byte, 10), want: "01ARYZ6S41" + strings.Repeat("0", 16)},
		{name: "all-ones entropy", ms: 0, entropy: bytes.Repeat([]byte{0xFF}, 10), want: strings.Repeat("0", 10) + strings.Repeat("Z", 16)},
		{name: "largest timestamp", ms: maxTimestamp, entropy: make([]byte, 10), want: "7ZZZZZZZZZ" + strings.Repeat("0", 16)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := NewID(time.UnixMilli(tt.ms), bytes.NewReader(tt.entropy))
			if err != nil {
				t.Fatalf("NewID: %v", err)
			}
			if got != tt.want {
				t.Fatalf("NewID = %q, want %q", got, tt.want)
			}
			if !ValidID(got) {
				t.Errorf("NewID = %q does not satisfy ValidID", got)
			}
		})
	}
}

func TestNewIDRejects(t *testing.T) {
	t.Parallel()

	if _, err := NewID(time.UnixMilli(maxTimestamp+1), bytes.NewReader(make([]byte, 10))); err == nil {
		t.Error("NewID beyond 48 bits of milliseconds: want an error")
	}
	if _, err := NewID(time.UnixMilli(-1), bytes.NewReader(make([]byte, 10))); err == nil {
		t.Error("NewID before the epoch: want an error")
	}
	if _, err := NewID(time.UnixMilli(1), bytes.NewReader(make([]byte, 9))); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("NewID with short entropy: err = %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestValidID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		id   string
		want bool
	}{
		{id: "01ARYZ6S41TSV4RRFFQ69G5FAV", want: true},
		{id: strings.Repeat("0", 26), want: true},
		{id: strings.Repeat("Z", 26), want: true},
		{id: "01ARYZ6S41TSV4RRFFQ69G5FA", want: false},   // 25
		{id: "01ARYZ6S41TSV4RRFFQ69G5FAVV", want: false}, // 27
		{id: "01ARYZ6S41TSV4RRFFQ69G5FAI", want: false},  // I
		{id: "01ARYZ6S41TSV4RRFFQ69G5FAL", want: false},  // L
		{id: "01ARYZ6S41TSV4RRFFQ69G5FAO", want: false},  // O
		{id: "01ARYZ6S41TSV4RRFFQ69G5FAU", want: false},  // U
		{id: strings.ToLower("01ARYZ6S41TSV4RRFFQ69G5FAV"), want: false},
		{id: "", want: false},
	}
	for _, tt := range tests {
		if got := ValidID(tt.id); got != tt.want {
			t.Errorf("ValidID(%q) = %v, want %v", tt.id, got, tt.want)
		}
	}
}
