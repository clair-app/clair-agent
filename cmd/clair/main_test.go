package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		wantStatus int
		wantOut    string // substring of stdout
		wantErr    string // substring of stderr
	}{
		{name: "no args prints usage to stderr", args: nil, wantStatus: 2, wantErr: "usage: clair"},
		{name: "version", args: []string{"version"}, wantStatus: 0, wantOut: "clair "},
		{name: "help", args: []string{"help"}, wantStatus: 0, wantOut: "usage: clair"},
		{name: "-h", args: []string{"-h"}, wantStatus: 0, wantOut: "usage: clair"},
		{name: "unknown command", args: []string{"pair"}, wantStatus: 2, wantErr: `unknown command "pair"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer
			got := run(tt.args, &stdout, &stderr)

			if got != tt.wantStatus {
				t.Errorf("run(%q) = %d, want %d", tt.args, got, tt.wantStatus)
			}
			if !strings.Contains(stdout.String(), tt.wantOut) {
				t.Errorf("stdout = %q, want substring %q", stdout.String(), tt.wantOut)
			}
			if !strings.Contains(stderr.String(), tt.wantErr) {
				t.Errorf("stderr = %q, want substring %q", stderr.String(), tt.wantErr)
			}
		})
	}
}

func TestBuildVersionFallsBackToDefaults(t *testing.T) {
	t.Parallel()

	ver, rev := buildVersion()
	if ver == "" || rev == "" {
		t.Fatalf("buildVersion() = (%q, %q), want both non-empty", ver, rev)
	}
}
