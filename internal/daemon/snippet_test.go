package daemon

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"

	"claircode.app/clair-agent/internal/claudecfg"
	"claircode.app/clair-agent/internal/ctl"
)

// blockingInstaller holds its first install until released and records
// every snippet it was given.
type blockingInstaller struct {
	mu        sync.Mutex
	installed []string
	release   chan struct{}
}

func (b *blockingInstaller) InstallSnippet(s json.RawMessage) (claudecfg.SnippetReport, error) {
	b.mu.Lock()
	first := len(b.installed) == 0
	b.installed = append(b.installed, string(s))
	b.mu.Unlock()
	if first {
		<-b.release
	}
	return claudecfg.SnippetReport{}, nil
}

func (*blockingInstaller) RefreshHooks() (claudecfg.RefreshReport, error) {
	return claudecfg.RefreshReport{}, nil
}

func (*blockingInstaller) Uninstall() error { return nil }

// Snippets that arrive while one is being installed collapse into the
// newest: installs never overlap, and the last one written is the last one
// sent (AG-7).
func TestSnippetsInstallOneAtATimeLatestLast(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		inst := &blockingInstaller{release: make(chan struct{})}
		d := &daemon{opts: Options{Installer: inst}, log: slog.New(slog.DiscardHandler)}
		var wg sync.WaitGroup
		wg.Go(func() { d.onSnippet("p", json.RawMessage(`1`)) })
		synctest.Wait()
		for _, s := range []string{`2`, `3`, `4`} {
			wg.Go(func() { d.onSnippet("p", json.RawMessage(s)) })
			synctest.Wait()
		}
		close(inst.release)
		wg.Wait()
		if want := []string{`1`, `4`}; !slices.Equal(inst.installed, want) {
			t.Errorf("installed %v, want %v", inst.installed, want)
		}
	})
}

// reportingInstaller answers every snippet, and every refresh, with the same
// report.
type reportingInstaller struct {
	report  claudecfg.SnippetReport
	refresh claudecfg.RefreshReport
	err     error
}

func (r reportingInstaller) InstallSnippet(json.RawMessage) (claudecfg.SnippetReport, error) {
	return r.report, r.err
}

func (r reportingInstaller) RefreshHooks() (claudecfg.RefreshReport, error) {
	return r.refresh, r.err
}

func (reportingInstaller) Uninstall() error { return nil }

// What the start's refresh found is in the log and in the status: rewritten
// with its backup, already current, no Clair hook at all, or refused.
func TestHookRefreshOutcomes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		inst reportingInstaller
		want ctl.HooksStatus
		log  string
	}{
		{
			name: "rewritten",
			inst: reportingInstaller{refresh: claudecfg.RefreshReport{Report: claudecfg.Report{Backup: "settings.json.bak-1"}, Groups: 9}},
			want: ctl.HooksStatus{Outcome: ctl.HooksRewritten, Groups: 9, Backup: "settings.json.bak-1"},
			log:  "hooks rewritten to this agent's template",
		},
		{
			name: "current",
			inst: reportingInstaller{refresh: claudecfg.RefreshReport{Report: claudecfg.Report{Unchanged: true}, Groups: 9}},
			want: ctl.HooksStatus{Outcome: ctl.HooksCurrent, Groups: 9},
			log:  "hooks match this agent's template",
		},
		{
			name: "none",
			inst: reportingInstaller{refresh: claudecfg.RefreshReport{Report: claudecfg.Report{Unchanged: true}}},
			want: ctl.HooksStatus{Outcome: ctl.HooksNone},
			log:  "no Clair hooks in settings.json",
		},
		{
			name: "refused",
			inst: reportingInstaller{err: claudecfg.ErrSnippetRejected},
			want: ctl.HooksStatus{Outcome: ctl.HooksFailed, Error: claudecfg.ErrSnippetRejected.Error()},
			log:  "hooks not refreshed; they stay as they were",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var log bytes.Buffer
			d := &daemon{opts: Options{Installer: tt.inst}, log: slog.New(slog.NewTextHandler(&log, nil))}
			d.refreshHooks()
			if d.hooks == nil || *d.hooks != tt.want {
				t.Errorf("hooks status = %+v, want %+v", d.hooks, tt.want)
			}
			if !strings.Contains(log.String(), tt.log) {
				t.Errorf("log lacks %q:\n%s", tt.log, log.String())
			}
		})
	}
}

// What an install left out, refused or found already in place is in the
// log, and a refused snippet is not reported as written.
func TestSnippetOutcomesAreLogged(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		inst      reportingInstaller
		want, not []string
	}{
		{name: "written", inst: reportingInstaller{}, want: []string{"hooks rewritten"}},
		{
			name: "events dropped",
			inst: reportingInstaller{report: claudecfg.SnippetReport{Dropped: []string{"SubagentStop"}}},
			want: []string{"snippet trimmed", `left out: \"SubagentStop\"`, "hooks rewritten"},
		},
		{name: "unchanged", inst: reportingInstaller{report: claudecfg.SnippetReport{Report: claudecfg.Report{Unchanged: true}}}, want: []string{"snippet already installed"}, not: []string{"hooks rewritten"}},
		{name: "refused", inst: reportingInstaller{err: claudecfg.ErrSnippetRejected}, want: []string{"snippet not installed; the hooks stay as they were"}, not: []string{"hooks rewritten"}},
		{name: "failed", inst: reportingInstaller{err: errors.New("disk full")}, want: []string{"disk full"}, not: []string{"hooks rewritten"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var log bytes.Buffer
			d := &daemon{opts: Options{Installer: tt.inst}, log: slog.New(slog.NewTextHandler(&log, nil))}
			d.onSnippet("p", json.RawMessage(`{}`))
			for _, want := range tt.want {
				if !strings.Contains(log.String(), want) {
					t.Errorf("log lacks %q:\n%s", want, log.String())
				}
			}
			for _, not := range tt.not {
				if strings.Contains(log.String(), not) {
					t.Errorf("log has %q:\n%s", not, log.String())
				}
			}
		})
	}
}
