package daemon

import (
	"encoding/json"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
)

// blockingInstaller holds its first install until released and records
// every snippet it was given.
type blockingInstaller struct {
	mu        sync.Mutex
	installed []string
	release   chan struct{}
}

func (b *blockingInstaller) InstallSnippet(s json.RawMessage) error {
	b.mu.Lock()
	first := len(b.installed) == 0
	b.installed = append(b.installed, string(s))
	b.mu.Unlock()
	if first {
		<-b.release
	}
	return nil
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
