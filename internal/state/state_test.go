package state

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"claircode.app/clair-agent/internal/envelope"
)

// counting is deterministic entropy that never repeats within a test.
type counting struct {
	mu sync.Mutex
	n  byte
}

func (c *counting) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range p {
		p[i] = c.n
		c.n++
	}
	return len(p), nil
}

func openDir(t *testing.T) *Dir {
	t.Helper()
	d, err := Open(filepath.Join(t.TempDir(), "clair"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return d
}

func TestDefaultDir(t *testing.T) {
	t.Parallel()

	got, err := DefaultDir(func(string) string { return "/custom/clair" })
	if err != nil || got != "/custom/clair" {
		t.Errorf("DefaultDir with the override = %q, %v; want /custom/clair", got, err)
	}
	got, err = DefaultDir(func(string) string { return "" })
	if err != nil || filepath.Base(got) != dirName {
		t.Errorf("DefaultDir = %q, %v; want a %s directory", got, err, dirName)
	}
}

func TestEnsureAgentCreatesOnceAndKeepsIt(t *testing.T) {
	t.Parallel()

	d := openDir(t)
	defaults := Agent{Listen: "127.0.0.1:7317", Relay: "https://relay.example", LogLevel: "info"}
	a, created, err := d.EnsureAgent(&counting{}, defaults)
	if err != nil || !created {
		t.Fatalf("EnsureAgent = %+v, created=%v, err=%v; want created", a, created, err)
	}
	if len(a.Token) != 43 || len(a.AdminToken) != 43 || a.Token == a.AdminToken || strings.ContainsAny(a.Token, "+/=") {
		t.Errorf("tokens = %q / %q, want two distinct 43-char base64url tokens", a.Token, a.AdminToken)
	}
	if a.V != fileVersion || a.Listen != defaults.Listen || a.Relay != defaults.Relay {
		t.Errorf("agent = %+v, want the defaults with v=%d", a, fileVersion)
	}
	again, created, err := d.EnsureAgent(&counting{}, Agent{Listen: "other"})
	if err != nil || created || again != a {
		t.Fatalf("second EnsureAgent = %+v, created=%v, err=%v; want the first file back", again, created, err)
	}
	assertMode(t, filepath.Join(d.Path(), agentFile), 0o600)
}

func TestEnsureAgentRace(t *testing.T) {
	t.Parallel()

	d := openDir(t)
	const workers = 8
	results := make([]Agent, workers)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Go(func() {
			a, _, err := d.EnsureAgent(&counting{n: byte(i)}, Agent{})
			if err != nil {
				t.Errorf("EnsureAgent: %v", err)
			}
			results[i] = a
		})
	}
	wg.Wait()
	for i := 1; i < workers; i++ {
		if results[i] != results[0] {
			t.Fatalf("worker %d got %+v, worker 0 got %+v: two agent files were minted", i, results[i], results[0])
		}
	}
}

func TestHostKeyLifecycle(t *testing.T) {
	t.Parallel()

	d := openDir(t)
	if _, err := d.LoadHostKey(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("LoadHostKey before any: err = %v, want ErrNotFound", err)
	}
	keys, created, err := d.EnsureHostKey(&counting{})
	if err != nil || !created {
		t.Fatalf("EnsureHostKey = created %v, err %v; want created", created, err)
	}
	assertMode(t, filepath.Join(d.Path(), hostKeyFile), 0o600)
	same, created, err := d.EnsureHostKey(&counting{n: 200})
	if err != nil || created || !bytes.Equal(same.AgreementPublic(), keys.AgreementPublic()) {
		t.Fatalf("second EnsureHostKey created=%v err=%v, keys differ=%v; want the same key back", created, err, !bytes.Equal(same.AgreementPublic(), keys.AgreementPublic()))
	}
	replaced, err := d.ReplaceHostKey(&counting{n: 100})
	if err != nil || bytes.Equal(replaced.AgreementPublic(), keys.AgreementPublic()) {
		t.Fatalf("ReplaceHostKey: err %v, keys unchanged", err)
	}
	if err := d.DeleteHostKey(); err != nil {
		t.Fatalf("DeleteHostKey: %v", err)
	}
	if err := d.DeleteHostKey(); err != nil {
		t.Fatalf("DeleteHostKey when absent: %v", err)
	}
	if _, err := d.LoadHostKey(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("LoadHostKey after delete: err = %v, want ErrNotFound", err)
	}
}

func samplePair(id string) Pair {
	var keys envelope.Keys
	for i := range keys.H2P {
		keys.H2P[i], keys.P2H[i] = byte(i), byte(255-i)
	}
	for i := range keys.FP {
		keys.FP[i] = byte(i * 3)
	}
	p := Pair{PairID: id, Relay: "https://relay.example", PhonePub: "AAAA", PhoneName: "Pixel", CreatedAt: time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC), H2PNext: 4097, P2HLast: 3}
	p.SetKeys(&keys)
	return p
}

func TestPairFiles(t *testing.T) {
	t.Parallel()

	d := openDir(t)
	if pairs, err := d.ListPairs(); err != nil || len(pairs) != 0 {
		t.Fatalf("ListPairs on a fresh dir = %v, %v; want none", pairs, err)
	}
	if _, err := d.LoadPair("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("LoadPair(missing): err = %v, want ErrNotFound", err)
	}
	want := samplePair("AAAAAAAAAAAAAAAAAAAAAA")
	if err := d.SavePair(want); err != nil {
		t.Fatalf("SavePair: %v", err)
	}
	if err := d.SavePair(samplePair("BBBBBBBBBBBBBBBBBBBBBB")); err != nil {
		t.Fatalf("SavePair: %v", err)
	}
	assertMode(t, filepath.Join(d.Path(), pairsDir, want.PairID+".json"), 0o600)
	got, err := d.LoadPair(want.PairID)
	if err != nil {
		t.Fatalf("LoadPair: %v", err)
	}
	want.V = fileVersion
	if got != want {
		t.Fatalf("LoadPair = %+v, want %+v", got, want)
	}
	keys, err := got.Keys()
	if err != nil || keys.H2P[1] != 1 || keys.P2H[1] != 254 || keys.FP[1] != 3 {
		t.Errorf("Keys = %+v, %v; want the sample keys", keys, err)
	}
	pairs, err := d.ListPairs()
	if err != nil || len(pairs) != 2 || pairs[0].PairID != want.PairID {
		t.Fatalf("ListPairs = %d pairs (%v), want 2 sorted", len(pairs), err)
	}
	if err := d.DeletePair(want.PairID); err != nil {
		t.Fatalf("DeletePair: %v", err)
	}
	if err := d.DeletePair(want.PairID); err != nil {
		t.Fatalf("DeletePair when absent: %v", err)
	}
	if pairs, _ := d.ListPairs(); len(pairs) != 1 {
		t.Fatalf("ListPairs after delete = %d, want 1", len(pairs))
	}
	if err := d.SavePair(Pair{}); err == nil {
		t.Error("SavePair without an id: want an error")
	}
}

func TestPairCountersPersist(t *testing.T) {
	t.Parallel()

	d := openDir(t)
	p := samplePair("AAAAAAAAAAAAAAAAAAAAAA")
	p.H2PNext, p.P2HLast, p.PendingHelloAck = 0, 0, true
	if err := d.SavePair(p); err != nil {
		t.Fatalf("SavePair: %v", err)
	}
	counter := envelope.NewCounter(0, func(limit uint64) error { return d.ReserveH2P(p.PairID, limit) })
	n, err := counter.Next()
	if err != nil || n != 1 {
		t.Fatalf("Next = %d, %v; want 1", n, err)
	}
	stored, _ := d.LoadPair(p.PairID)
	if stored.H2PNext != 1+envelope.CounterBlock {
		t.Fatalf("H2PNext after the first block = %d, want %d (persisted before use)", stored.H2PNext, 1+envelope.CounterBlock)
	}
	// A restart continues above the block, never inside it.
	restarted := envelope.NewCounter(stored.H2PNext, func(limit uint64) error { return d.ReserveH2P(p.PairID, limit) })
	if n, err := restarted.Next(); err != nil || n != 1+envelope.CounterBlock {
		t.Fatalf("Next after restart = %d, %v; want %d", n, err, 1+envelope.CounterBlock)
	}
	if err := d.ReserveH2P(p.PairID, 5); err != nil {
		t.Fatalf("ReserveH2P lower: %v", err)
	}
	if err := d.SaveP2HLast(p.PairID, 9); err != nil {
		t.Fatalf("SaveP2HLast: %v", err)
	}
	if err := d.SaveP2HLast(p.PairID, 4); err != nil {
		t.Fatalf("SaveP2HLast lower: %v", err)
	}
	if err := d.ClearPendingHelloAck(p.PairID); err != nil {
		t.Fatalf("ClearPendingHelloAck: %v", err)
	}
	stored, _ = d.LoadPair(p.PairID)
	if stored.H2PNext != 1+2*envelope.CounterBlock || stored.P2HLast != 9 || stored.PendingHelloAck {
		t.Fatalf("pair after updates = %+v; want H2PNext %d, P2HLast 9, no pending hello-ack", stored, 1+2*envelope.CounterBlock)
	}
	if err := d.ReserveH2P("missing", 1); !errors.Is(err, ErrNotFound) {
		t.Errorf("ReserveH2P on a missing pair: err = %v, want ErrNotFound", err)
	}
}

func TestWriteIsAtomicAndLeavesNoTempFiles(t *testing.T) {
	t.Parallel()

	d := openDir(t)
	if err := d.write("x.json", []byte("one\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := d.write("x.json", []byte("two\n")); err != nil {
		t.Fatalf("write again: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(d.Path(), "x.json"))
	if string(got) != "two\n" {
		t.Errorf("file = %q, want the second write", got)
	}
	entries, _ := os.ReadDir(d.Path())
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("temp file %s left behind", e.Name())
		}
	}
}

func TestCorruptFilesAreReported(t *testing.T) {
	t.Parallel()

	d := openDir(t)
	if err := os.WriteFile(filepath.Join(d.Path(), agentFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := d.LoadAgent(); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("LoadAgent on a corrupt file: err = %v, want a decode error", err)
	}
	if err := os.WriteFile(filepath.Join(d.Path(), agentFile), []byte(`{"v":9}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := d.LoadAgent(); err == nil || !strings.Contains(err.Error(), "version") {
		t.Errorf("LoadAgent on a future version: err = %v, want a version error", err)
	}
	if err := os.WriteFile(filepath.Join(d.Path(), hostKeyFile), []byte(`{"v":1,"x25519":"short","ed25519":"short"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := d.LoadHostKey(); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("LoadHostKey on a corrupt file: err = %v, want a parse error", err)
	}
	if err := os.WriteFile(filepath.Join(d.Path(), pairsDir, "X.json"), []byte(`{"v":1,"pairId":"Y"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := d.LoadPair("X"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("LoadPair with a mismatched id: err = %v, want an error", err)
	}
	if _, err := d.ListPairs(); err == nil {
		t.Error("ListPairs with a bad file: want an error")
	}
	bad := samplePair("AAAAAAAAAAAAAAAAAAAAAA")
	bad.KH2P = "nope"
	if _, err := bad.Keys(); err == nil {
		t.Error("Keys with a bad kH2p: want an error")
	}
}
