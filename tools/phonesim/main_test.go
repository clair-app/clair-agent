package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"claircode.app/clair-agent/internal/envelope"
	"claircode.app/clair-agent/internal/identity"
	"claircode.app/clair-agent/internal/pairing"
	"claircode.app/clair-agent/internal/record"
	"claircode.app/clair-agent/internal/relay"
	"claircode.app/clair-agent/internal/relay/relaytest"
)

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func TestPhonesimPairsAndAnswers(t *testing.T) {
	t.Parallel()

	fake := relaytest.New()
	t.Cleanup(fake.Close)
	host, err := identity.Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostClient, err := relay.New(host.Auth(), relay.Options{BaseURL: fake.URL})
	if err != nil {
		t.Fatal(err)
	}
	pairingRec, err := hostClient.MintPairing(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	payload := pairing.Payload{V: 1}
	idBytes, err := decodeID(pairingRec.ID)
	if err != nil {
		t.Fatal(err)
	}
	payload.PairingID = idBytes
	copy(payload.HostPub[:], host.AgreementPublic())
	if _, readErr := rand.Read(payload.K[:]); readErr != nil {
		t.Fatal(readErr)
	}
	link, err := pairing.PayloadURL(fake.URL, payload)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	out := &lockedBuffer{}
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"-name", "Sim", "-v", link}, out, out) }()

	completed, err := hostClient.WaitPairing(t.Context(), pairingRec.ID)
	if err != nil {
		t.Fatalf("WaitPairing: %v", err)
	}
	keys, err := envelope.Derive(host.Agreement(), completed.PhonePub, payload.K[:])
	if err != nil {
		t.Fatal(err)
	}
	plain, err := envelope.Open(keys.Key(envelope.DirP2H), completed.Envelope)
	if err != nil {
		t.Fatalf("hello does not open: %v", err)
	}
	hello, err := record.Unmarshal(plain)
	if err != nil || hello.Control != record.ControlHello || hello.Name != "Sim" || !bytes.Contains(hello.Snippet, []byte("__TOKEN__")) {
		t.Fatalf("hello = %+v, %v", hello, err)
	}

	// The host sends a decide; the simulator answers it.
	decide := record.Record{N: 1, Kind: record.KindRequest, ReqID: "01ARYZ6S41TSV4RRFFQ69G5FAV", Path: record.PathDecide, Body: json.RawMessage(`{"session_id":"s","hook_event_name":"PermissionRequest"}`)}
	decidePlain, _ := record.Marshal(&decide)
	id, _ := envelope.NewID(time.Now(), rand.Reader)
	env, err := envelope.Seal(keys.Key(envelope.DirH2P), envelope.Header{Pair: completed.PairID, ID: id, Dir: envelope.DirH2P, Wake: envelope.WakeNow, TTLSec: 60}, decidePlain, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hostClient.Upload(t.Context(), completed.PairID, []envelope.Envelope{env}); err != nil {
		t.Fatal(err)
	}
	streamCtx, stopStream := context.WithCancel(t.Context())
	t.Cleanup(stopStream)
	var response *record.Record
	_ = hostClient.Stream(streamCtx, completed.PairID, "", func(_ context.Context, ev relay.Event) error {
		if ev.Kind != relay.EventEnvelope {
			return nil
		}
		plain, err := envelope.Open(keys.Key(envelope.DirP2H), *ev.Envelope)
		if err != nil {
			return err
		}
		rec, err := record.Unmarshal(plain)
		if err != nil {
			return err
		}
		if rec.Kind == record.KindResponse {
			response = rec
			stopStream()
		}
		return nil
	})
	if response == nil || response.ReqID != decide.ReqID || response.Status != 200 || !bytes.Contains(response.Body, []byte(`"behavior":"allow"`)) {
		t.Fatalf("response = %+v", response)
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("phonesim exited %d:\n%s", code, out.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("phonesim did not stop")
	}
	for _, want := range []string{"paired: pair " + completed.PairID, "request n=1 wake=now /clair/v1/hook/decide", `"hook_event_name":"PermissionRequest"`, "→ answered allow"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
}

func TestPhonesimUsage(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	if code := run(t.Context(), nil, &out, &out); code != 2 || !strings.Contains(out.String(), "usage") {
		t.Errorf("run() = %d, %q", code, out.String())
	}
	if code := run(t.Context(), []string{"-answer", "maybe", "x"}, &out, &out); code != 2 {
		t.Errorf("bad -answer = %d", code)
	}
	if code := run(t.Context(), []string{"not-a-link"}, &out, &out); code != 1 {
		t.Errorf("bad link = %d", code)
	}
}
