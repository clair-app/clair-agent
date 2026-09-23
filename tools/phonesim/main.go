// Command phonesim stands in for the phone while the Android RelayIngress
// does not exist: it scans a `clair pair` link, completes the pairing at the
// relay with its own keys, streams the host's envelopes, prints what it
// decrypts, and answers decides. Development only; never shipped.
//
//	go run ./tools/phonesim [flags] '<link printed by clair pair>'
//
// It is the phone, so — unlike the agent — printing plaintext is its job.
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"claircode.app/clair-agent/internal/claudecfg"
	"claircode.app/clair-agent/internal/envelope"
	"claircode.app/clair-agent/internal/identity"
	"claircode.app/clair-agent/internal/pairing"
	"claircode.app/clair-agent/internal/presence"
	"claircode.app/clair-agent/internal/record"
	"claircode.app/clair-agent/internal/relay"
)

// The hook outputs the simulator answers with (Claude Code's contract, as
// the phone's HookOutput writes them).
const (
	allowOutput = `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}`
	denyOutput  = `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"The user denied this from phonesim."}}}`
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// options are the flags.
type options struct {
	link          string
	relayURL      string
	name          string
	answer        string
	verbose       bool
	revokeOnExit  bool
	idleThreshold int
}

func parse(args []string, stderr io.Writer) (options, error) {
	fs := flag.NewFlagSet("phonesim", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o options
	fs.StringVar(&o.relayURL, "relay", "", "relay base URL (default: the one in the link)")
	fs.StringVar(&o.name, "name", "phonesim", "the phone's display name in hello")
	fs.StringVar(&o.answer, "answer", "allow", "how to answer decides: allow, deny or none")
	fs.BoolVar(&o.verbose, "v", false, "print decrypted record bodies")
	fs.BoolVar(&o.revokeOnExit, "revoke-on-exit", false, "revoke the pair at the relay when stopping")
	fs.IntVar(&o.idleThreshold, "idle-threshold", -1, "presence threshold in seconds to send in hello (RELAY.md §4.3); 0 switches the terminal release off, -1 leaves the agent's default")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() != 1 {
		return o, errors.New("usage: phonesim [flags] '<link printed by clair pair>'")
	}
	o.link = fs.Arg(0)
	switch o.answer {
	case "allow", "deny", "none":
	default:
		return o, errors.New("-answer must be allow, deny or none")
	}
	return o, nil
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	o, err := parse(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "phonesim:", err)
		return 2
	}
	if err := simulate(ctx, o, stdout); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(stderr, "phonesim:", err)
		return 1
	}
	return 0
}

// snippet is the hooks block a phone would send: the agent's own shape with
// the placeholders of RELAY.md §6.5.
func snippet() (json.RawMessage, error) {
	hooks := claudecfg.RenderHooks(claudecfg.SnippetConfig{
		BaseURL: "http://127.0.0.1:" + claudecfg.PlaceholderPort, Token: claudecfg.PlaceholderToken,
		Host: claudecfg.PlaceholderHost, IncludeSessionStart: true, ClairExe: claudecfg.PlaceholderExe,
	})
	var buf strings.Builder
	if err := writeCompact(&buf, hooks); err != nil {
		return nil, err
	}
	return json.RawMessage(buf.String()), nil
}

func simulate(ctx context.Context, o options, stdout io.Writer) error {
	relayURL, payload, err := pairing.ParseURL(o.link)
	if err != nil {
		return err
	}
	if o.relayURL != "" {
		relayURL = o.relayURL
	}
	keys, err := identity.Generate(rand.Reader)
	if err != nil {
		return err
	}
	traffic, err := envelope.Derive(keys.Agreement(), payload.HostPub[:], payload.K[:])
	if err != nil {
		return err
	}
	client, err := relay.New(keys.Auth(), relay.Options{BaseURL: relayURL, UserAgent: "clair-phonesim"})
	if err != nil {
		return err
	}
	pairingID := payload.PairingIDString()
	counter := envelope.NewCounter(0, func(uint64) error { return nil })
	seal := func(rec record.Record, pair string) (envelope.Envelope, error) {
		n, nerr := counter.Next()
		if nerr != nil {
			return envelope.Envelope{}, nerr
		}
		rec.N = n
		plain, merr := record.Marshal(&rec)
		if merr != nil {
			return envelope.Envelope{}, merr
		}
		id, ierr := envelope.NewID(time.Now(), rand.Reader)
		if ierr != nil {
			return envelope.Envelope{}, ierr
		}
		return envelope.Seal(traffic.Key(envelope.DirP2H), envelope.Header{
			Pair: pair, ID: id, Dir: envelope.DirP2H, Wake: envelope.WakeSoon, TTLSec: 600,
		}, plain, rand.Reader)
	}

	snip, err := snippet()
	if err != nil {
		return err
	}
	helloRec := record.Record{Kind: record.KindControl, Control: record.ControlHello, Name: o.name, Snippet: snip}
	if o.idleThreshold >= 0 {
		helloRec.Presence = &record.Presence{IdleThresholdSec: &o.idleThreshold}
	}
	hello, err := seal(helloRec, pairingID)
	if err != nil {
		return err
	}
	pairID, err := client.CompletePairing(ctx, pairingID, keys.AgreementPublic(), "phonesim", hello)
	if err != nil {
		return fmt.Errorf("complete pairing: %w", err)
	}
	fmt.Fprintf(stdout, "paired: pair %s, fingerprint %s — waiting for the host\n", pairID, traffic.Fingerprint())
	high := envelope.NewHighWater(0)

	err = client.Stream(ctx, pairID, "", func(ctx context.Context, ev relay.Event) error {
		switch ev.Kind {
		case relay.EventPresence:
			fmt.Fprintf(stdout, "presence: %s is %s\n", ev.Presence.Peer, ev.Presence.State)
			return nil
		case relay.EventRevoked:
			fmt.Fprintln(stdout, "the host revoked the pair")
			return nil
		case relay.EventEnvelope:
		default:
			return nil
		}
		env := *ev.Envelope
		defer func() { _ = client.Ack(ctx, pairID, ev.Cursor) }()
		rec, openErr := open(traffic, high, pairID, env)
		if openErr != nil {
			fmt.Fprintf(stdout, "dropped %s: %v\n", ev.Cursor, openErr)
			return nil
		}
		describe(stdout, rec, env, o.verbose)
		if rec.Kind == record.KindRequest && rec.Path == record.PathDecide && o.answer != "none" {
			// The phone's half of RELAY.md §4.3: a bubbled prompt with someone
			// at the terminal is the host's to show; a cancel follows.
			if leftToTerminal(rec, o.threshold()) {
				fmt.Fprintln(stdout, "  → left to the terminal (bubbled, someone is there)")
				return nil
			}
			output := allowOutput
			if o.answer == "deny" {
				output = denyOutput
			}
			resp, sealErr := seal(record.Record{Kind: record.KindResponse, ReqID: rec.ReqID, Status: 200, Body: json.RawMessage(output)}, pairID)
			if sealErr != nil {
				return sealErr
			}
			if _, upErr := client.Upload(ctx, pairID, []envelope.Envelope{resp}); upErr != nil {
				return fmt.Errorf("answer decide: %w", upErr)
			}
			fmt.Fprintf(stdout, "  → answered %s\n", o.answer)
		}
		return nil
	})
	if o.revokeOnExit {
		revokeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		// The sealed record is what ends the pair on the host; the DELETE
		// alone only parks it there (agent ADR 2026-09.9ufb). The relay
		// keeps what the revoker sent for the other side to drain (RELAY.md
		// r9 §6.6), so the DELETE follows once the upload is taken.
		if rec, sealErr := seal(record.Record{Kind: record.KindControl, Control: record.ControlRevoke}, pairID); sealErr == nil {
			_, _ = client.Upload(revokeCtx, pairID, []envelope.Envelope{rec})
		}
		if rerr := client.Revoke(revokeCtx, pairID); rerr == nil {
			fmt.Fprintln(stdout, "revoked the pair")
		}
	}
	if errors.Is(err, relay.ErrRevoked) {
		return nil
	}
	return err
}

// threshold is the presence threshold this phone asked for, or the agent's default.
func (o options) threshold() time.Duration {
	if o.idleThreshold >= 0 {
		return time.Duration(o.idleThreshold) * time.Second
	}
	return presence.DefaultThreshold
}

// leftToTerminal applies the release predicate the agent applies (§4.3), on
// the same inputs: the hook's permission mode and the stamped idle time.
func leftToTerminal(rec *record.Record, threshold time.Duration) bool {
	var body struct {
		PermissionMode string `json:"permission_mode"`
	}
	if json.Unmarshal(rec.Body, &body) != nil || body.PermissionMode != record.ModeBubble {
		return false
	}
	ms, err := strconv.ParseInt(rec.Headers[record.IdleHeader], 10, 64)
	if err != nil {
		return false
	}
	return presence.Sample{Idle: time.Duration(ms) * time.Millisecond, Known: true}.Present(threshold)
}

// open validates, decrypts and replay-checks one host envelope.
func open(traffic *envelope.Keys, high *envelope.HighWater, pairID string, env envelope.Envelope) (*record.Record, error) {
	if err := env.Validate(pairID, envelope.DirH2P); err != nil {
		return nil, err
	}
	plain, err := envelope.Open(traffic.Key(envelope.DirH2P), env)
	if err != nil {
		return nil, err
	}
	rec, err := record.Unmarshal(plain)
	if err != nil {
		return nil, err
	}
	if err := high.Accept(rec.N); err != nil {
		return nil, err
	}
	return rec, nil
}

// describe prints one record: what the agent would never log, printed here
// because this is the phone.
func describe(w io.Writer, rec *record.Record, env envelope.Envelope, verbose bool) {
	switch rec.Kind {
	case record.KindRequest:
		fmt.Fprintf(w, "request n=%d wake=%s %s reqId=%s host=%s idleMs=%s bytes=%d\n", rec.N, env.Wake, rec.Path, rec.ReqID, rec.Headers[record.HostHeader], orDash(rec.Headers[record.IdleHeader]), len(rec.Body))
		if verbose || rec.Path == record.PathPresence {
			fmt.Fprintf(w, "  %s\n", rec.Body)
		}
	case record.KindControl:
		fmt.Fprintf(w, "control n=%d wake=%s %s", rec.N, env.Wake, rec.Control)
		switch rec.Control {
		case record.ControlHelloAck:
			fmt.Fprintf(w, " from %s (agent %s)", rec.Hostname, rec.AgentVersion)
		case record.ControlCancel:
			fmt.Fprintf(w, " reqId=%s reason=%s", rec.ReqID, orDash(rec.Reason))
		default:
		}
		fmt.Fprintln(w)
	default:
		fmt.Fprintf(w, "%s n=%d\n", rec.Kind, rec.N)
	}
}

// orDash shows an absent value as "-".
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
