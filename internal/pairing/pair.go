package pairing

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"claircode.app/clair-agent/internal/claudecfg"
	"claircode.app/clair-agent/internal/ctl"
	"claircode.app/clair-agent/internal/envelope"
	"claircode.app/clair-agent/internal/identity"
	"claircode.app/clair-agent/internal/presence"
	"claircode.app/clair-agent/internal/record"
	"claircode.app/clair-agent/internal/relay"
	"claircode.app/clair-agent/internal/state"
)

const (
	// The hello-ack is attempted helloAckRetries times, helloAckBackoff
	// apart, before it is left to the daemon (pendingHelloAck).
	helloAckRetries = 3
	helloAckBackoff = time.Second
	// Waiting on the relay lasts the pairing's life plus waitGrace, so the
	// relay's own 410 is what the user sees rather than a local timeout.
	waitGrace = 30 * time.Second
	// A new pair's first phone record has n under maxHelloN: the phone
	// starts each pair's counter at 1, within its first reserved block.
	maxHelloN = envelope.CounterBlock
	// A pair the relay completed but this host does not keep is revoked
	// within abandonTimeout, on a context of its own: the command's may be
	// what ended. The sealed revoke gets abandonUploadTimeout of it, so the
	// DELETE always has time (ADR 2026-09.mwfw).
	abandonTimeout       = 5 * time.Second
	abandonUploadTimeout = 2 * time.Second
)

// Errors a caller can test with errors.Is.
var (
	// ErrAlreadyPaired is a host with a pair when --replace was not given.
	ErrAlreadyPaired = errors.New("pairing: already paired")
	// ErrNotThisPhone is a completion the host could not decrypt: whoever
	// completed the pairing did not scan this QR (§6.2, §6.3).
	ErrNotThisPhone = errors.New("pairing: the completing phone did not scan this code")
	// ErrDeclined is the user answering no at the confirmation.
	ErrDeclined = errors.New("pairing: declined")
	// ErrNothingToUnpair is `clair unpair` on a host with no pair.
	ErrNothingToUnpair = errors.New("pairing: nothing to unpair")
	// ErrHooksNotWritten is a pair that was saved when no hooks, not even
	// the built-in block, could be written to settings.json.
	ErrHooksNotWritten = errors.New("pairing: Claude Code's hooks not written")
)

// Relay is the slice of the relay client pairing uses.
type Relay interface {
	MintPairing(ctx context.Context) (relay.Pairing, error)
	WaitPairing(ctx context.Context, pairingID string) (relay.Completed, error)
	Upload(ctx context.Context, pair string, envs []envelope.Envelope) (relay.Receipt, error)
	Revoke(ctx context.Context, pair string) error
}

// Daemon is the running daemon's control surface; ctl.Client satisfies it.
type Daemon interface {
	Reload(ctx context.Context) error
	ReleasePair(ctx context.Context, pairID string) error
}

// Options configure Pair and Unpair.
type Options struct {
	Dir *state.Dir
	// RelayURL is the relay to pair through.
	RelayURL string
	// NewRelay builds a client signing as the given key.
	NewRelay func(baseURL string, auth ed25519.PrivateKey) (Relay, error)
	// Daemon is the running daemon, or nil; ctl.ErrUnreachable is tolerated.
	Daemon Daemon
	// Install writes the hooks for the hello's snippet (nil when it sent
	// none): the phone's, or the built-in block in its place; an error means
	// none were written (claudecfg.SnippetInstaller.InstallAtPairing).
	// Uninstall removes them.
	Install   func(snippet json.RawMessage) (claudecfg.SnippetReport, error)
	Uninstall func() error
	Stdout    io.Writer
	Stderr    io.Writer
	// Term asks the confirmations; nil is headless (print and continue).
	Term Terminal
	QR   QRMode
	// Invert draws the QR for a light terminal.
	Invert bool
	// Replace allows replacing an existing pair without asking; Yes skips
	// the "Pair with …?" confirmation.
	Replace, Yes bool
	Now          func() time.Time
	Entropy      io.Reader
	Hostname     string
	AgentVersion string
}

// Pair runs `clair pair`.
func Pair(ctx context.Context, o Options) error {
	if o.Dir == nil || o.NewRelay == nil || o.Entropy == nil || o.Install == nil {
		return errors.New("pairing: Dir, NewRelay, Entropy and Install are required")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Stdout == nil {
		o.Stdout = io.Discard
	}
	if o.Stderr == nil {
		o.Stderr = io.Discard
	}
	if o.QR == "" {
		o.QR = QRUnicode
	}

	existing, err := o.Dir.ListPairs()
	if err != nil {
		return err
	}
	replacing := len(existing) > 0
	if replacing {
		if err = o.confirmReplace(ctx, existing); err != nil {
			return err
		}
	}
	// A replace pairs under a new host key (§6.6) that is saved, and the old
	// pairs revoked, only once the new pairing is proven and accepted: a
	// code that expires or a phone that is declined leaves the host as it
	// was (AG-19).
	host, err := o.hostKey(replacing)
	if err != nil {
		return err
	}
	client, err := o.NewRelay(o.RelayURL, host.Auth())
	if err != nil {
		return err
	}

	pairing, err := client.MintPairing(ctx)
	if err != nil {
		return describeRelayError("mint a pairing", err)
	}
	payload := Payload{V: payloadVersion}
	if payload.PairingID, err = pairingIDBytes(pairing.ID); err != nil {
		return err
	}
	copy(payload.HostPub[:], host.AgreementPublic())
	if _, err = io.ReadFull(o.Entropy, payload.K[:]); err != nil {
		return fmt.Errorf("pairing: read pairing secret: %w", err)
	}
	link, err := PayloadURL(o.RelayURL, payload)
	if err != nil {
		return err
	}
	fmt.Fprintln(o.Stdout)
	if _, err = RenderQR(o.Stdout, link, o.QR, o.Invert); err != nil {
		return err
	}
	fmt.Fprintf(o.Stdout, "\nScan with Clair on your phone, or enter this link in the app:\n\n  %s\n\n", link)
	if !pairing.ExpiresAt.IsZero() {
		fmt.Fprintf(o.Stdout, "The code expires at %s (in %d minutes). Waiting for the phone…\n", pairing.ExpiresAt.Local().Format("15:04"), int(time.Until(pairing.ExpiresAt).Minutes()))
	} else {
		fmt.Fprintln(o.Stdout, "Waiting for the phone…")
	}

	waitCtx := ctx
	if !pairing.ExpiresAt.IsZero() {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithDeadline(ctx, pairing.ExpiresAt.Add(waitGrace))
		defer cancel()
	}
	completed, err := client.WaitPairing(waitCtx, pairing.ID)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			return errors.New("pairing: the code expired (10 minutes); run `clair pair` again")
		}
		return describeRelayError("wait for the phone", err)
	}
	// The relay now holds a pair the phone may already show. Until its file
	// is saved, every way out — an impostor, a no, Ctrl-C, a hangup, a
	// terminal or a disk that fails — revokes it, so neither end keeps an
	// orphan (ADR 2026-09.mwfw).
	unfinished := &unfinishedPair{client: client, pairID: completed.PairID}
	defer o.abandon(ctx, unfinished)

	keys, err := envelope.Derive(host.Agreement(), completed.PhonePub, payload.K[:])
	if err != nil {
		return err
	}
	hello, err := openHello(keys, completed)
	if err != nil {
		// Whoever completed the pairing does not know k: the revoke gives
		// them nothing further.
		return fmt.Errorf("%w: %w", ErrNotThisPhone, err)
	}
	if hello.N > maxHelloN {
		return fmt.Errorf("pairing: the phone's hello claims n=%d; a new pair's first record is under %d", hello.N, maxHelloN)
	}
	name := hello.Name
	if name == "" {
		name = "an unnamed phone"
	}
	if o.Term != nil && !o.Yes {
		ok, err := o.Term.Confirm(ctx, fmt.Sprintf("Pair with %q?", name), true)
		if err != nil {
			return interrupted(ctx, err)
		}
		if !ok {
			return ErrDeclined
		}
	} else {
		fmt.Fprintf(o.Stdout, "Pairing with %q.\n", name)
	}
	if replacing {
		if err := o.releaseAll(ctx, existing); err != nil {
			return interrupted(ctx, err)
		}
		if err := o.Dir.SaveHostKey(host); err != nil {
			return err
		}
	}

	pair := state.Pair{
		PairID:    completed.PairID,
		Relay:     o.RelayURL,
		PhonePub:  base64.RawURLEncoding.EncodeToString(completed.PhonePub),
		PhoneName: hello.Name,
		CreatedAt: o.Now(),
		P2HLast:   hello.N,
		H2PNext:   2, // the hello-ack takes n=1
	}
	if hello.Presence != nil && hello.Presence.IdleThresholdSec != nil {
		sec := presence.ClampThresholdSec(*hello.Presence.IdleThresholdSec)
		pair.IdleThresholdSec = &sec
	}
	pair.SetKeys(keys)
	// From here the phone may hold the hello-ack, and an abandoned pair is
	// ended with a sealed revoke as well.
	unfinished.acked = keys
	if err := o.sendHelloAck(ctx, client, keys, completed.PairID); err != nil && ctx.Err() == nil {
		fmt.Fprintf(o.Stderr, "clair pair: the hello-ack did not reach the relay (%v); the daemon will send it.\n", err)
		pair.PendingHelloAck = true
	}
	if err := ctx.Err(); err != nil {
		return interrupted(ctx, err)
	}
	if err := o.Dir.SavePair(pair); err != nil {
		return err
	}
	unfinished.kept = true

	report, installErr := o.Install(hello.Snippet)
	for _, w := range report.Warnings() {
		fmt.Fprintf(o.Stderr, "clair pair: %s.\n", w)
	}
	if installErr != nil {
		// The pair is kept: the phone shows it and the daemon runs it, but
		// Claude Code calls nobody. Say so, and fail (ADR 2026-09.bckr).
		o.reloadDaemon(ctx)
		return fmt.Errorf("%w (%w). The pair with %q is saved, but Claude Code will not reach the phone until they are: "+
			"fix that, then run `clair pair --replace` to pair again, or `clair unpair` to drop the pair", ErrHooksNotWritten, installErr, name)
	}
	switch {
	case report.Unchanged:
		fmt.Fprintln(o.Stdout, "Claude Code's settings.json already had these hooks; left as it was.")
	case report.Backup != "":
		fmt.Fprintln(o.Stdout, "Hooks written to Claude Code's settings.json (a .bak copy sits beside it).")
	default:
		fmt.Fprintln(o.Stdout, "Hooks written to Claude Code's settings.json.")
	}
	o.reloadDaemon(ctx)
	fmt.Fprintf(o.Stdout, "Paired with %q. Fingerprint: %s\nRestart any running Claude Code session to pick up the hooks.\n", name, keys.Fingerprint())
	return nil
}

// unfinishedPair is a pair the relay completed and this host has not saved.
type unfinishedPair struct {
	client Relay
	pairID string
	// acked holds the traffic keys once a hello-ack may have reached the
	// relay; kept is set once the pair file is saved.
	acked *envelope.Keys
	kept  bool
}

// abandon revokes an unfinished pair at the relay, best effort, on a
// context of its own bounded to abandonTimeout: the command's may be what
// ended. A phone still waiting for its hello-ack drops a pair the relay
// reports revoked; one that may have read the hello-ack gets a sealed
// revoke first, which ends the pair on the phone instead of parking it
// (RELAY.md §6.6; ADR 2026-09.mwfw).
func (o Options) abandon(ctx context.Context, p *unfinishedPair) {
	if p.kept {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), abandonTimeout)
	defer cancel()
	if p.acked != nil {
		env, err := o.sealControl(p.acked, p.pairID, record.Record{N: 2, Kind: record.KindControl, Control: record.ControlRevoke})
		if err == nil {
			uploadCtx, cancelUpload := context.WithTimeout(ctx, abandonUploadTimeout)
			_, err = p.client.Upload(uploadCtx, p.pairID, []envelope.Envelope{env})
			cancelUpload()
		}
		if err != nil {
			fmt.Fprintf(o.Stderr, "clair pair: the phone was not sent the revoke (%v); it will see the pair gone.\n", err)
		}
	}
	if err := p.client.Revoke(ctx, p.pairID); err != nil && !errors.Is(err, relay.ErrRevoked) && !errors.Is(err, relay.ErrNotFound) {
		fmt.Fprintf(o.Stderr, "clair pair: the relay did not drop the unfinished pair %s: %v\n", p.pairID, err)
	}
}

// interrupted names a way out that ended the command — Ctrl-C, SIGTERM,
// a hangup — for what it is, rather than as the error it caused.
func interrupted(ctx context.Context, err error) error {
	if ctx.Err() == nil {
		return err
	}
	return fmt.Errorf("pairing: interrupted before the pair was saved; it was not kept (%w)", context.Cause(ctx))
}

// confirmReplace asks before replacing an existing pair.
func (o Options) confirmReplace(ctx context.Context, existing []state.Pair) error {
	if o.Replace {
		return nil
	}
	quoted := make([]string, len(existing))
	for i := range existing {
		quoted[i] = fmt.Sprintf("%q", existing[i].PhoneName)
	}
	names := strings.Join(quoted, ", ")
	if o.Term == nil {
		return fmt.Errorf("%w with %s; pass --replace to pair again with new keys", ErrAlreadyPaired, names)
	}
	ok, err := o.Term.Confirm(ctx, fmt.Sprintf("Already paired with %s. Replace it (new keys on both sides)?", names), false)
	if err != nil {
		return err
	}
	if !ok {
		return ErrDeclined
	}
	return nil
}

// releaseAll stops and revokes the existing pairs: the daemon hands the
// files over (or they are removed directly when it is not running), the
// relay is told, and the old host key goes with them.
func (o Options) releaseAll(ctx context.Context, existing []state.Pair) error {
	oldHost, err := o.Dir.LoadHostKey()
	if err != nil && !errors.Is(err, state.ErrNotFound) {
		return err
	}
	for i := range existing {
		p := &existing[i]
		if err := o.releasePair(ctx, p.PairID); err != nil {
			return err
		}
		if oldHost != nil {
			if client, err := o.NewRelay(p.Relay, oldHost.Auth()); err == nil {
				if err := client.Revoke(ctx, p.PairID); err != nil && !errors.Is(err, relay.ErrRevoked) && !errors.Is(err, relay.ErrNotFound) {
					fmt.Fprintf(o.Stderr, "clair pair: the relay did not revoke %s: %v\n", p.PairID, err)
				}
			}
		}
	}
	return nil
}

// releasePair takes a pair file back from the daemon — which stops the pair
// and deletes the file — and deletes it regardless, which is what happens
// when no daemon is running or it never held the pair.
func (o Options) releasePair(ctx context.Context, pairID string) error {
	if o.Daemon != nil {
		if err := o.Daemon.ReleasePair(ctx, pairID); err != nil && !errors.Is(err, ctl.ErrUnreachable) && !errors.Is(err, ctl.ErrNotFound) {
			return err
		}
	}
	return o.Dir.DeletePair(pairID)
}

// hostKey returns the host's keys: new, not yet saved ones for a replace
// (§6.6) — Pair saves them once the new pairing is accepted — else whatever
// is there, created on first use.
func (o Options) hostKey(replace bool) (*identityKeys, error) {
	if replace {
		return identity.Generate(o.Entropy)
	}
	keys, _, err := o.Dir.EnsureHostKey(o.Entropy)
	return keys, err
}

// openHello verifies the completion: the envelope must be addressed to the
// new pair in the phone's direction, decrypt under the derived key, and be
// a hello. Success is the proof that the completing phone scanned this QR.
func openHello(keys *envelope.Keys, completed relay.Completed) (*record.Record, error) {
	env := completed.Envelope
	if err := env.Validate(completed.PairID, envelope.DirP2H); err != nil {
		return nil, err
	}
	plain, err := envelope.Open(keys.Key(envelope.DirP2H), env)
	if err != nil {
		return nil, err
	}
	rec, err := record.Unmarshal(plain)
	if err != nil {
		return nil, err
	}
	if rec.Kind != record.KindControl || rec.Control != record.ControlHello {
		return nil, fmt.Errorf("pairing: the phone's first record is %s/%s, not hello", rec.Kind, rec.Control)
	}
	return rec, nil
}

// sendHelloAck uploads the hello-ack as the pair's first host record.
func (o Options) sendHelloAck(ctx context.Context, client Relay, keys *envelope.Keys, pairID string) error {
	env, err := o.sealControl(keys, pairID, record.Record{N: 1, Kind: record.KindControl, Control: record.ControlHelloAck, Hostname: o.Hostname, AgentVersion: o.AgentVersion})
	if err != nil {
		return err
	}
	for attempt := range helloAckRetries {
		_, err = client.Upload(ctx, pairID, []envelope.Envelope{env})
		if err == nil || ctx.Err() != nil {
			return err
		}
		if attempt < helloAckRetries-1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(helloAckBackoff):
			}
		}
	}
	return err
}

// sealControl seals a control record from the host to the phone.
func (o Options) sealControl(keys *envelope.Keys, pairID string, rec record.Record) (envelope.Envelope, error) {
	plain, err := record.Marshal(&rec)
	if err != nil {
		return envelope.Envelope{}, err
	}
	id, err := envelope.NewID(o.Now(), o.Entropy)
	if err != nil {
		return envelope.Envelope{}, err
	}
	return envelope.Seal(keys.Key(envelope.DirH2P), envelope.Header{
		Pair: pairID, ID: id, Dir: envelope.DirH2P, Wake: record.ControlWake, TTLSec: record.TTL(record.ControlWake, 0),
	}, plain, o.Entropy)
}

// reloadDaemon tells a running daemon to pick the pair up, or says how to start one.
func (o Options) reloadDaemon(ctx context.Context) {
	if o.Daemon == nil {
		fmt.Fprintln(o.Stdout, "Start the agent with `clair daemon` to bring the phone online.")
		return
	}
	err := o.Daemon.Reload(ctx)
	switch {
	case err == nil:
		fmt.Fprintln(o.Stdout, "The running agent picked the pair up.")
	case errors.Is(err, ctl.ErrUnreachable):
		fmt.Fprintln(o.Stdout, "No agent is running; start it with `clair daemon`.")
	default:
		fmt.Fprintf(o.Stderr, "clair pair: the agent did not reload: %v\n", err)
	}
}

// Unpair runs `clair unpair`: the pairs are released and revoked, the hooks
// removed, the host key deleted (§6.6).
func Unpair(ctx context.Context, o Options) error {
	if o.Dir == nil || o.NewRelay == nil || o.Uninstall == nil {
		return errors.New("pairing: Dir, NewRelay and Uninstall are required")
	}
	if o.Stdout == nil {
		o.Stdout = io.Discard
	}
	if o.Stderr == nil {
		o.Stderr = io.Discard
	}
	existing, err := o.Dir.ListPairs()
	if err != nil {
		return err
	}
	if len(existing) == 0 {
		if _, err := o.Dir.LoadHostKey(); errors.Is(err, state.ErrNotFound) {
			return ErrNothingToUnpair
		}
	}
	if err := o.releaseAll(ctx, existing); err != nil {
		return err
	}
	if err := o.Uninstall(); err != nil {
		fmt.Fprintf(o.Stderr, "clair unpair: hooks not removed: %v\n", err)
	} else {
		fmt.Fprintln(o.Stdout, "Hooks and the statusline removed from Claude Code's settings.json (a .bak copy sits beside it).")
	}
	if err := o.Dir.DeleteHostKey(); err != nil {
		return err
	}
	if o.Daemon != nil {
		if err := o.Daemon.Reload(ctx); err != nil && !errors.Is(err, ctl.ErrUnreachable) {
			fmt.Fprintf(o.Stderr, "clair unpair: the agent did not reload: %v\n", err)
		}
	}
	fmt.Fprintln(o.Stdout, "Unpaired. Restart any running Claude Code session; run `clair pair` to pair again.")
	return nil
}

// describeRelayError turns the relay's refusals into sentences.
func describeRelayError(doing string, err error) error {
	switch {
	case errors.Is(err, relay.ErrPairingUsed):
		return fmt.Errorf("pairing: this code was already used; if that wasn't you, run `clair unpair` (%w)", err)
	case errors.Is(err, relay.ErrPairingExpired):
		return fmt.Errorf("pairing: the code expired (10 minutes); run `clair pair` again (%w)", err)
	case errors.Is(err, relay.ErrRateLimited):
		msg := "pairing: the relay is rate limiting pairings; try again later"
		if serr, ok := errors.AsType[*relay.StatusError](err); ok && serr.RetryAfter > 0 {
			msg = fmt.Sprintf("pairing: the relay is rate limiting pairings; try again in %s", serr.RetryAfter)
		}
		return fmt.Errorf("%s (%w)", msg, err)
	default:
		return fmt.Errorf("pairing: %s: %w", doing, err)
	}
}
