package relay

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"claircode.app/clair-agent/internal/envelope"
)

// EventKind discriminates what a stream delivered.
type EventKind int

// The event kinds of GET /v1/pairs/{pair}/events.
const (
	// EventEnvelope is an envelope addressed to this side; Cursor is its
	// mailbox position, to acknowledge once applied.
	EventEnvelope EventKind = iota + 1
	// EventPresence says the peer's stream opened or closed (RELAY.md §7.6).
	EventPresence
	// EventRevoked says the pair was revoked; Stream returns ErrRevoked after
	// delivering it.
	EventRevoked
)

// Presence is the peer's stream state.
type Presence struct {
	// Peer is "host" or "phone".
	Peer string
	// State is "connected" or "idle".
	State string
	// At is when it changed.
	At time.Time
}

// Event is one delivery from a stream.
type Event struct {
	Kind     EventKind
	Cursor   Cursor
	Envelope *envelope.Envelope
	Presence *Presence
}

// Handler receives stream events in order, synchronously. Returning nil means
// the event was applied and the resume cursor may move past it; an error
// stops the stream and is returned by Stream as is.
type Handler func(ctx context.Context, ev Event) error

// errRetryNow says a connection failed for a reason a re-signed request
// fixes (a corrected clock, a spent nonce): reconnect without waiting, once.
// It wraps the *StatusError, which follow surfaces if the retry is refused
// the same way.
var errRetryNow = errors.New("relay: retry now")

// errIdle says the idle watchdog closed a silent stream.
var errIdle = errors.New("relay: stream idle")

// handlerError wraps an error the Handler returned, so follow can tell it
// from a transport error and hand it back unchanged.
type handlerError struct{ err error }

func (e *handlerError) Error() string { return e.err.Error() }
func (e *handlerError) Unwrap() error { return e.err }

// Stream follows GET /v1/pairs/{pair}/events from last (the Last-Event-ID;
// empty drains from the oldest surviving row) and hands every event to h. It
// owns reconnection: a clean bounded end (the deadline's, or a quiet end
// because a newer stream took over the pair side) is followed after the
// relay's `retry:`, a failed connection after a jittered exponential backoff,
// a corrected clock or a spent nonce immediately, once. It returns when ctx ends, when h returns an
// error, with ErrRevoked after a `revoked` event or a 410, and with the
// relay's answer for anything a reconnect cannot fix (404, 401, …).
func (c *Client) Stream(ctx context.Context, pair string, last Cursor, h Handler) error {
	path := "/v1/pairs/" + url.PathEscape(pair) + "/events"
	return c.follow(ctx, path, string(last), func(ev sseEvent) error {
		switch ev.name {
		case "envelope":
			var env envelope.Envelope
			if json.Unmarshal(ev.data, &env) != nil {
				// The relay's problem, not ours; the row would repeat on every
				// resume, so skip it rather than stall the pair.
				c.log.Warn("stream envelope unreadable, skipped", "pair", pair, "cursor", ev.id, "bytes", len(ev.data))
				return nil //nolint:nilerr // skipping the row is the point; see the comment above
			}
			return h(ctx, Event{Kind: EventEnvelope, Cursor: Cursor(ev.id), Envelope: &env})
		case "presence":
			var body struct {
				Peer  string          `json:"peer"`
				State string          `json:"state"`
				At    json.RawMessage `json:"at"`
			}
			if json.Unmarshal(ev.data, &body) != nil {
				c.log.Warn("stream presence unreadable, skipped", "pair", pair, "cursor", ev.id)
				return nil //nolint:nilerr // presence is advisory; an unreadable one is dropped
			}
			p := &Presence{Peer: body.Peer, State: body.State}
			if unix, ok := parseUnix(body.At); ok {
				p.At = time.Unix(unix, 0)
			}
			return h(ctx, Event{Kind: EventPresence, Cursor: Cursor(ev.id), Presence: p})
		case "revoked":
			_ = h(ctx, Event{Kind: EventRevoked, Cursor: Cursor(ev.id)})
			return ErrRevoked
		default:
			return nil
		}
	})
}

// errPairingDone ends WaitPairing's follow once the completion arrived.
var errPairingDone = errors.New("relay: pairing completed")

// WaitPairing follows GET /v1/pairings/{id}/wait until the phone completes
// the pairing (RELAY.md §6, §7.2). The ten-minute limit is the caller's
// context deadline; ErrPairingExpired is the relay's word that it passed.
func (c *Client) WaitPairing(ctx context.Context, pairingID string) (Completed, error) {
	var out Completed
	path := "/v1/pairings/" + url.PathEscape(pairingID) + "/wait"
	err := c.follow(ctx, path, "", func(ev sseEvent) error {
		if ev.name != "completed" {
			return nil
		}
		var body struct {
			PairID   string            `json:"pairId"`
			PhonePub string            `json:"phonePub"`
			Envelope envelope.Envelope `json:"envelope"`
		}
		if err := json.Unmarshal(ev.data, &body); err != nil {
			return fmt.Errorf("%w: completed event: %w", ErrProtocol, err)
		}
		pub, err := base64.RawURLEncoding.Strict().DecodeString(body.PhonePub)
		if err != nil || len(pub) != envelope.KeySize || body.PairID == "" {
			return fmt.Errorf("%w: completed event: bad pairId or phonePub", ErrProtocol)
		}
		out = Completed{PairID: body.PairID, PhonePub: pub, Envelope: body.Envelope}
		return errPairingDone
	})
	if errors.Is(err, errPairingDone) {
		return out, nil
	}
	return Completed{}, err
}

// openStream performs the signed GET for a stream and returns the response
// once it is a 200. A 401 a re-signed request can fix yields errRetryNow.
func (c *Client) openStream(ctx context.Context, path, lastID string) (*http.Response, error) {
	req, err := c.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	if lastID != "" {
		req.Header.Set("Last-Event-ID", lastID)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("relay: open %s: %w", path, err)
	}
	if resp.StatusCode == http.StatusOK {
		return resp, nil
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := readBody(resp.Body, maxErrorBody)
	serr := c.statusError(path, resp, data)
	if resp.StatusCode == http.StatusUnauthorized && c.resign(path, serr, resp.Header, data) {
		return nil, fmt.Errorf("%w: %w", errRetryNow, serr)
	}
	return nil, serr
}

// connectOnce runs one connection: open, deliver events until the relay ends the
// stream, the connection fails, the watchdog fires, or fn refuses one. It
// returns the id to resume from, the relay's retry hint, whether anything
// was delivered, and nil for a clean end.
func (c *Client) connectOnce(ctx context.Context, path, lastID string, fn func(sseEvent) error) (newLast string, retry time.Duration, delivered bool, err error) {
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	resp, err := c.openStream(connCtx, path, lastID)
	if err != nil {
		return lastID, 0, false, err
	}
	defer func() { _ = resp.Body.Close() }()

	// The watchdog closes a connection that went quiet for longer than the
	// relay's keepalive cadence allows; every line resets it.
	watchdog := time.AfterFunc(c.idle, cancel)
	defer watchdog.Stop()
	rd := newSSEReader(resp.Body, func() { watchdog.Reset(c.idle) })
	rd.lastID = lastID
	newLast = lastID
	for {
		ev, err := rd.next()
		if err != nil {
			switch {
			case errors.Is(err, io.EOF):
				return rd.lastID, rd.retry, delivered, nil
			case ctx.Err() != nil:
				return newLast, 0, delivered, ctx.Err()
			case connCtx.Err() != nil:
				return newLast, 0, delivered, errIdle
			case errors.Is(err, ErrProtocol):
				return newLast, 0, delivered, err
			default:
				return newLast, 0, delivered, fmt.Errorf("relay: stream %s: %w", path, err)
			}
		}
		if err := fn(ev); err != nil {
			return newLast, 0, delivered, &handlerError{err: err}
		}
		delivered = true
		newLast = rd.lastID
	}
}

// follow keeps a stream alive across the relay's bounded ends and the
// network's failures, resuming from the last applied id each time.
func (c *Client) follow(ctx context.Context, path, lastID string, fn func(sseEvent) error) error {
	attempt := 0
	// retriedNow is set after an immediate retry, so a second refusal in a
	// row is surfaced instead of looping (ADR 2026-09.n68c).
	retriedNow := false
	for {
		newLast, retry, delivered, err := c.connectOnce(ctx, path, lastID, fn)
		lastID = newLast
		if !errors.Is(err, errRetryNow) {
			retriedNow = false
		}
		var wait time.Duration
		switch {
		case err == nil:
			attempt = 0
			wait = DefaultRetry
			if retry > 0 {
				wait = retry
			}
			wait = min(max(wait, RetryMin), RetryMax)
			c.log.Debug("stream ended, reconnecting", "path", path, "after_ms", wait.Milliseconds())
		case ctx.Err() != nil:
			return ctx.Err()
		case errors.Is(err, errRetryNow):
			if retriedNow {
				if serr, ok := errors.AsType[*StatusError](err); ok {
					return serr
				}
				return err
			}
			retriedNow = true
			wait = 0
		default:
			if herr, ok := errors.AsType[*handlerError](err); ok {
				return herr.err
			}
			if !retryable(err) {
				return err
			}
			if delivered {
				attempt = 0
			}
			wait = backoff(attempt, c.jitter())
			if serr, ok := errors.AsType[*StatusError](err); ok && serr.RetryAfter > wait {
				wait = serr.RetryAfter
			}
			attempt++
			c.log.Warn("stream failed, reconnecting", "path", path, "attempt", attempt, "after_ms", wait.Milliseconds(), "error", err.Error())
		}
		if err := c.sleep(ctx, wait); err != nil {
			return err
		}
	}
}

// retryable reports whether a failed connection is worth another try: a
// transport error, an idle timeout, a 429 or a 5xx — not the relay saying no.
func retryable(err error) bool {
	if _, ok := errors.AsType[*StatusError](err); ok {
		return errors.Is(err, ErrRateLimited) || errors.Is(err, ErrMailboxFull) || errors.Is(err, ErrUnavailable)
	}
	return !errors.Is(err, ErrProtocol)
}

// backoff is the delay before reconnection attempt n: exponential from
// BackoffInitial, capped at BackoffMax, with equal jitter (half fixed, half
// random) so a fleet of agents does not reconnect in lockstep (§13).
func backoff(attempt int, jitter float64) time.Duration {
	d := BackoffInitial << min(max(attempt, 0), 6)
	d = min(d, BackoffMax)
	half := d / 2
	return half + time.Duration(float64(half)*min(max(jitter, 0), 1))
}
