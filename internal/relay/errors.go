package relay

import (
	"errors"
	"fmt"
	"time"
)

// Sentinels for the relay's answers, testable with errors.Is. A *StatusError
// wraps the one that fits and carries the detail.
var (
	// ErrUnauthorized is a 401 the client could not fix by correcting its clock.
	ErrUnauthorized = errors.New("relay: unauthorised")
	// ErrBadRequest is a 400: an envelope whose dir does not match the caller's
	// role, a pair that does not match the path, a malformed body.
	ErrBadRequest = errors.New("relay: bad request")
	// ErrNotFound is a 404: a pair the caller is not a member of, or a pairing
	// another host minted (the relay does not disclose existence).
	ErrNotFound = errors.New("relay: not found")
	// ErrPairingUsed is a 409 on complete: a phone got there first (§6.3).
	ErrPairingUsed = errors.New("relay: pairing already used")
	// ErrPairingExpired is a 410 `pairing_expired`: the ten minutes are over.
	ErrPairingExpired = errors.New("relay: pairing expired")
	// ErrRevoked is a 410 on a pair, or the stream's `revoked` event: the other
	// side ended the pair (§6.6).
	ErrRevoked = errors.New("relay: pair revoked")
	// ErrTooLarge is a 413: an envelope or batch over the 4 MiB cap.
	ErrTooLarge = errors.New("relay: payload too large")
	// ErrRateLimited is a 429 `rate_limited`; RetryAfter says when to try again.
	ErrRateLimited = errors.New("relay: rate limited")
	// ErrMailboxFull is a 429 `mailbox_full`: the peer's mailbox hit its cap.
	ErrMailboxFull = errors.New("relay: mailbox full")
	// ErrUnavailable is a 5xx: the relay (or the platform in front of it) is
	// having a moment; the call is worth retrying with backoff.
	ErrUnavailable = errors.New("relay: unavailable")
	// ErrProtocol is an answer this client cannot make sense of.
	ErrProtocol = errors.New("relay: protocol error")
)

// StatusError is an HTTP status the relay answered with. It unwraps to the
// sentinel above that classifies it.
type StatusError struct {
	// Status is the HTTP status code.
	Status int
	// Code is the body's `error` field, when the body was JSON.
	Code string
	// Reason is a 401's `reason`: skew, signature or malformed.
	Reason string
	// RetryAfter is a 429's Retry-After, clamped to RetryAfterMax; zero when absent.
	RetryAfter time.Duration
	// Path is the request path, for the message.
	Path string

	sentinel error
}

func (e *StatusError) Error() string {
	msg := fmt.Sprintf("relay: %s answered %d", e.Path, e.Status)
	if e.Code != "" {
		msg += " " + e.Code
	}
	if e.Reason != "" {
		msg += " (" + e.Reason + ")"
	}
	return msg
}

// Unwrap yields the sentinel that classifies the status.
func (e *StatusError) Unwrap() error { return e.sentinel }
