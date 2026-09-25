// Package ctl is the daemon's control surface as the CLI sees it: the JSON it
// answers on the loopback listener under /clair/ctl and a client for it.
// `clair status` reads it; `clair pair` asks the daemon to release a pair and
// to reload; `clair service stop` asks it to stop; `clair update` asks it to
// check for a release. It shares the hook listener but not the hook bearer:
// the admin token never leaves the config directory.
//
// After a self-update the CLI on disk can be newer than the running daemon,
// by any number of releases, so this JSON only ever gains fields
// (ADR 2026-09.66m4).
package ctl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Prefix is the control surface's path prefix on the loopback listener.
const Prefix = "/clair/ctl/"

// Paths under Prefix.
const (
	PathStatus = Prefix + "status"
	PathReload = Prefix + "reload"
	PathStop   = Prefix + "stop"
	PathPairs  = Prefix + "pairs/"
	// PathUpdate takes `check=1` to only look, and `releases=<url>` to read
	// another release server.
	PathUpdate = Prefix + "update"
)

// updateTimeout bounds `clair update` through the daemon: a download of a
// build over a slow link, then its first run.
const updateTimeout = 12 * time.Minute

// Errors a caller can test with errors.Is.
var (
	// ErrUnreachable is a daemon that is not listening.
	ErrUnreachable = errors.New("ctl: daemon unreachable")
	// ErrNotFound is a pair the daemon does not hold.
	ErrNotFound = errors.New("ctl: not found")
	// ErrUnauthorized is a rejected admin token.
	ErrUnauthorized = errors.New("ctl: admin token rejected")
)

// Status is what the daemon reports about itself.
type Status struct {
	Version   string       `json:"version"`
	Listen    string       `json:"listen"`
	Relay     string       `json:"relay"`
	UptimeSec int64        `json:"uptimeSec"`
	Paired    bool         `json:"paired"`
	Pairs     []PairStatus `json:"pairs"`
	// Unpaired explains why there is no pair when there used to be one.
	Unpaired string `json:"unpaired,omitempty"`
	// Presence is the host's terminal-input reading at the time of the call
	// (RELAY.md §4.3); nil when the host has no signal.
	Presence *Presence `json:"presence,omitempty"`
	// Update is the self-updater's state; nil from a daemon older than it.
	Update *UpdateStatus `json:"update,omitempty"`
}

// UpdateStatus is what the daemon knows about releases (ADR 2026-09.qk6v).
type UpdateStatus struct {
	// Off says why this daemon never updates itself; "" when it does.
	Off string `json:"off,omitempty"`
	// Paused is agent.json's autoUpdate turned off: no background check,
	// though `clair update` still runs one.
	Paused bool `json:"paused,omitempty"`
	// Path is the binary the updater replaces.
	Path string `json:"path,omitempty"`
	// Latest is the newest release at the last successful check.
	Latest string `json:"latest,omitempty"`
	// Staged is a release swapped onto disk that the daemon is not running
	// yet; it runs from the next start.
	Staged string `json:"staged,omitempty"`
	// Note says why the last check left the binary on disk alone.
	Note string `json:"note,omitempty"`
	// LastCheckAt is when the last check finished; LastError its failure.
	LastCheckAt time.Time `json:"lastCheckAt,omitzero"`
	LastError   string    `json:"lastError,omitempty"`
}

// Update outcomes: internal/update's, plus the two the daemon adds.
const (
	OutcomeUpToDate      = "up-to-date"
	OutcomeAvailable     = "available"
	OutcomeStaged        = "staged"
	OutcomeAlreadyStaged = "already-staged"
	OutcomeLeftAlone     = "left-alone"
	// OutcomeOff is a daemon that does not update itself (UpdateResult.Note says why).
	OutcomeOff = "off"
	// OutcomeFailed is a check that failed (UpdateResult.Error).
	OutcomeFailed = "failed"
)

// UpdateRequest is one `clair update`.
type UpdateRequest struct {
	// Check only looks; otherwise a newer release is staged.
	Check bool
	// Releases reads another release server this once; "" is the daemon's.
	Releases string
}

// UpdateResult is what an update check found or did.
type UpdateResult struct {
	Outcome string `json:"outcome"`
	// Running is the version the daemon runs.
	Running string `json:"running"`
	// Latest is the newest release, when the check got that far.
	Latest string `json:"latest,omitempty"`
	// Path is the binary checked or replaced.
	Path  string `json:"path,omitempty"`
	Note  string `json:"note,omitempty"`
	Error string `json:"error,omitempty"`
}

// Presence is one reading of the host's terminal input idle.
type Presence struct {
	IdleMs int64  `json:"idleMs"`
	Source string `json:"source"` // pty or console
}

// PairStatus is one loaded pair.
type PairStatus struct {
	PairID      string    `json:"pairId"`
	PhoneName   string    `json:"phoneName"`
	Fingerprint string    `json:"fingerprint"`
	Phone       string    `json:"phone"` // connected, idle or unknown
	PhoneSeenAt time.Time `json:"phoneSeenAt,omitzero"`
	// QueueRecords and QueueBytes describe the outbound FIFO; Held is the
	// number of decides waiting on the phone.
	QueueRecords int  `json:"queueRecords"`
	QueueBytes   int  `json:"queueBytes"`
	Held         int  `json:"held"`
	Uploader     Link `json:"uploader"`
	Stream       Link `json:"stream"`
	// SkewSec is the clock correction learnt from the relay.
	SkewSec int64 `json:"skewSec"`
	// IdleThresholdSec is the phone's presence threshold; 0 means a bubbled
	// decide is never released to the terminal.
	IdleThresholdSec int64 `json:"idleThresholdSec"`
	// Dormant is set while the relay reports the pair gone (410 or 404): the
	// pair is parked, its keys and hooks kept, until the relay accepts it
	// again, the phone confirms, `clair unpair`, or DeleteAfter.
	Dormant *Dormant `json:"dormant,omitempty"`
}

// Dormant describes a parked pair.
type Dormant struct {
	// Reason is the agent's own wording, never the relay's.
	Reason      string    `json:"reason"`
	Since       time.Time `json:"since"`
	DeleteAfter time.Time `json:"deleteAfter"`
}

// Link is the state of one relay connection.
type Link struct {
	State     string    `json:"state"` // connected, backoff, idle or stopped
	LastError string    `json:"lastError,omitempty"`
	LastOKAt  time.Time `json:"lastOkAt,omitzero"`
}

// Client talks to a running daemon.
type Client struct {
	// Base is the daemon's listen address as a URL, e.g. http://127.0.0.1:7317.
	Base string
	// AdminToken is agent.json's adminToken.
	AdminToken string
	// HTTP is the client to use; nil means one with a short timeout.
	HTTP *http.Client
}

// Status fetches the daemon's status.
func (c *Client) Status(ctx context.Context) (Status, error) {
	var s Status
	body, err := c.call(ctx, http.MethodGet, PathStatus)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(body, &s); err != nil {
		return s, fmt.Errorf("ctl: decode status: %w", err)
	}
	return s, nil
}

// Reload asks the daemon to re-read its keys and pairs.
func (c *Client) Reload(ctx context.Context) error {
	_, err := c.call(ctx, http.MethodPost, PathReload)
	return err
}

// Stop asks the daemon to shut down the way a SIGTERM would: held decides
// answered, queues drained, streams released. It returns once the daemon has
// accepted; the listener goes a moment later.
func (c *Client) Stop(ctx context.Context) error {
	_, err := c.call(ctx, http.MethodPost, PathStop)
	return err
}

// ReleasePair asks the daemon to stop a pair and hand its file to the caller.
func (c *Client) ReleasePair(ctx context.Context, pairID string) error {
	_, err := c.call(ctx, http.MethodDelete, PathPairs+url.PathEscape(pairID))
	return err
}

// Update asks the daemon to check for a release, and to stage it unless
// req.Check. A daemon older than the self-updater answers ErrNotFound.
func (c *Client) Update(ctx context.Context, req UpdateRequest) (UpdateResult, error) {
	var res UpdateResult
	q := url.Values{}
	if req.Check {
		q.Set("check", "1")
	}
	if req.Releases != "" {
		q.Set("releases", req.Releases)
	}
	path := PathUpdate
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	body, err := c.callTimeout(ctx, http.MethodPost, path, updateTimeout)
	if err != nil {
		return res, err
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return res, fmt.Errorf("ctl: decode update: %w", err)
	}
	return res, nil
}

func (c *Client) call(ctx context.Context, method, path string) ([]byte, error) {
	return c.callTimeout(ctx, method, path, 5*time.Second)
}

func (c *Client) callTimeout(ctx context.Context, method, path string, timeout time.Duration) ([]byte, error) {
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.Base, "/")+path, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("ctl: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.AdminToken)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnreachable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("ctl: read: %w", err)
	}
	switch {
	case resp.StatusCode/100 == 2:
		return body, nil
	case resp.StatusCode == http.StatusUnauthorized:
		return nil, ErrUnauthorized
	case resp.StatusCode == http.StatusNotFound:
		return nil, ErrNotFound
	default:
		return nil, fmt.Errorf("ctl: %s %s: %d %s", method, path, resp.StatusCode, bytes.TrimSpace(body))
	}
}
