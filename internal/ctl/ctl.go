// Package ctl is the daemon's control surface as the CLI sees it: the JSON it
// answers on the loopback listener under /clair/ctl and a client for it.
// `clair status` reads it; `clair pair` asks the daemon to release a pair and
// to reload. It shares the hook listener but not the hook bearer: the admin
// token never leaves the config directory.
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
	PathPairs  = Prefix + "pairs/"
)

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

// ReleasePair asks the daemon to stop a pair and hand its file to the caller.
func (c *Client) ReleasePair(ctx context.Context, pairID string) error {
	_, err := c.call(ctx, http.MethodDelete, PathPairs+url.PathEscape(pairID))
	return err
}

func (c *Client) call(ctx context.Context, method, path string) ([]byte, error) {
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
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
