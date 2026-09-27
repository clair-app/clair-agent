// Package record is the plaintext inside an envelope (RELAY.md §4.1): the
// tunnelled request, the phone's response, and the control records the two
// ends exchange. The hook body travels as raw JSON, never re-encoded, and the
// only fields of it anyone here reads are the two in [Hook] — see the
// blind-tunnel rule in .agents/rules/go.md and ADR 2026-09.34qh.
package record

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"claircode.app/clair-agent/internal/envelope"
)

// The loopback surface the agent tunnels (RELAY.md §4; the phone's
// BridgePaths). Marker is how installers recognise hook entries they wrote.
const (
	PathPrefix     = "/clair/v1"
	Marker         = PathPrefix + "/"
	PathEvent      = PathPrefix + "/hook/event"
	PathDecide     = PathPrefix + "/hook/decide"
	PathStatusline = PathPrefix + "/statusline"
	PathPing       = PathPrefix + "/ping"
	PathStatus     = PathPrefix + "/status"
	// PathPresence is a request the agent itself sends while it holds a
	// decide: the host's terminal-input idle time changed (§4.3). Its body
	// is `{"idleMs": <int>}`.
	PathPresence = PathPrefix + "/hook/presence"
	// TimeoutQuery is the decide endpoint's query parameter, in seconds.
	TimeoutQuery = "timeout"
	// HostHeader names the machine a hook came from; it is the one request
	// header the loopback forwards.
	HostHeader = "X-Clair-Host"
	// IdleHeader is stamped by the agent on every request record it sends
	// when the host has a presence signal: milliseconds since a terminal of
	// this user's last read input (§4.3).
	IdleHeader = "X-Clair-Idle-Ms"
)

// Hook is what the loopback server learned from a hook body's top level, and
// all the agent ever learns of one: the event name, for the wake hint (§7.5),
// and the permission mode, for the release rule (§4.3).
type Hook struct {
	Event string
	// Mode is `permission_mode`; ModeBubble marks a background subagent's
	// prompt, which Claude Code shows in the terminal only once the hook
	// returns without a decision.
	Mode string
}

// ModeBubble is the permission mode of a bubbled prompt (an internal value
// of Claude Code, observed on 2.1.278; NOTES.md in the phone repository).
const ModeBubble = "bubble"

// Why the agent cancels a held decide (the cancel record's `reason`).
const (
	// CancelClient: Claude Code closed the hook's socket.
	CancelClient = "client"
	// CancelTerminal: the prompt was handed to the terminal because someone
	// is at it (§4.3).
	CancelTerminal = "terminal"
	// CancelStop: the agent is stopping; `reset` follows on the next start.
	CancelStop = "stop"
	// CancelTimeout: the decide's timeout ran out before anyone answered;
	// the prompt is still open in the terminal.
	CancelTimeout = "timeout"
)

// Kind discriminates the three record shapes.
type Kind string

// The record kinds.
const (
	KindRequest  Kind = "request"
	KindResponse Kind = "response"
	KindControl  Kind = "control"
)

// Control names a control record (§4.1, plus `cancel` from the RELAY.md
// revision this agent proposes).
type Control string

// The control records.
const (
	// ControlHello is the phone's first record, sent inside the pairing
	// completion: its display name and, optionally, the hooks snippet (§6, §6.5).
	ControlHello Control = "hello"
	// ControlHelloAck is the agent's reply: hostname and agent version (§6).
	ControlHelloAck Control = "hello-ack"
	// ControlSnippet carries a fresh hooks block from the phone (§6.5).
	ControlSnippet Control = "snippet"
	// ControlReset says the agent restarted and every decide it held is gone (§4.1).
	ControlReset Control = "reset"
	// ControlRevoke ends the pair from the sender's side (§6.6).
	ControlRevoke Control = "revoke"
	// ControlCancel closes a held decide on the phone: Claude Code
	// abandoned it, the terminal took it, or the agent is stopping (§4.1).
	ControlCancel Control = "cancel"
	// ControlPolicy carries the phone's settings for the host (§4.3).
	ControlPolicy Control = "policy"
)

// Presence is the phone's presence policy, inside `hello` and `policy`.
type Presence struct {
	// IdleThresholdSec is the terminal idle time under which someone counts
	// as present; nil leaves the agent's default, 0 switches the release
	// rule off.
	IdleThresholdSec *int `json:"idleThresholdSec,omitempty"`
}

// ControlWake is the wake hint stamped on every control record the agent
// sends: none of them is a prompt, none is churn.
const ControlWake = envelope.WakeSoon

// Errors a caller can test with errors.Is.
var (
	// ErrInvalid is a record that fails [Record.Validate].
	ErrInvalid = errors.New("record: invalid")
	// ErrNotObject is a hook body that is not a JSON object.
	ErrNotObject = errors.New("record: hook body is not a JSON object")
	// ErrNoEventName is a hook body without a string `hook_event_name`.
	ErrNoEventName = errors.New("record: hook body has no hook_event_name")
)

// UnknownControlError is a control record this agent does not know. It is not
// fatal: a newer phone may send one, and the receiver drops it.
type UnknownControlError struct {
	Control Control
}

func (e *UnknownControlError) Error() string {
	return fmt.Sprintf("record: unknown control %q", string(e.Control))
}

// Is makes an UnknownControlError match ErrInvalid too.
func (*UnknownControlError) Is(target error) bool { return target == ErrInvalid }

// Record is one plaintext record, discriminated by Kind. Fields the kind does
// not use stay empty and are omitted from the JSON, so each kind's wire form
// is minimal and the field order is fixed by this declaration.
type Record struct {
	// N is the per-direction replay counter (§5.4).
	N uint64 `json:"n"`
	// Kind is the record shape.
	Kind Kind `json:"kind"`
	// ReqID correlates a response, or a cancel, with its request.
	ReqID string `json:"reqId,omitempty"`
	// Path is the loopback path of a request (`/clair/v1/…`).
	Path string `json:"path,omitempty"`
	// Query holds the request's query parameters, first value per key.
	Query map[string]string `json:"query,omitempty"`
	// Headers holds the forwarded request headers: only HostHeader, when set.
	Headers map[string]string `json:"headers,omitempty"`
	// Status is a response's HTTP status (200 with a body, or 204).
	Status int `json:"status,omitempty"`
	// Control names a control record.
	Control Control `json:"control,omitempty"`
	// Reason says why a decide was cancelled (cancel): one of the Cancel*
	// constants; absent means CancelClient.
	Reason string `json:"reason,omitempty"`
	// Body is the hook JSON of a request, or the hook output of a response,
	// verbatim.
	Body json.RawMessage `json:"body,omitempty"`
	// Name is the phone's display name (hello).
	Name string `json:"name,omitempty"`
	// Snippet is a hooks block with `__PORT__`, `__TOKEN__` and
	// `__CLAIR_HOST__` placeholders (hello, snippet).
	Snippet json.RawMessage `json:"snippet,omitempty"`
	// Hostname is the host's name (hello-ack).
	Hostname string `json:"hostname,omitempty"`
	// AgentVersion is the agent's version (hello-ack).
	AgentVersion string `json:"agentVersion,omitempty"`
	// Presence is the phone's presence policy (hello, policy).
	Presence *Presence `json:"presence,omitempty"`
}

// Marshal encodes r without HTML escaping, so the bytes of Body survive:
// encoding/json compacts a RawMessage on the way out and would otherwise turn
// `>` and `&` in a hook body into > and &.
func Marshal(r *Record) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return nil, fmt.Errorf("record: encode: %w", err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// Unmarshal decodes a record, ignoring fields it does not know, and validates it.
func Unmarshal(data []byte) (*Record, error) {
	var r Record
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

// Validate checks the fields a kind requires. An unknown control record fails
// with an *UnknownControlError, which the receiver treats as "drop", not "stop".
func (r *Record) Validate() error {
	if r.N == 0 {
		return fmt.Errorf("%w: n must be positive", ErrInvalid)
	}
	switch r.Kind {
	case KindRequest:
		if r.ReqID == "" {
			return fmt.Errorf("%w: request without reqId", ErrInvalid)
		}
		if !strings.HasPrefix(r.Path, Marker) {
			return fmt.Errorf("%w: request path %q is outside %s", ErrInvalid, r.Path, PathPrefix)
		}
		if r.Status != 0 || r.Control != "" {
			return fmt.Errorf("%w: request carries response or control fields", ErrInvalid)
		}
	case KindResponse:
		if r.ReqID == "" {
			return fmt.Errorf("%w: response without reqId", ErrInvalid)
		}
		if r.Status < 100 || r.Status > 599 {
			return fmt.Errorf("%w: response status %d", ErrInvalid, r.Status)
		}
		if r.Path != "" || r.Control != "" {
			return fmt.Errorf("%w: response carries request or control fields", ErrInvalid)
		}
	case KindControl:
		switch r.Control {
		case ControlHello, ControlHelloAck, ControlSnippet, ControlReset, ControlRevoke, ControlPolicy:
		case ControlCancel:
			if r.ReqID == "" {
				return fmt.Errorf("%w: cancel without reqId", ErrInvalid)
			}
		default:
			return &UnknownControlError{Control: r.Control}
		}
	default:
		return fmt.Errorf("%w: unknown kind %q", ErrInvalid, r.Kind)
	}
	return nil
}

// HookEventName returns the `hook_event_name` of a hook body. It decodes
// nothing else: it walks the top-level keys and skips every other value
// without interpreting it, so a `hook_event_name` nested inside `tool_input`
// never counts. The first occurrence wins.
func HookEventName(body []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrNotObject, err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return "", ErrNotObject
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return "", fmt.Errorf("%w: %w", ErrNotObject, err)
		}
		key, ok := tok.(string)
		if !ok {
			return "", ErrNotObject
		}
		if key != "hook_event_name" {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return "", fmt.Errorf("%w: %w", ErrNotObject, err)
			}
			continue
		}
		var name string
		if err := dec.Decode(&name); err != nil {
			return "", fmt.Errorf("%w: %w", ErrNoEventName, err)
		}
		if name == "" {
			return "", ErrNoEventName
		}
		return name, nil
	}
	return "", ErrNoEventName
}
