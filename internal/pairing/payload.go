// Package pairing is `clair pair` and `clair unpair` (RELAY.md §6): the host
// mints a pairing at the relay, shows a QR the phone scans, waits for the
// phone's hello, proves the phone scanned this code by decrypting it, and
// writes the pair and the hooks. The relay never sees the QR's secret.
package pairing

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"claircode.app/clair-agent/internal/envelope"
)

// The QR payload (RELAY.md §6.1, binary layout pinned here):
//
//	0x01 ‖ pairingId[16] ‖ hostPub[32] ‖ k[16] ‖ relay host (UTF-8, the rest, optional)
//
// carried as `https://<relay>/p#<base64url, no padding>`. The relay field is
// omitted when the relay is the URL's origin — always, today — which keeps
// the payload at 65 bytes and the QR at version 6 (41 modules).
const (
	payloadVersion = 1
	pairingIDSize  = 16
	payloadMinSize = 1 + pairingIDSize + envelope.KeySize + envelope.PairingSecretSize
	// PathPage is the relay's install page; the payload rides its fragment.
	PathPage = "/p"
)

// ErrPayload is a payload that does not parse.
var ErrPayload = errors.New("pairing: malformed payload")

// Payload is what the QR carries.
type Payload struct {
	V         byte
	PairingID [pairingIDSize]byte
	HostPub   [envelope.KeySize]byte
	K         [envelope.PairingSecretSize]byte
	// Relay is the relay's host[:port] when it differs from the URL's origin.
	Relay string
}

// MarshalBinary encodes the payload.
func (p Payload) MarshalBinary() ([]byte, error) {
	if p.V != payloadVersion {
		return nil, fmt.Errorf("%w: version %d", ErrPayload, p.V)
	}
	out := make([]byte, 0, payloadMinSize+len(p.Relay))
	out = append(out, p.V)
	out = append(out, p.PairingID[:]...)
	out = append(out, p.HostPub[:]...)
	out = append(out, p.K[:]...)
	return append(out, p.Relay...), nil
}

// ParsePayload decodes a payload.
func ParsePayload(b []byte) (Payload, error) {
	if len(b) < payloadMinSize {
		return Payload{}, fmt.Errorf("%w: %d bytes, want at least %d", ErrPayload, len(b), payloadMinSize)
	}
	if b[0] != payloadVersion {
		return Payload{}, fmt.Errorf("%w: version %d", ErrPayload, b[0])
	}
	var p Payload
	p.V = b[0]
	rest := b[1:]
	rest = rest[copy(p.PairingID[:], rest):]
	rest = rest[copy(p.HostPub[:], rest):]
	rest = rest[copy(p.K[:], rest):]
	p.Relay = string(rest)
	return p, nil
}

// PairingIDString is the pairing id as the relay names it: base64url, no padding.
func (p Payload) PairingIDString() string {
	return base64.RawURLEncoding.EncodeToString(p.PairingID[:])
}

// PayloadURL is the QR text: the relay's install page with the payload in
// the fragment, so it never reaches a web server (§6.1).
func PayloadURL(origin string, p Payload) (string, error) {
	data, err := p.MarshalBinary()
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(origin, "/") + PathPage + "#" + base64.RawURLEncoding.EncodeToString(data), nil
}

// ParseURL reads a QR text back: the relay's base URL (the payload's relay
// field when set, else the URL's origin) and the payload. The phone and
// tools/phonesim use it.
func ParseURL(raw string) (relayURL string, p Payload, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", Payload{}, fmt.Errorf("%w: %w", ErrPayload, err)
	}
	if u.Fragment == "" || u.Path != PathPage {
		return "", Payload{}, fmt.Errorf("%w: not a %s link with a fragment", ErrPayload, PathPage)
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(u.Fragment)
	if err != nil {
		return "", Payload{}, fmt.Errorf("%w: fragment: %w", ErrPayload, err)
	}
	p, err = ParsePayload(data)
	if err != nil {
		return "", Payload{}, err
	}
	relayURL = u.Scheme + "://" + u.Host
	if p.Relay != "" {
		relayURL = "https://" + p.Relay
	}
	return relayURL, p, nil
}

// pairingIDBytes decodes a relay-minted pairing id into the payload's field.
func pairingIDBytes(id string) ([pairingIDSize]byte, error) {
	var out [pairingIDSize]byte
	raw, err := base64.RawURLEncoding.Strict().DecodeString(id)
	if err != nil || len(raw) != pairingIDSize {
		return out, fmt.Errorf("pairing: the relay minted a pairing id that is not %d bytes of base64url: %q", pairingIDSize, id)
	}
	copy(out[:], raw)
	return out, nil
}
