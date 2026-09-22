package relay

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
)

// authScheme is the Authorization scheme of RELAY.md §7.3.
const authScheme = "Clair-Ed25519"

// Signer signs requests as one Ed25519 identity (RELAY.md §7.3, with the
// canonical string the relay's OpenAPI document pins).
type Signer struct {
	priv ed25519.PrivateKey
	key  string
}

// NewSigner wraps an Ed25519 private key.
func NewSigner(priv ed25519.PrivateKey) *Signer {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		// ed25519.PrivateKey.Public always returns an ed25519.PublicKey.
		panic("relay: ed25519 public key has an unexpected type")
	}
	return &Signer{priv: priv, key: base64.RawURLEncoding.EncodeToString(pub)}
}

// Key is the public key as the header carries it: base64url, no padding.
func (s *Signer) Key() string { return s.key }

// Canonical is the signed string:
//
//	METHOD "\n" request-target "\n" ts "\n" lowercase-hex-sha256(body)
//
// where request-target is the path with the query string exactly as sent and
// ts is unix seconds. An empty body hashes to e3b0c442…b855.
func Canonical(method, requestURI string, ts int64, body []byte) []byte {
	sum := sha256.Sum256(body)
	var b strings.Builder
	b.Grow(len(method) + len(requestURI) + 24 + hex.EncodedLen(len(sum)))
	b.WriteString(method)
	b.WriteByte('\n')
	b.WriteString(requestURI)
	b.WriteByte('\n')
	b.WriteString(strconv.FormatInt(ts, 10))
	b.WriteByte('\n')
	b.WriteString(hex.EncodeToString(sum[:]))
	return []byte(b.String())
}

// Authorization is the header value for one request:
//
//	Clair-Ed25519 key=<b64url pub>, ts=<unix s>, sig=<b64url ed25519(Canonical)>
//
// Ed25519 is deterministic, so the same inputs always give the same header.
func (s *Signer) Authorization(method, requestURI string, ts int64, body []byte) string {
	sig := ed25519.Sign(s.priv, Canonical(method, requestURI, ts, body))
	return authScheme + " key=" + s.key + ", ts=" + strconv.FormatInt(ts, 10) +
		", sig=" + base64.RawURLEncoding.EncodeToString(sig)
}
