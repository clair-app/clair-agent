package relay

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// authScheme is the Authorization scheme of RELAY.md §7.3.
const authScheme = "Clair-Ed25519"

// canonicalLabel opens the v2 canonical string; with the line count it keeps
// a signature of one form from ever verifying as the other (relay ADR
// 2026-09.9vsq).
const canonicalLabel = "clair-v2"

// NonceSize is the bytes of randomness in a request nonce. The relay accepts
// 16 to 32 and spends each once per key.
const NonceSize = 16

// Signer signs requests as one Ed25519 identity (RELAY.md §7.3, with the
// canonical v2 string the relay's OpenAPI document pins; ADR 2026-09.n68c).
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

// NewNonce reads NonceSize bytes from r and encodes them as the header
// carries them: base64url, no padding, 22 characters. Every request, retries
// included, takes a fresh one.
func NewNonce(r io.Reader) (string, error) {
	var b [NonceSize]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", fmt.Errorf("relay: read nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// Canonical is the signed string, one field per line:
//
//	"clair-v2" \n METHOD \n host \n request-target \n ts \n nonce \n lowercase-hex-sha256(body)
//
// where host is the Host header as sent, lower-cased, with its port only if
// one is sent; request-target is the path with the query string exactly as
// sent; and ts is unix seconds. An empty body hashes to e3b0c442…b855.
func Canonical(method, host, requestURI string, ts int64, nonce string, body []byte) []byte {
	sum := sha256.Sum256(body)
	return []byte(strings.Join([]string{
		canonicalLabel,
		strings.ToUpper(method),
		strings.ToLower(host),
		requestURI,
		strconv.FormatInt(ts, 10),
		nonce,
		hex.EncodeToString(sum[:]),
	}, "\n"))
}

// Authorization is the header value for one request:
//
//	Clair-Ed25519 key=<b64url pub>, ts=<unix s>, nonce=<b64url>, sig=<b64url ed25519(Canonical)>
//
// Ed25519 is deterministic, so the same inputs always give the same header;
// the nonce is what makes each request's header unique.
func (s *Signer) Authorization(method, host, requestURI string, ts int64, nonce string, body []byte) string {
	sig := ed25519.Sign(s.priv, Canonical(method, host, requestURI, ts, nonce, body))
	return authScheme + " key=" + s.key + ", ts=" + strconv.FormatInt(ts, 10) +
		", nonce=" + nonce + ", sig=" + base64.RawURLEncoding.EncodeToString(sig)
}
