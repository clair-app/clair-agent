package envelope

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// Fixed material for every test in this package: the phone and the host each
// hold an X25519 key built from a constant scalar, and they share `k`.
const (
	testPair = "AAAAAAAAAAAAAAAAAAAAAA" // 22 characters, like a relay-minted pair id
	testID   = "01ARYZ6S41TSV4RRFFQ69G5FAV"
)

func pattern(n int, first byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = first + byte(i)
	}
	return b
}

// zeroNonce is a nonce source of NUL bytes: deterministic, and obviously not
// something production ever uses.
func zeroNonce() io.Reader { return bytes.NewReader(make([]byte, NonceSize)) }

func hostAndPhone(t *testing.T) (host, phone *ecdh.PrivateKey) {
	t.Helper()
	var err error
	if host, err = ecdh.X25519().NewPrivateKey(pattern(KeySize, 0x10)); err != nil {
		t.Fatalf("host key: %v", err)
	}
	if phone, err = ecdh.X25519().NewPrivateKey(pattern(KeySize, 0x50)); err != nil {
		t.Fatalf("phone key: %v", err)
	}
	return host, phone
}

func testKeys(t *testing.T) *Keys {
	t.Helper()
	host, phone := hostAndPhone(t)
	keys, err := Derive(host, phone.PublicKey().Bytes(), pattern(PairingSecretSize, 0x90))
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	return keys
}

func header() Header {
	return Header{Pair: testPair, ID: testID, Dir: DirH2P, Wake: WakeNow, TTLSec: 86400}
}

func TestAADLayout(t *testing.T) {
	t.Parallel()

	got := AAD(Header{Pair: "p", ID: "i", Dir: DirP2H, Wake: WakeSoon, TTLSec: 7})
	want := []byte("clair-relay/1\x00p\x00i\x00p2h\x00soon")
	if !bytes.Equal(got, want) {
		t.Fatalf("AAD = %x, want %x", got, want)
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	t.Parallel()

	keys := testKeys(t)
	sizes := map[string]int{"empty": 0, "one byte": 1, "max": MaxRecordBytes}
	for _, dir := range []Dir{DirH2P, DirP2H} {
		for _, wake := range []Wake{WakeNow, WakeSoon, WakeNo} {
			for name, size := range sizes {
				t.Run(string(dir)+"/"+string(wake)+"/"+name, func(t *testing.T) {
					t.Parallel()
					record := pattern(size, 0)
					h := header()
					h.Dir, h.Wake = dir, wake
					env, err := Seal(keys.Key(dir), h, record, zeroNonce())
					if err != nil {
						t.Fatalf("Seal: %v", err)
					}
					if env.Header() != h || env.V != Version {
						t.Errorf("sealed header = %+v (v=%d), want %+v (v=%d)", env.Header(), env.V, h, Version)
					}
					got, err := Open(keys.Key(dir), env)
					if err != nil {
						t.Fatalf("Open: %v", err)
					}
					if !bytes.Equal(got, record) {
						t.Errorf("Open returned %d bytes that differ from the %d sealed", len(got), len(record))
					}
				})
			}
		}
	}
}

func TestSealRejectsOversizeRecord(t *testing.T) {
	t.Parallel()

	_, err := Seal(testKeys(t).Key(DirH2P), header(), make([]byte, MaxRecordBytes+1), zeroNonce())
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Seal(%d bytes): err = %v, want ErrTooLarge", MaxRecordBytes+1, err)
	}
}

func TestSealedMaxRecordFitsTheRelayCap(t *testing.T) {
	t.Parallel()

	h := header()
	h.Wake = WakeSoon // the longest hint
	env, err := Seal(testKeys(t).Key(DirH2P), h, make([]byte, MaxRecordBytes), zeroNonce())
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if len(data) > MaxEnvelopeJSON {
		t.Fatalf("envelope JSON is %d bytes for a %d-byte record, want ≤ %d", len(data), MaxRecordBytes, MaxEnvelopeJSON)
	}
	if slack := MaxEnvelopeJSON - len(data); slack > 16 {
		t.Errorf("envelope JSON leaves %d bytes of slack under the cap; MaxRecordBytes is too conservative", slack)
	}
}

func TestSealLayoutIsNonceThenCiphertext(t *testing.T) {
	t.Parallel()

	keys := testKeys(t)
	nonce := pattern(NonceSize, 0xA0)
	record := []byte(`{"n":1}`)
	env, err := Seal(keys.Key(DirH2P), header(), record, bytes.NewReader(nonce))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	ct, err := base64.RawURLEncoding.Strict().DecodeString(env.CT)
	if err != nil {
		t.Fatalf("ct is not strict unpadded base64url: %v", err)
	}
	aead, err := chacha20poly1305.NewX(keys.Key(DirH2P))
	if err != nil {
		t.Fatalf("NewX: %v", err)
	}
	want := append(append([]byte{}, nonce...), aead.Seal(nil, nonce, record, AAD(header()))...)
	if !bytes.Equal(ct, want) {
		t.Fatalf("ct = %x, want nonce ‖ aead = %x", ct, want)
	}
	again, err := Seal(keys.Key(DirH2P), header(), record, bytes.NewReader(nonce))
	if err != nil {
		t.Fatalf("Seal again: %v", err)
	}
	if again != env {
		t.Errorf("Seal with the same nonce is not deterministic: %+v vs %+v", again, env)
	}
}

func TestAEADIsXChaCha20Poly1305(t *testing.T) {
	t.Parallel()

	var v struct {
		Plaintext, AAD, Key, Nonce, Ciphertext, Tag string
	}
	loadJSON(t, "testdata/xchacha20poly1305-a3.json", &v)
	aead, err := chacha20poly1305.NewX(unhex(t, v.Key))
	if err != nil {
		t.Fatalf("NewX: %v", err)
	}
	got := aead.Seal(nil, unhex(t, v.Nonce), unhex(t, v.Plaintext), unhex(t, v.AAD))
	want := append(unhex(t, v.Ciphertext), unhex(t, v.Tag)...)
	if !bytes.Equal(got, want) {
		t.Fatalf("Seal = %x, want %x", got, want)
	}
}

func TestSealRejectsBadHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Header)
	}{
		{name: "empty pair", mutate: func(h *Header) { h.Pair = "" }},
		{name: "NUL in pair", mutate: func(h *Header) { h.Pair = "a\x00b" }},
		{name: "short id", mutate: func(h *Header) { h.ID = testID[:25] }},
		{name: "lowercase id", mutate: func(h *Header) { h.ID = strings.ToLower(testID) }},
		{name: "unknown dir", mutate: func(h *Header) { h.Dir = "h2h" }},
		{name: "unknown wake", mutate: func(h *Header) { h.Wake = "later" }},
		{name: "zero ttl", mutate: func(h *Header) { h.TTLSec = 0 }},
		{name: "negative ttl", mutate: func(h *Header) { h.TTLSec = -1 }},
	}
	keys := testKeys(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := header()
			tt.mutate(&h)
			_, err := Seal(keys.Key(DirH2P), h, []byte("x"), zeroNonce())
			if !errors.Is(err, ErrHeader) {
				t.Fatalf("Seal: err = %v, want ErrHeader", err)
			}
		})
	}
}

func TestOpenRejects(t *testing.T) {
	t.Parallel()

	keys := testKeys(t)
	sealed, err := Seal(keys.Key(DirH2P), header(), []byte(`{"n":1}`), zeroNonce())
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	flipped := func(env Envelope, at int) Envelope {
		ct, err := base64.RawURLEncoding.DecodeString(env.CT)
		if err != nil {
			t.Fatalf("decode ct: %v", err)
		}
		ct[at] ^= 1
		env.CT = base64.RawURLEncoding.EncodeToString(ct)
		return env
	}
	tests := []struct {
		name string
		key  []byte
		env  func() Envelope
		want error
	}{
		{name: "tampered nonce", key: keys.Key(DirH2P), env: func() Envelope { return flipped(sealed, 0) }, want: ErrAuth},
		{name: "tampered ciphertext", key: keys.Key(DirH2P), env: func() Envelope { return flipped(sealed, NonceSize) }, want: ErrAuth},
		{name: "tampered tag", key: keys.Key(DirH2P), env: func() Envelope { return flipped(sealed, len(sealed.CT)*3/4-1) }, want: ErrAuth},
		{name: "relabelled pair", key: keys.Key(DirH2P), env: func() Envelope { e := sealed; e.Pair = "BBBBBBBBBBBBBBBBBBBBBB"; return e }, want: ErrAuth},
		{name: "relabelled id", key: keys.Key(DirH2P), env: func() Envelope { e := sealed; e.ID = "01ARYZ6S41TSV4RRFFQ69G5FAW"; return e }, want: ErrAuth},
		{name: "relabelled dir", key: keys.Key(DirH2P), env: func() Envelope { e := sealed; e.Dir = DirP2H; return e }, want: ErrAuth},
		{name: "downgraded wake", key: keys.Key(DirH2P), env: func() Envelope { e := sealed; e.Wake = WakeNo; return e }, want: ErrAuth},
		{name: "clamped ttl still opens", key: keys.Key(DirH2P), env: func() Envelope { e := sealed; e.TTLSec = 60; return e }, want: nil},
		{name: "wrong key", key: pattern(KeySize, 0xF0), env: func() Envelope { return sealed }, want: ErrAuth},
		{name: "other direction's key", key: keys.Key(DirP2H), env: func() Envelope { return sealed }, want: ErrAuth},
		{name: "short ct", key: keys.Key(DirH2P), env: func() Envelope { e := sealed; e.CT = e.CT[:20]; return e }, want: ErrMalformed},
		{name: "padded base64", key: keys.Key(DirH2P), env: func() Envelope { e := sealed; e.CT += "="; return e }, want: ErrMalformed},
		{name: "standard base64", key: keys.Key(DirH2P), env: func() Envelope { e := sealed; e.CT = "+" + e.CT[1:]; return e }, want: ErrMalformed},
		{name: "future version", key: keys.Key(DirH2P), env: func() Envelope { e := sealed; e.V = 2; return e }, want: ErrVersion},
		{name: "bad id shape", key: keys.Key(DirH2P), env: func() Envelope { e := sealed; e.ID = "nope"; return e }, want: ErrHeader},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Open(tt.key, tt.env())
			if !errors.Is(err, tt.want) {
				t.Fatalf("Open: err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestEnvelopeJSONOrder(t *testing.T) {
	t.Parallel()

	env := Envelope{V: 1, Pair: "p", ID: testID, Dir: DirH2P, Wake: WakeNow, TTLSec: 86400, CT: "AAAA"}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"v":1,"pair":"p","id":"` + testID + `","dir":"h2p","wake":"now","ttlSec":86400,"ct":"AAAA"}`
	if string(data) != want {
		t.Fatalf("Marshal = %s, want %s", data, want)
	}
	var back Envelope
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back != env {
		t.Fatalf("round trip = %+v, want %+v", back, env)
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	sealed, err := Seal(testKeys(t).Key(DirH2P), header(), []byte("x"), zeroNonce())
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	tests := []struct {
		name string
		env  func() Envelope
		pair string
		dir  Dir
		want error
	}{
		{name: "as sealed", env: func() Envelope { return sealed }, pair: testPair, dir: DirH2P, want: nil},
		{name: "other pair", env: func() Envelope { return sealed }, pair: "other", dir: DirH2P, want: ErrHeader},
		{name: "other dir", env: func() Envelope { return sealed }, pair: testPair, dir: DirP2H, want: ErrHeader},
		{name: "version", env: func() Envelope { e := sealed; e.V = 0; return e }, pair: testPair, dir: DirH2P, want: ErrVersion},
		{name: "wake", env: func() Envelope { e := sealed; e.Wake = ""; return e }, pair: testPair, dir: DirH2P, want: ErrHeader},
		{name: "ttl", env: func() Envelope { e := sealed; e.TTLSec = 0; return e }, pair: testPair, dir: DirH2P, want: ErrHeader},
		{name: "ct", env: func() Envelope { e := sealed; e.CT = "AA"; return e }, pair: testPair, dir: DirH2P, want: ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.env().Validate(tt.pair, tt.dir)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Validate: err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestDirAndWake(t *testing.T) {
	t.Parallel()

	if !DirH2P.Valid() || !DirP2H.Valid() || Dir("up").Valid() {
		t.Error("Dir.Valid: want h2p and p2h only")
	}
	if DirH2P.Opposite() != DirP2H || DirP2H.Opposite() != DirH2P {
		t.Error("Dir.Opposite: want h2p ↔ p2h")
	}
	if !WakeNow.Valid() || !WakeSoon.Valid() || !WakeNo.Valid() || Wake("").Valid() || Wake("NOW").Valid() {
		t.Error("Wake.Valid: want now, soon and no only")
	}
}

func loadJSON(t *testing.T, path string, v any) {
	t.Helper()
	f, err := openTestdata(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(v); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}
