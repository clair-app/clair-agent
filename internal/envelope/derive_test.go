package envelope

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"strings"
	"testing"
)

// hkdfManual is an independent HKDF-SHA256 (RFC 5869) written against
// crypto/hmac alone, so the tests below can tell whether Derive passes the
// salt and the shared secret to crypto/hkdf in the right order.
func hkdfManual(salt, ikm, info []byte, length int) (prk, okm []byte) {
	extract := hmac.New(sha256.New, salt)
	extract.Write(ikm)
	prk = extract.Sum(nil)
	var block []byte
	for counter := byte(1); len(okm) < length; counter++ {
		expand := hmac.New(sha256.New, prk)
		expand.Write(block)
		expand.Write(info)
		expand.Write([]byte{counter})
		block = expand.Sum(nil)
		okm = append(okm, block...)
	}
	return prk, okm[:length]
}

func TestManualHKDFMatchesRFC5869(t *testing.T) {
	t.Parallel()

	var v struct {
		IKM, Salt, Info, PRK, OKM string
		Length                    int
	}
	loadJSON(t, "testdata/rfc5869-a1.json", &v)
	prk, okm := hkdfManual(unhex(t, v.Salt), unhex(t, v.IKM), unhex(t, v.Info), v.Length)
	if want := unhex(t, v.PRK); !bytes.Equal(prk, want) {
		t.Errorf("PRK = %x, want %x", prk, want)
	}
	if want := unhex(t, v.OKM); !bytes.Equal(okm, want) {
		t.Errorf("OKM = %x, want %x", okm, want)
	}
}

func TestDeriveMatchesTheSchedule(t *testing.T) {
	t.Parallel()

	host, phone := hostAndPhone(t)
	k := pattern(PairingSecretSize, 0x90)
	keys, err := Derive(host, phone.PublicKey().Bytes(), k)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	ss, err := host.ECDH(phone.PublicKey())
	if err != nil {
		t.Fatalf("ECDH: %v", err)
	}
	_, h2p := hkdfManual(k, ss, []byte(infoH2P), KeySize)
	_, p2h := hkdfManual(k, ss, []byte(infoP2H), KeySize)
	_, fp := hkdfManual(k, ss, []byte(infoFP), FingerprintSize)
	if !bytes.Equal(keys.H2P[:], h2p) {
		t.Errorf("k_h2p = %x, want %x", keys.H2P, h2p)
	}
	if !bytes.Equal(keys.P2H[:], p2h) {
		t.Errorf("k_p2h = %x, want %x", keys.P2H, p2h)
	}
	if !bytes.Equal(keys.FP[:], fp) {
		t.Errorf("fp = %x, want %x", keys.FP, fp)
	}
	if keys.H2P == keys.P2H {
		t.Error("k_h2p and k_p2h are equal; the info strings did not separate them")
	}
}

func TestDeriveIsSymmetric(t *testing.T) {
	t.Parallel()

	host, phone := hostAndPhone(t)
	k := pattern(PairingSecretSize, 0x90)
	fromHost, err := Derive(host, phone.PublicKey().Bytes(), k)
	if err != nil {
		t.Fatalf("Derive (host): %v", err)
	}
	fromPhone, err := Derive(phone, host.PublicKey().Bytes(), k)
	if err != nil {
		t.Fatalf("Derive (phone): %v", err)
	}
	if *fromHost != *fromPhone {
		t.Fatalf("host derived %+v, phone derived %+v", fromHost, fromPhone)
	}

	other, err := Derive(host, phone.PublicKey().Bytes(), pattern(PairingSecretSize, 0x91))
	if err != nil {
		t.Fatalf("Derive (other k): %v", err)
	}
	if *other == *fromHost {
		t.Fatal("a different pairing secret derived the same keys")
	}
}

func TestDeriveRejects(t *testing.T) {
	t.Parallel()

	host, phone := hostAndPhone(t)
	good := phone.PublicKey().Bytes()
	tests := []struct {
		name string
		pub  []byte
		k    []byte
		want string
	}{
		{name: "low-order peer key", pub: make([]byte, KeySize), k: pattern(PairingSecretSize, 0), want: "x25519"},
		{name: "short peer key", pub: good[:31], k: pattern(PairingSecretSize, 0), want: "peer public key"},
		{name: "short k", pub: good, k: pattern(PairingSecretSize-1, 0), want: "pairing secret"},
		{name: "empty k", pub: good, k: nil, want: "pairing secret"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Derive(host, tt.pub, tt.k)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Derive: err = %v, want one mentioning %q", err, tt.want)
			}
		})
	}
}

func TestFingerprintFormat(t *testing.T) {
	t.Parallel()

	keys := &Keys{}
	copy(keys.FP[:], pattern(FingerprintSize, 0xA0))
	got := keys.Fingerprint()
	want := "a0a1 a2a3 a4a5 a6a7 a8a9 aaab acad aeaf"
	if got != want {
		t.Fatalf("Fingerprint = %q, want %q", got, want)
	}
}

func TestKeyByDirection(t *testing.T) {
	t.Parallel()

	keys := testKeys(t)
	if !bytes.Equal(keys.Key(DirH2P), keys.H2P[:]) || !bytes.Equal(keys.Key(DirP2H), keys.P2H[:]) {
		t.Fatal("Key(dir) does not select the direction's key")
	}
	if _, err := ecdh.X25519().NewPrivateKey(keys.Key(DirH2P)); err != nil {
		t.Fatalf("traffic key is not %d bytes: %v", KeySize, err)
	}
}
