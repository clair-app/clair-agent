package envelope

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"testing"
)

// vectorsPath is the golden file from `:shared/relay` in the clair repository
// (RelayVectorsTest, shared/relay/src/test/resources/relay-vectors.json), copied
// unchanged from clair commit d6d2a15.
const vectorsPath = "testdata/relay-vectors.json"

// vectors is the file's schema, proposed to the phone side: every value is
// base64url without padding, and each envelope pins the exact plaintext
// bytes, because Kotlin and Go would serialise the same record differently.
type vectors struct {
	Version int    `json:"version"`
	K       string `json:"k"`
	Host    struct {
		X25519Priv string `json:"x25519Priv"`
		X25519Pub  string `json:"x25519Pub"`
	} `json:"host"`
	Phone struct {
		X25519Priv string `json:"x25519Priv"`
		X25519Pub  string `json:"x25519Pub"`
	} `json:"phone"`
	Derived struct {
		KH2P string `json:"k_h2p"`
		KP2H string `json:"k_p2h"`
		FP   string `json:"fp"`
	} `json:"derived"`
	Envelopes []struct {
		Name        string `json:"name"`
		Pair        string `json:"pair"`
		ID          string `json:"id"`
		Dir         Dir    `json:"dir"`
		Wake        Wake   `json:"wake"`
		TTLSec      int    `json:"ttlSec"`
		Nonce       string `json:"nonce"`
		RecordBytes string `json:"recordBytes"`
		AAD         string `json:"aad"`
		CT          string `json:"ct"`
	} `json:"envelopes"`
}

func openTestdata(path string) (*os.File, error) {
	return os.Open(path)
}

func TestVectors(t *testing.T) {
	t.Parallel()

	f, err := openTestdata(vectorsPath)
	if errors.Is(err, fs.ErrNotExist) {
		t.Skipf("%s is absent: copy shared/relay/src/test/resources/relay-vectors.json from the clair repository", vectorsPath)
	}
	if err != nil {
		t.Fatalf("open %s: %v", vectorsPath, err)
	}
	t.Cleanup(func() { f.Close() })
	var v vectors
	if decodeErr := json.NewDecoder(f).Decode(&v); decodeErr != nil {
		t.Fatalf("decode %s: %v", vectorsPath, decodeErr)
	}
	if v.Version != 1 {
		t.Fatalf("vectors version = %d, want 1", v.Version)
	}
	b64 := func(s string) []byte {
		t.Helper()
		b, decodeErr := base64.RawURLEncoding.Strict().DecodeString(s)
		if decodeErr != nil {
			t.Fatalf("base64url %q: %v", s, decodeErr)
		}
		return b
	}

	host, err := ecdh.X25519().NewPrivateKey(b64(v.Host.X25519Priv))
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	phone, err := ecdh.X25519().NewPrivateKey(b64(v.Phone.X25519Priv))
	if err != nil {
		t.Fatalf("phone key: %v", err)
	}
	for name, key := range map[string]*ecdh.PrivateKey{"host": host, "phone": phone} {
		want := b64(map[string]string{"host": v.Host.X25519Pub, "phone": v.Phone.X25519Pub}[name])
		if got := key.PublicKey().Bytes(); !bytes.Equal(got, want) {
			t.Errorf("%s public key = %x, want %x", name, got, want)
		}
	}
	k := b64(v.K)
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
	if want := b64(v.Derived.KH2P); !bytes.Equal(fromHost.H2P[:], want) {
		t.Errorf("k_h2p = %x, want %x", fromHost.H2P, want)
	}
	if want := b64(v.Derived.KP2H); !bytes.Equal(fromHost.P2H[:], want) {
		t.Errorf("k_p2h = %x, want %x", fromHost.P2H, want)
	}
	if want := b64(v.Derived.FP); !bytes.Equal(fromHost.FP[:], want) {
		t.Errorf("fp = %x, want %x", fromHost.FP, want)
	}

	for _, e := range v.Envelopes {
		t.Run(e.Name, func(t *testing.T) {
			t.Parallel()
			h := Header{Pair: e.Pair, ID: e.ID, Dir: e.Dir, Wake: e.Wake, TTLSec: e.TTLSec}
			if got, want := AAD(h), b64(e.AAD); !bytes.Equal(got, want) {
				t.Errorf("AAD = %x, want %x", got, want)
			}
			record := b64(e.RecordBytes)
			sealed, err := Seal(fromHost.Key(e.Dir), h, record, bytes.NewReader(b64(e.Nonce)))
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			if got, want := b64(sealed.CT), b64(e.CT); !bytes.Equal(got, want) {
				t.Errorf("ct = %x, want %x", got, want)
			}
			opened, err := Open(fromHost.Key(e.Dir), Envelope{V: 1, Pair: e.Pair, ID: e.ID, Dir: e.Dir, Wake: e.Wake, TTLSec: e.TTLSec, CT: e.CT})
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(opened, record) {
				t.Errorf("Open = %x, want %x", opened, record)
			}
		})
	}
}
