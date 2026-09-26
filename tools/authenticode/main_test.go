package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures are signed by jsign 7.5, not by code written from the same
// reading of the specifications as the checker. The file unsigned.exe is a
// 1 KiB PE32+ with one section holding `ret`; the others are copies of it
// signed with a throwaway self-signed "Test Signer" code-signing certificate:
//
//	jsign --keystore test.p12 --storetype PKCS12 --storepass test --alias test --alg SHA-256 \
//	      --tsaurl http://timestamp.acs.microsoft.com --tsmode RFC3161 signed.exe
//	jsign … (no --tsaurl) untimestamped.exe
//	jsign … with a certificate valid 2020-01-01 to 2020-01-04, timestamped now: expired.exe
//
// Nothing here checks a chain or the current time, so they stay valid.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// signatures returns the byte offsets of the file's own signature value and
// its timestamp's, so a test can break one of them.
func signatures(t *testing.T, data []byte) (own, stamp int) {
	t.Helper()
	img, err := parsePE(data)
	if err != nil {
		t.Fatal(err)
	}
	length := int(binary.LittleEndian.Uint32(data[img.certOff:]))
	sd, err := parseSignedData(data[img.certOff+8 : img.certOff+length])
	if err != nil {
		t.Fatal(err)
	}
	si := sd.SignerInfos[0]
	attrs, err := parseAttributes(si.UnsignedAttrs)
	if err != nil {
		t.Fatal(err)
	}
	tsd, err := parseSignedData(attrs[oidRFC3161Stamp.String()])
	if err != nil {
		t.Fatal(err)
	}
	own = bytes.Index(data, si.Signature)
	stamp = bytes.Index(data, tsd.SignerInfos[0].Signature)
	if own < 0 || stamp < 0 {
		t.Fatal("a signature value is not in the file")
	}
	return own, stamp
}

func TestVerify(t *testing.T) {
	t.Parallel()
	signed := fixture(t, "signed.exe")
	own, stamp := signatures(t, signed)
	img, err := parsePE(signed)
	if err != nil {
		t.Fatal(err)
	}
	keep := func(b []byte) []byte { return b }

	cases := []struct {
		name   string
		src    []byte
		signer string
		mutate func(b []byte) []byte
		want   string // in the summary's signer, or in the error when wantErr
		// wantErr is set when the file must be refused.
		wantErr bool
	}{
		{
			name: "jsign's timestamped signature verifies", src: signed, signer: "Test Signer", mutate: keep,
			want: "Test Signer",
		},
		{
			name: "the checksum is outside the digest, as signing rewrites it", src: signed, mutate: func(b []byte) []byte {
				b[img.checksum] ^= 0xff
				return b
			},
			want: "Test Signer",
		},
		{
			name: "a changed byte of code fails the digest", src: signed, mutate: func(b []byte) []byte {
				b[0x200] ^= 0xff
				return b
			},
			want: "not the ones signed", wantErr: true,
		},
		{
			name: "another signer is refused", src: signed, signer: "Jeffrey Mixon", mutate: keep,
			want: `signed by "Test Signer", not "Jeffrey Mixon"`, wantErr: true,
		},
		{
			name: "a broken signature value is refused", src: signed, mutate: func(b []byte) []byte {
				b[own+10] ^= 0xff
				return b
			},
			want: "does not verify", wantErr: true,
		},
		{
			name: "a broken timestamp signature is refused", src: signed, mutate: func(b []byte) []byte {
				b[stamp+10] ^= 0xff
				return b
			},
			want: "timestamp: the signature by", wantErr: true,
		},
		{
			name: "bytes after the certificate table are refused", src: signed, mutate: func(b []byte) []byte {
				return append(b, make([]byte, 8)...)
			},
			want: "is not the end of the", wantErr: true,
		},
		{
			name: "a signature without a timestamp is refused, since the certificate lives three days", src: fixture(t, "untimestamped.exe"),
			mutate: keep, want: "not timestamped", wantErr: true,
		},
		{
			name: "a timestamp outside the certificate's validity is refused", src: fixture(t, "expired.exe"),
			mutate: keep, want: "outside the certificate's 2020-01-01T00:00:00Z to 2020-01-04T00:00:00Z", wantErr: true,
		},
		{
			name: "an unsigned build is refused", src: fixture(t, "unsigned.exe"), mutate: keep,
			want: "not signed", wantErr: true,
		},
		{
			name: "a file that is not a PE is refused", src: []byte("#!/bin/sh\necho not a binary\n"), mutate: keep,
			want: "not a PE file", wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sig, err := verify(tc.mutate(bytes.Clone(tc.src)), tc.signer)
			switch {
			case tc.wantErr && err == nil:
				t.Fatalf("verified (signer %q), want an error containing %q", sig.signer, tc.want)
			case tc.wantErr && !strings.Contains(err.Error(), tc.want):
				t.Fatalf("got error %q, want one containing %q", err, tc.want)
			case !tc.wantErr && err != nil:
				t.Fatalf("got error %v, want a signature by %q", err, tc.want)
			case !tc.wantErr && sig.signer != tc.want:
				t.Fatalf("got signer %q, want %q", sig.signer, tc.want)
			case !tc.wantErr && (sig.stamper == "" || sig.at.IsZero()):
				t.Fatalf("got timestamp %q at %v, want both", sig.stamper, sig.at)
			}
		})
	}
}

// A signed file and the build it was made from have one digest: what makes a
// signed release comparable with a local `make dist`.
func TestDigestIsTheSameSignedAndUnsigned(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	unsigned, signed := filepath.Join("testdata", "unsigned.exe"), filepath.Join("testdata", "signed.exe")
	if code := run([]string{"digest", unsigned, signed}, &stdout, &stderr); code != 0 {
		t.Fatalf("got exit %d, stderr %q", code, &stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %q, want a line per file", &stdout)
	}
	a, _, _ := strings.Cut(lines[0], "  ")
	b, _, _ := strings.Cut(lines[1], "  ")
	if a != b || len(a) != 64 {
		t.Errorf("got digests %s and %s, want one SHA-256", a, b)
	}
}

func TestCheckAgainstTheUnsignedBuild(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	signed := filepath.Join(dir, "clair.exe")
	if err := os.WriteFile(signed, fixture(t, "signed.exe"), 0o644); err != nil {
		t.Fatal(err)
	}
	build := func(t *testing.T, data []byte) string {
		t.Helper()
		d := t.TempDir()
		if err := os.WriteFile(filepath.Join(d, "clair.exe"), data, 0o644); err != nil {
			t.Fatal(err)
		}
		return d
	}
	other := fixture(t, "unsigned.exe")
	other[0x201] = 0x90

	cases := []struct {
		name, unsigned, want string
		code                 int
	}{
		{"the build it was signed from matches", build(t, fixture(t, "unsigned.exe")), "over the build ", 0},
		{"another build does not", build(t, other), "covers other bytes than", 1},
		{"a signed build is not the build before signing", build(t, fixture(t, "signed.exe")), "is signed; -unsigned names", 1},
		{"a missing build fails", t.TempDir(), "the unsigned build: ", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			code := run([]string{"check", "-signer", "Test Signer", "-unsigned", tc.unsigned, signed}, &stdout, &stderr)
			if code != tc.code || !strings.Contains(stdout.String()+stderr.String(), tc.want) {
				t.Fatalf("got exit %d\nstdout: %s\nstderr: %s\nwant exit %d and %q", code, &stdout, &stderr, tc.code, tc.want)
			}
		})
	}
}

func TestRunChecksEveryFileAndFailsOnAny(t *testing.T) {
	t.Parallel()
	bad, good := filepath.Join("testdata", "untimestamped.exe"), filepath.Join("testdata", "signed.exe")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"check", bad, good}, &stdout, &stderr); code != 1 {
		t.Fatalf("got exit %d, want 1\nstdout: %s\nstderr: %s", code, &stdout, &stderr)
	}
	if !strings.Contains(stderr.String(), "✗ "+bad+": ") {
		t.Errorf("got stderr %q, want a ✗ line for %s", &stderr, bad)
	}
	if !strings.Contains(stdout.String(), good+`: signed by "Test Signer", timestamped `) {
		t.Errorf("got stdout %q, want %s verified after the failure", &stdout, good)
	}

	for _, args := range [][]string{nil, {"check"}, {"digest"}, {"sign", good}} {
		stdout.Reset()
		stderr.Reset()
		if code := run(args, &stdout, &stderr); code != 2 || !strings.HasSuffix(stderr.String(), usageText) {
			t.Errorf("%q: got exit %d, stderr %q; want 2 and the usage", args, code, &stderr)
		}
	}
}

// The linker's own output, for both architectures the release signs, parses
// and has a digest; unsigned, it is refused by check.
func TestGoBuilds(t *testing.T) {
	t.Parallel()
	for _, goarch := range []string{"amd64", "arm64"} {
		t.Run(goarch, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			for name, body := range map[string]string{
				"go.mod":  "module hello\n\ngo 1.26\n",
				"main.go": "package main\n\nfunc main() {}\n",
			} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			out := filepath.Join(dir, "hello.exe")
			cmd := exec.CommandContext(t.Context(), "go", "build", "-trimpath", "-ldflags=-s -w", "-o", out, ".")
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=windows", "GOARCH="+goarch)
			if msg, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("go build for windows/%s: %v\n%s", goarch, err, msg)
			}
			var stdout, stderr bytes.Buffer
			if code := run([]string{"digest", out}, &stdout, &stderr); code != 0 {
				t.Fatalf("digest: got exit %d, stderr %q", code, &stderr)
			}
			stdout.Reset()
			if code := run([]string{"check", out}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), ": not signed") {
				t.Fatalf("check: got exit %d, stderr %q; want 1 and not signed", code, &stderr)
			}
		})
	}
}
