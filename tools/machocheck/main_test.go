package main

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// build links an empty program for darwin/goarch the way `make build-all`
// does, so the checker is held to what Go's linker actually writes rather than
// to a fixture written from the same reading of cs_blobs.h. A cold build is
// about two seconds; the build cache makes the next one a link.
func build(t *testing.T, goarch string) []byte {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"go.mod":  "module hello\n\ngo 1.26\n",
		"main.go": "package main\n\nfunc main() {}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(dir, "hello")
	cmd := exec.CommandContext(t.Context(), "go", "build", "-trimpath", "-ldflags=-s -w", "-o", out, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=darwin", "GOARCH="+goarch)
	if msg, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build for darwin/%s: %v\n%s", goarch, err, msg)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// layout finds, in a signed build, the file offsets a mutation needs: the
// LC_CODE_SIGNATURE command itself, the signature, and its CodeDirectory.
type layout struct {
	loadCmd, sigOff, codeDir int
}

func locate(t *testing.T, data []byte) layout {
	t.Helper()
	f, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	var l layout
	off := 32 // a 64-bit Mach-O header
	for _, load := range f.Loads {
		raw := load.Raw()
		if f.ByteOrder.Uint32(raw) == lcCodeSignature {
			l.loadCmd = off
			l.sigOff = int(f.ByteOrder.Uint32(raw[8:]))
		}
		off += len(raw)
	}
	if l.loadCmd == 0 {
		t.Fatal("the build carries no LC_CODE_SIGNATURE to mutate")
	}
	be := binary.BigEndian
	for i := range int(be.Uint32(data[l.sigOff+8:])) {
		entry := data[l.sigOff+12+8*i:]
		if be.Uint32(entry) == slotCodeDirectory {
			l.codeDir = l.sigOff + int(be.Uint32(entry[4:]))
		}
	}
	if l.codeDir == 0 {
		t.Fatal("the build's signature has no CodeDirectory")
	}
	return l
}

func TestVerify(t *testing.T) {
	t.Parallel()
	arm64 := build(t, "arm64")
	amd64 := build(t, "amd64")
	l := locate(t, arm64)
	pages := (l.sigOff + 4095) / 4096

	cases := []struct {
		name   string
		src    []byte
		mutate func(b []byte) []byte
		want   string // in the summary, or in the error when wantErr
		// wantErr is set when the file must be refused.
		wantErr bool
	}{
		{
			name: "Go's own arm64 signature verifies over every page",
			src:  arm64, mutate: func(b []byte) []byte { return b },
			want: "arm64, ad-hoc signature verified over " + strconv.Itoa(pages) + " pages of 4096 bytes",
		},
		{
			name: "an unsigned amd64 build passes, since Intel Macs run it",
			src:  amd64, mutate: func(b []byte) []byte { return b },
			want: "amd64, unsigned",
		},
		{
			name: "a changed byte in the code fails its page",
			src:  arm64, mutate: func(b []byte) []byte { b[4096+7] ^= 0xff; return b },
			want: "page 1 ", wantErr: true,
		},
		{
			name: "a changed byte in the last, partial page fails it",
			src:  arm64, mutate: func(b []byte) []byte { b[l.sigOff-1] ^= 0xff; return b },
			want: "page " + strconv.Itoa(pages-1) + " ", wantErr: true,
		},
		{
			name: "an arm64 build without its signature command is refused",
			src:  arm64, mutate: func(b []byte) []byte { binary.LittleEndian.PutUint32(b[l.loadCmd:], 0); return b },
			want: "arm64 without a code signature", wantErr: true,
		},
		{
			name: "a CodeDirectory that stops short of the signature is refused",
			src:  arm64, mutate: func(b []byte) []byte {
				binary.BigEndian.PutUint32(b[l.codeDir+32:], uint32(l.sigOff-4096))
				return b
			},
			want: "covers", wantErr: true,
		},
		{
			name: "a signature cut short by a truncated download is refused",
			src:  arm64, mutate: func(b []byte) []byte { return b[:len(b)-16] },
			want: "runs past the file", wantErr: true,
		},
		{
			name: "a file that is not a Mach-O is refused",
			src:  []byte("#!/bin/sh\necho not a binary\n"), mutate: func(b []byte) []byte { return b },
			want: "not a thin Mach-O", wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			summary, err := verify(tc.mutate(bytes.Clone(tc.src)))
			switch {
			case tc.wantErr && err == nil:
				t.Fatalf("verified (%q), want an error containing %q", summary, tc.want)
			case tc.wantErr && !strings.Contains(err.Error(), tc.want):
				t.Fatalf("got error %q, want one containing %q", err, tc.want)
			case !tc.wantErr && err != nil:
				t.Fatalf("got error %v, want a summary containing %q", err, tc.want)
			case !tc.wantErr && !strings.Contains(summary, tc.want):
				t.Fatalf("got summary %q, want one containing %q", summary, tc.want)
			}
		})
	}
}

func TestRunChecksEveryFileAndFailsOnAny(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	good := filepath.Join(dir, "clair-darwin-arm64")
	bad := filepath.Join(dir, "clair-darwin-bad")
	if err := os.WriteFile(good, build(t, "arm64"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte("not mach-o"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{bad, good}, &stdout, &stderr); code != 1 {
		t.Fatalf("got exit %d, want 1\nstdout: %s\nstderr: %s", code, &stdout, &stderr)
	}
	if !strings.Contains(stderr.String(), "✗ "+bad+": ") {
		t.Errorf("got stderr %q, want a ✗ line for %s", &stderr, bad)
	}
	if !strings.Contains(stdout.String(), good+": arm64, ad-hoc signature verified") {
		t.Errorf("got stdout %q, want %s verified after the failure", &stdout, good)
	}

	stdout.Reset()
	stderr.Reset()
	if code := run(nil, &stdout, &stderr); code != 2 || stderr.String() != usageText {
		t.Errorf("no arguments: got exit %d, stderr %q; want 2 and the usage", code, &stderr)
	}
}
