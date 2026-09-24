// Command machocheck verifies the ad-hoc code signature on a darwin build the
// way the kernel will.
//
//	go run ./tools/machocheck dist/clair-darwin-amd64 dist/clair-darwin-arm64
//
// Why. Apple silicon kills an arm64 binary at exec when it carries no code
// signature, or one whose page hashes do not match its bytes: the process
// dies with SIGKILL before main, and `curl … | sh` leaves the user a binary
// that cannot start. Go's linker signs darwin/arm64 builds itself, ad hoc,
// even when cross-compiling, so a Linux CI image can ship them. Nobody runs
// these builds on a Mac before a release, so `make build-all` runs this on
// every darwin output instead: a toolchain change, a post-link step that
// rewrites the file, or a switch to a linker that does not sign fails here.
//
// What is checked. An arm64 file must carry an LC_CODE_SIGNATURE whose
// CodeDirectory covers every byte before the signature, one SHA-256 per page,
// and every page must hash to its slot. Any other Mach-O is checked the same
// way when it carries a signature and passes when it does not: Intel Macs run
// unsigned code. Special slots (Info.plist, requirements, entitlements) and a
// CMS signature are not checked; Go's ad-hoc signature has neither.
//
// Stdlib only; the layouts are Apple's cs_blobs.h, as Go's own
// cmd/internal/codesign writes them.
package main

import (
	"bytes"
	"crypto/sha256"
	"debug/macho"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

const usageText = "usage: machocheck <mach-o file>...\n"

// Constants from Apple's cs_blobs.h and mach-o/loader.h.
const (
	lcCodeSignature   = 0x1d
	magicSuperBlob    = 0xfade0cc0
	magicCodeDir      = 0xfade0c02
	slotCodeDirectory = 0
	hashTypeSHA256    = 2
	flagAdhoc         = 0x2
	// The CodeDirectory's fixed fields up to and including spare2; every
	// version has at least these.
	codeDirHeader = 44
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is main without the process, so the tests exercise it in-process. Each
// file gets one line: what was verified on stdout, or `✗ <file>: <why>` on
// stderr. Every file is checked even after one fails.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	code := 0
	for _, path := range args {
		summary, err := check(path)
		if err != nil {
			fmt.Fprintf(stderr, "✗ %s: %v\n", path, err)
			code = 1
			continue
		}
		fmt.Fprintf(stdout, "  %s: %s\n", path, summary)
	}
	return code
}

// check reads path and verifies it; the summary names the architecture and
// what the signature covered.
func check(path string) (string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // reading the files it is asked to check is the point
	if err != nil {
		return "", err
	}
	return verify(data)
}

func verify(data []byte) (string, error) {
	f, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("not a thin Mach-O: %w", err)
	}
	arch := archName(f.Cpu)

	var sigOff, sigSize uint32
	found := false
	for _, l := range f.Loads {
		raw := l.Raw()
		if len(raw) >= 16 && f.ByteOrder.Uint32(raw) == lcCodeSignature {
			sigOff, sigSize = f.ByteOrder.Uint32(raw[8:]), f.ByteOrder.Uint32(raw[12:])
			found = true
		}
	}
	if !found {
		if f.Cpu == macho.CpuArm64 {
			return "", errors.New("arm64 without a code signature: Apple silicon kills it at exec")
		}
		return arch + ", unsigned (Intel Macs run unsigned code)", nil
	}
	if uint64(sigOff)+uint64(sigSize) > uint64(len(data)) {
		return "", fmt.Errorf("code signature at %d+%d runs past the file's %d bytes", sigOff, sigSize, len(data))
	}

	cd, err := codeDirectory(data[sigOff : sigOff+sigSize])
	if err != nil {
		return "", err
	}
	pages, pageSize, err := verifyPages(data, cd, sigOff)
	if err != nil {
		return "", err
	}
	kind := "signature"
	if binary.BigEndian.Uint32(cd[12:])&flagAdhoc != 0 {
		kind = "ad-hoc signature"
	}
	return fmt.Sprintf("%s, %s verified over %d pages of %d bytes", arch, kind, pages, pageSize), nil
}

// codeDirectory finds the CodeDirectory in the signature's SuperBlob. Every
// field in a signature is big-endian, whatever the Mach-O's byte order.
func codeDirectory(sb []byte) ([]byte, error) {
	be := binary.BigEndian
	if len(sb) < 12 || be.Uint32(sb) != magicSuperBlob {
		return nil, errors.New("code signature is not a SuperBlob")
	}
	count := be.Uint32(sb[8:])
	if uint64(count)*8+12 > uint64(len(sb)) {
		return nil, fmt.Errorf("SuperBlob claims %d entries in %d bytes", count, len(sb))
	}
	for i := range count {
		entry := sb[12+8*i:]
		if be.Uint32(entry) != slotCodeDirectory {
			continue
		}
		off := be.Uint32(entry[4:])
		if uint64(off)+8 > uint64(len(sb)) {
			return nil, fmt.Errorf("CodeDirectory offset %d is outside the SuperBlob", off)
		}
		cd := sb[off:]
		if be.Uint32(cd) != magicCodeDir {
			return nil, fmt.Errorf("slot 0 holds magic %#x, not a CodeDirectory", be.Uint32(cd))
		}
		length := be.Uint32(cd[4:])
		if length < codeDirHeader || uint64(length) > uint64(len(cd)) {
			return nil, fmt.Errorf("CodeDirectory length %d does not fit its %d bytes", length, len(cd))
		}
		return cd[:length], nil
	}
	return nil, errors.New("code signature has no CodeDirectory")
}

// verifyPages checks that the CodeDirectory covers every byte before the
// signature and that each page hashes to its slot, as the kernel does when it
// maps the page in.
func verifyPages(data, cd []byte, sigOff uint32) (pages, pageSize uint32, err error) {
	be := binary.BigEndian
	hashOffset := be.Uint32(cd[16:])
	nCodeSlots := be.Uint32(cd[28:])
	codeLimit := be.Uint32(cd[32:])
	hashSize, hashType, pageShift := cd[36], cd[37], cd[39]

	if hashType != hashTypeSHA256 || hashSize != sha256.Size {
		return 0, 0, fmt.Errorf("CodeDirectory hash type %d, size %d; want SHA-256", hashType, hashSize)
	}
	if pageShift == 0 || pageShift > 30 {
		return 0, 0, fmt.Errorf("CodeDirectory page shift %d is not a page size", pageShift)
	}
	if codeLimit != sigOff {
		return 0, 0, fmt.Errorf("CodeDirectory covers %d bytes, but the signature starts at %d", codeLimit, sigOff)
	}
	pageSize = 1 << pageShift
	want := (uint64(codeLimit) + uint64(pageSize) - 1) >> pageShift
	if uint64(nCodeSlots) != want {
		return 0, 0, fmt.Errorf("CodeDirectory has %d page hashes for %d bytes; want %d", nCodeSlots, codeLimit, want)
	}
	if uint64(hashOffset)+uint64(nCodeSlots)*sha256.Size > uint64(len(cd)) {
		return 0, 0, fmt.Errorf("CodeDirectory's %d hashes at %d run past its %d bytes", nCodeSlots, hashOffset, len(cd))
	}

	for i := range nCodeSlots {
		start := uint64(i) << pageShift
		end := min(start+uint64(pageSize), uint64(codeLimit))
		got := sha256.Sum256(data[start:end])
		slot := cd[uint64(hashOffset)+uint64(i)*sha256.Size:][:sha256.Size]
		if !bytes.Equal(got[:], slot) {
			return 0, 0, fmt.Errorf("page %d (bytes %d–%d) hashes to %x, but its slot holds %x", i, start, end, got, slot)
		}
	}
	return nCodeSlots, pageSize, nil
}

func archName(cpu macho.Cpu) string {
	switch cpu {
	case macho.CpuArm64:
		return "arm64"
	case macho.CpuAmd64:
		return "amd64"
	default:
		return cpu.String()
	}
}
