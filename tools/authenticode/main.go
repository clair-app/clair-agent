// Command authenticode checks the Authenticode signature on a Windows build
// the way a release needs it, and prints the digest a signature covers.
//
//	go run ./tools/authenticode check -signer "Jeffrey Mixon" -unsigned dist signed/clair-windows-amd64.exe
//	go run ./tools/authenticode digest dist/clair-windows-amd64.exe
//
// Why. The tag pipeline signs the Windows builds through Azure Artifact
// Signing (ADR 2026-09.6uv6), whose certificates live for three days: a
// signature without a timestamp reads as valid on the day of the release and
// invalid by the weekend, in users' hands. The `release` job runs `check`
// before it uploads anything, so a signature that is missing, untimestamped,
// by someone else, or over other bytes than the build this pipeline made
// fails the release instead of shipping.
//
// What `check` verifies, with the standard library only:
//
//   - The file is a PE whose certificate table is its last bytes and holds
//     exactly one PKCS#7 signature, so nothing rides unhashed after it.
//   - The Authenticode digest in the signature (SHA-256 or stronger) is the
//     file's own; with -unsigned DIR, it is also the digest of DIR's build of
//     the same name, which must be unsigned. Signing changes only the
//     checksum, the certificate table's directory entry and the table itself,
//     so that proves the signed file is this pipeline's build and a signature.
//   - The signer's signature over its signed attributes verifies with its
//     certificate, which is for code signing and, with -signer, has that
//     common name.
//   - An RFC 3161 timestamp countersigns that signature: its imprint is the
//     signature's hash, the timestamping authority's signature over it
//     verifies, and the time falls inside the signer certificate's validity.
//
// What it does not: build a chain to a root Windows trusts, or check
// revocation. The `signature:windows` job asks Windows itself
// (Get-AuthenticodeSignature) on the same files.
//
// `digest` prints the SHA-256 Authenticode digest of each file, signed or
// not, so a local `make dist` can be compared with a signed release: the two
// match when the release is that build plus a signature (ADR 2026-09.zvs8).
package main

import (
	"bytes"
	"crypto"
	_ "crypto/sha256" // the digests a signature may use
	_ "crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"time"
)

const usageText = `usage: authenticode check [-signer NAME] [-unsigned DIR] <file>...
       authenticode digest <file>...
`

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
	switch args[0] {
	case "check":
		return runCheck(args[1:], stdout, stderr)
	case "digest":
		return runDigest(args[1:], stdout, stderr)
	default:
		fmt.Fprint(stderr, usageText)
		return 2
	}
}

func runCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("authenticode check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	signer := fs.String("signer", "", "the common name the signing certificate must carry")
	unsigned := fs.String("unsigned", "", "a directory holding the unsigned build of each file, by the same name")
	if err := fs.Parse(args); err != nil || fs.NArg() == 0 {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	code := 0
	for _, path := range fs.Args() {
		summary, err := checkFile(path, *signer, *unsigned)
		if err != nil {
			fmt.Fprintf(stderr, "✗ %s: %v\n", path, err)
			code = 1
			continue
		}
		fmt.Fprintf(stdout, "  %s: %s\n", path, summary)
	}
	return code
}

func runDigest(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	code := 0
	for _, path := range args {
		data, err := os.ReadFile(path) //nolint:gosec // G703: reading the files it is asked about is the point
		var sum []byte
		if err == nil {
			sum, err = fileDigest(data, crypto.SHA256)
		}
		if err != nil {
			fmt.Fprintf(stderr, "✗ %s: %v\n", path, err)
			code = 1
			continue
		}
		fmt.Fprintf(stdout, "%x  %s\n", sum, path)
	}
	return code
}

func checkFile(path, signer, unsignedDir string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sig, err := verify(data, signer)
	if err != nil {
		return "", err
	}
	summary := fmt.Sprintf("signed by %q, timestamped %s by %q", sig.signer, sig.at.UTC().Format(time.RFC3339), sig.stamper)
	if unsignedDir == "" {
		return summary, nil
	}
	build := filepath.Join(unsignedDir, filepath.Base(path))
	raw, err := os.ReadFile(build)
	if err != nil {
		return "", err
	}
	img, err := parsePE(raw)
	if err != nil {
		return "", fmt.Errorf("%s: %w", build, err)
	}
	if img.signed() {
		return "", fmt.Errorf("%s is signed; -unsigned names the builds before signing", build)
	}
	if !bytes.Equal(authenticodeDigest(raw, img, sig.hash), sig.digest) {
		return "", fmt.Errorf("the signature covers other bytes than %s", build)
	}
	return summary + ", over the build " + build, nil
}

// PE layout (Microsoft's PE format and Authenticode specifications).
const (
	optHeaderPE32     = 0x10b
	optHeaderPE32Plus = 0x20b
	certTableIndex    = 4
	winCertRevision2  = 0x0200
	winCertTypePKCS7  = 0x0002
)

// image is where signing touches a PE file: the checksum and the
// certificate table's directory entry, which the digest skips, and the table.
type image struct {
	checksum  int // file offset of the optional header's CheckSum
	certEntry int // file offset of the certificate table's data directory entry
	certOff   int // the certificate table, or 0 and 0 when unsigned
	certLen   int
}

func (img image) signed() bool { return img.certLen > 0 }

func parsePE(data []byte) (image, error) {
	le := binary.LittleEndian
	if len(data) < 0x40 || data[0] != 'M' || data[1] != 'Z' {
		return image{}, errors.New("not a PE file")
	}
	pe := int(le.Uint32(data[0x3c:]))
	if pe+24 > len(data) || !bytes.Equal(data[pe:pe+4], []byte("PE\x00\x00")) {
		return image{}, errors.New("not a PE file")
	}
	opt := pe + 24
	end := opt + int(le.Uint16(data[pe+20:]))
	if end > len(data) || opt+2 > end {
		return image{}, errors.New("the optional header runs past the file")
	}
	var dirs, count int
	switch le.Uint16(data[opt:]) {
	case optHeaderPE32:
		dirs, count = opt+96, opt+92
	case optHeaderPE32Plus:
		dirs, count = opt+112, opt+108
	default:
		return image{}, fmt.Errorf("unknown optional header magic %#x", le.Uint16(data[opt:]))
	}
	img := image{checksum: opt + 64, certEntry: dirs + 8*certTableIndex}
	if count+4 > end || le.Uint32(data[count:]) <= certTableIndex || img.certEntry+8 > end {
		return image{}, errors.New("the optional header has no certificate table entry")
	}
	off, size := int64(le.Uint32(data[img.certEntry:])), int64(le.Uint32(data[img.certEntry+4:]))
	switch {
	case off == 0 && size == 0:
		return img, nil
	case off <= int64(end) || size < 8 || off+size != int64(len(data)):
		// Bytes after the table would be outside the digest, and Windows'
		// own padding check refuses them.
		return image{}, fmt.Errorf("the certificate table (%d bytes at %d) is not the end of the %d-byte file", size, off, len(data))
	case off%8 != 0:
		return image{}, fmt.Errorf("the certificate table at %d is not 8-byte aligned", off)
	}
	img.certOff, img.certLen = int(off), int(size)
	return img, nil
}

// authenticodeDigest hashes the file without its checksum, the certificate
// table's directory entry and the table: what signtool and jsign hash, and
// what Windows checks. A signer first pads the file to 8 bytes, so an
// unsigned file is hashed with that padding and matches its signed copy.
func authenticodeDigest(data []byte, img image, h crypto.Hash) []byte {
	end := len(data)
	if img.signed() {
		end = img.certOff
	}
	w := h.New()
	w.Write(data[:img.checksum])
	w.Write(data[img.checksum+4 : img.certEntry])
	w.Write(data[img.certEntry+8 : end])
	if !img.signed() {
		w.Write(make([]byte, (8-end%8)%8))
	}
	return w.Sum(nil)
}

func fileDigest(data []byte, h crypto.Hash) ([]byte, error) {
	img, err := parsePE(data)
	if err != nil {
		return nil, err
	}
	return authenticodeDigest(data, img, h), nil
}

// Object identifiers from RFC 5652 (CMS), RFC 3161, and Authenticode.
var (
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidTSTInfo       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidSpcIndirect   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}
	oidSpcPEImage    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 15}
	oidRFC3161Stamp  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 3, 3, 1}
)

// The digests a signature may use; SHA-1 is not one.
var digests = map[string]crypto.Hash{
	"2.16.840.1.101.3.4.2.1": crypto.SHA256,
	"2.16.840.1.101.3.4.2.2": crypto.SHA384,
	"2.16.840.1.101.3.4.2.3": crypto.SHA512,
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	Encap            encapsulated
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

type encapsulated struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type signerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

type spcIndirectData struct {
	Data struct {
		Type  asn1.ObjectIdentifier
		Value asn1.RawValue `asn1:"optional"`
	}
	Digest struct {
		Algorithm pkix.AlgorithmIdentifier
		Digest    []byte
	}
}

type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint struct {
		Algorithm     pkix.AlgorithmIdentifier
		HashedMessage []byte
	}
	Serial  *big.Int
	GenTime time.Time `asn1:"generalized"`
}

// signature is what verify found.
type signature struct {
	signer, stamper string
	at              time.Time
	hash            crypto.Hash // the Authenticode digest's algorithm
	digest          []byte
}

func verify(data []byte, signer string) (signature, error) {
	img, err := parsePE(data)
	if err != nil {
		return signature{}, err
	}
	if !img.signed() {
		return signature{}, errors.New("not signed")
	}
	table := data[img.certOff:]
	length := int(binary.LittleEndian.Uint32(table))
	switch {
	case length < 8 || length > len(table):
		return signature{}, fmt.Errorf("the certificate entry claims %d of the table's %d bytes", length, len(table))
	case (length+7)&^7 != len(table):
		return signature{}, errors.New("the certificate table holds more than one entry")
	case binary.LittleEndian.Uint16(table[4:]) != winCertRevision2 || binary.LittleEndian.Uint16(table[6:]) != winCertTypePKCS7:
		return signature{}, errors.New("the certificate entry is not a PKCS#7 signature")
	}

	sd, err := parseSignedData(table[8:length])
	if err != nil {
		return signature{}, err
	}
	if !sd.Encap.ContentType.Equal(oidSpcIndirect) {
		return signature{}, fmt.Errorf("the signed content is %v, not Authenticode's SpcIndirectDataContent", sd.Encap.ContentType)
	}
	var content asn1.RawValue
	if _, err = asn1.Unmarshal(sd.Encap.Content.Bytes, &content); err != nil {
		return signature{}, fmt.Errorf("signed content: %w", err)
	}
	var spc spcIndirectData
	if err = unmarshalAll(content.FullBytes, &spc); err != nil {
		return signature{}, fmt.Errorf("SpcIndirectDataContent: %w", err)
	}
	if !spc.Data.Type.Equal(oidSpcPEImage) {
		return signature{}, fmt.Errorf("the signature is for %v, not a PE image", spc.Data.Type)
	}
	h, ok := digests[spc.Digest.Algorithm.Algorithm.String()]
	if !ok {
		return signature{}, fmt.Errorf("the Authenticode digest is %v, not SHA-256 or stronger", spc.Digest.Algorithm.Algorithm)
	}
	if !bytes.Equal(authenticodeDigest(data, img, h), spc.Digest.Digest) {
		return signature{}, errors.New("the file's bytes are not the ones signed")
	}

	// The messageDigest attribute covers the content's value, without its tag.
	cert, si, err := verifySigner(sd, content.Bytes)
	if err != nil {
		return signature{}, err
	}
	if !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageCodeSigning) {
		return signature{}, fmt.Errorf("the certificate for %q is not for code signing", cert.Subject.CommonName)
	}
	if signer != "" && cert.Subject.CommonName != signer {
		return signature{}, fmt.Errorf("signed by %q, not %q", cert.Subject.CommonName, signer)
	}
	stamper, at, err := verifyTimestamp(si)
	if err != nil {
		return signature{}, err
	}
	if at.Before(cert.NotBefore) || at.After(cert.NotAfter) {
		return signature{}, fmt.Errorf("timestamped %s, outside the certificate's %s to %s", at.UTC().Format(time.RFC3339),
			cert.NotBefore.UTC().Format(time.RFC3339), cert.NotAfter.UTC().Format(time.RFC3339))
	}
	return signature{signer: cert.Subject.CommonName, stamper: stamper, at: at, hash: h, digest: spc.Digest.Digest}, nil
}

// verifyTimestamp finds the RFC 3161 countersignature on si, checks that it
// stamps si's signature, and returns its authority and time.
func verifyTimestamp(si signerInfo) (string, time.Time, error) {
	attrs, err := parseAttributes(si.UnsignedAttrs)
	if err != nil {
		return "", time.Time{}, err
	}
	token, ok := attrs[oidRFC3161Stamp.String()]
	if !ok {
		return "", time.Time{}, errors.New("the signature is not timestamped (no RFC 3161 countersignature)")
	}
	tsd, err := parseSignedData(token)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("timestamp: %w", err)
	}
	if !tsd.Encap.ContentType.Equal(oidTSTInfo) {
		return "", time.Time{}, fmt.Errorf("the timestamp's content is %v, not TSTInfo", tsd.Encap.ContentType)
	}
	var der []byte
	if err = unmarshalAll(tsd.Encap.Content.Bytes, &der); err != nil {
		return "", time.Time{}, fmt.Errorf("timestamp content: %w", err)
	}
	var info tstInfo
	if err = unmarshalAll(der, &info); err != nil {
		return "", time.Time{}, fmt.Errorf("TSTInfo: %w", err)
	}
	h, ok := digests[info.MessageImprint.Algorithm.Algorithm.String()]
	if !ok {
		return "", time.Time{}, fmt.Errorf("the timestamp imprint is %v, not SHA-256 or stronger", info.MessageImprint.Algorithm.Algorithm)
	}
	w := h.New()
	w.Write(si.Signature)
	if !bytes.Equal(w.Sum(nil), info.MessageImprint.HashedMessage) {
		return "", time.Time{}, errors.New("the timestamp is for another signature")
	}
	cert, _, err := verifySigner(tsd, der)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("timestamp: %w", err)
	}
	if !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageTimeStamping) {
		return "", time.Time{}, fmt.Errorf("the timestamp's certificate for %q is not for timestamping", cert.Subject.CommonName)
	}
	return cert.Subject.CommonName, info.GenTime, nil
}

// parseSignedData reads a ContentInfo holding a CMS SignedData. Signers pad
// the certificate entry to 8 bytes, so zeros may follow it.
func parseSignedData(der []byte) (signedData, error) {
	var ci contentInfo
	rest, err := asn1.Unmarshal(der, &ci)
	if err != nil {
		return signedData{}, fmt.Errorf("PKCS#7: %w", err)
	}
	if len(bytes.Trim(rest, "\x00")) > 0 {
		return signedData{}, errors.New("PKCS#7: data after the signature")
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return signedData{}, fmt.Errorf("PKCS#7: content is %v, not SignedData", ci.ContentType)
	}
	var sd signedData
	if err = unmarshalAll(ci.Content.Bytes, &sd); err != nil {
		return signedData{}, fmt.Errorf("SignedData: %w", err)
	}
	return sd, nil
}

// verifySigner checks sd's one signer: its signed attributes name the content
// and carry content's digest, and its certificate's key verifies them.
func verifySigner(sd signedData, content []byte) (*x509.Certificate, signerInfo, error) {
	if len(sd.SignerInfos) != 1 {
		return nil, signerInfo{}, fmt.Errorf("%d signers, want 1", len(sd.SignerInfos))
	}
	si := sd.SignerInfos[0]
	h, ok := digests[si.DigestAlgorithm.Algorithm.String()]
	if !ok {
		return nil, signerInfo{}, fmt.Errorf("the signer's digest is %v, not SHA-256 or stronger", si.DigestAlgorithm.Algorithm)
	}
	alg, err := signatureAlgorithm(h, si.SignatureAlgorithm.Algorithm)
	if err != nil {
		return nil, signerInfo{}, err
	}
	attrs, err := parseAttributes(si.SignedAttrs)
	if err != nil {
		return nil, signerInfo{}, err
	}
	var ct asn1.ObjectIdentifier
	if v, found := attrs[oidContentType.String()]; !found || unmarshalAll(v, &ct) != nil || !ct.Equal(sd.Encap.ContentType) {
		return nil, signerInfo{}, errors.New("the signed attributes do not name the signed content's type")
	}
	var md []byte
	if v, found := attrs[oidMessageDigest.String()]; !found || unmarshalAll(v, &md) != nil {
		return nil, signerInfo{}, errors.New("the signed attributes carry no message digest")
	}
	w := h.New()
	w.Write(content)
	if !bytes.Equal(w.Sum(nil), md) {
		return nil, signerInfo{}, errors.New("the signed attributes are for other content")
	}
	cert, err := signerCert(sd, si)
	if err != nil {
		return nil, signerInfo{}, err
	}
	// The signature is over the attributes as a SET, not as the [0] they are
	// tagged in the SignerInfo (RFC 5652 §5.4).
	signed := bytes.Clone(si.SignedAttrs.FullBytes)
	signed[0] = 0x31
	if err = cert.CheckSignature(alg, signed, si.Signature); err != nil {
		return nil, signerInfo{}, fmt.Errorf("the signature by %q does not verify: %w", cert.Subject.CommonName, err)
	}
	return cert, si, nil
}

// signerCert finds the certificate si names, by issuer and serial number or
// by subject key identifier.
func signerCert(sd signedData, si signerInfo) (*x509.Certificate, error) {
	certs, err := x509.ParseCertificates(sd.Certificates.Bytes)
	if err != nil {
		return nil, fmt.Errorf("certificates: %w", err)
	}
	match := func(*x509.Certificate) bool { return false }
	switch {
	case si.SID.Class == asn1.ClassUniversal && si.SID.Tag == asn1.TagSequence:
		var ias issuerAndSerial
		if err = unmarshalAll(si.SID.FullBytes, &ias); err != nil {
			return nil, fmt.Errorf("signer id: %w", err)
		}
		match = func(c *x509.Certificate) bool {
			return bytes.Equal(c.RawIssuer, ias.Issuer.FullBytes) && c.SerialNumber.Cmp(ias.Serial) == 0
		}
	case si.SID.Class == asn1.ClassContextSpecific && si.SID.Tag == 0:
		match = func(c *x509.Certificate) bool { return bytes.Equal(c.SubjectKeyId, si.SID.Bytes) }
	}
	for _, c := range certs {
		if match(c) {
			return c, nil
		}
	}
	return nil, errors.New("the signer's certificate is not in the signature")
}

// signatureAlgorithm maps a SignerInfo's signature algorithm, which CMS may
// name by key type alone, to x509's.
func signatureAlgorithm(h crypto.Hash, oid asn1.ObjectIdentifier) (x509.SignatureAlgorithm, error) {
	rsa := map[crypto.Hash]x509.SignatureAlgorithm{crypto.SHA256: x509.SHA256WithRSA, crypto.SHA384: x509.SHA384WithRSA, crypto.SHA512: x509.SHA512WithRSA}
	ecdsa := map[crypto.Hash]x509.SignatureAlgorithm{crypto.SHA256: x509.ECDSAWithSHA256, crypto.SHA384: x509.ECDSAWithSHA384, crypto.SHA512: x509.ECDSAWithSHA512}
	switch oid.String() {
	case "1.2.840.113549.1.1.1", "1.2.840.113549.1.1.11", "1.2.840.113549.1.1.12", "1.2.840.113549.1.1.13":
		return rsa[h], nil
	case "1.2.840.10045.2.1", "1.2.840.10045.4.3.2", "1.2.840.10045.4.3.3", "1.2.840.10045.4.3.4":
		return ecdsa[h], nil
	}
	return x509.UnknownSignatureAlgorithm, fmt.Errorf("unsupported signature algorithm %v", oid)
}

// parseAttributes reads a SignerInfo's [0] or [1] SET OF Attribute into each
// type's single value.
func parseAttributes(raw asn1.RawValue) (map[string][]byte, error) {
	if len(raw.FullBytes) == 0 {
		return make(map[string][]byte), nil
	}
	set := bytes.Clone(raw.FullBytes)
	set[0] = 0x31
	var attrs []attribute
	if err := unmarshalAllParams(set, &attrs, "set"); err != nil {
		return nil, fmt.Errorf("attributes: %w", err)
	}
	out := make(map[string][]byte, len(attrs))
	for _, a := range attrs {
		key := a.Type.String()
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("attribute %s appears twice", key)
		}
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(a.Values.Bytes, &v)
		if err != nil || len(rest) > 0 {
			return nil, fmt.Errorf("attribute %s must have one value", key)
		}
		out[key] = v.FullBytes
	}
	return out, nil
}

func unmarshalAll(der []byte, v any) error { return unmarshalAllParams(der, v, "") }

func unmarshalAllParams(der []byte, v any, params string) error {
	rest, err := asn1.UnmarshalWithParams(der, v, params)
	if err != nil {
		return err
	}
	if len(rest) > 0 {
		return errors.New("trailing data")
	}
	return nil
}
