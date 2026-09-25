// Command releasesign makes and signs a local release, to try the agent's
// self-update without claircode.app (ADR 2026-09.qk6v).
//
//	go run ./tools/releasesign keygen -out k.pem    # a test key; prints its public half
//	go run ./tools/releasesign pubkey -key k.pem    # the public half again
//	go run ./tools/releasesign sign -key k.pem DIR  # DIR/SHA256SUMS.txt → DIR/SHA256SUMS.txt.sig
//	go run ./tools/releasesign builtin              # the release keys built into the agent
//	go run ./tools/releasesign serve DIR            # serve a local release on 127.0.0.1:8001
//
// A build trusts a test key only when the linker put it there (`make build
// RELEASE_TEST_KEY=<public key>`), which `clair version` then says and `make
// dist` refuses. Real releases are signed in clair-web, with keys kept
// offline, by `node scripts/agent-release.mjs pin`; this tool never touches
// them. Its keys are unencrypted PKCS#8 PEM, as Node reads them too.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"claircode.app/clair-agent/internal/update"
)

const usageText = `usage:
  releasesign keygen -out FILE     write a new test key (0600) and print its public half
  releasesign pubkey -key FILE     print a key's public half
  releasesign sign -key FILE DIR   sign DIR/SHA256SUMS.txt into DIR/SHA256SUMS.txt.sig
  releasesign builtin              print the agent's built-in release keys; fail under two
  releasesign serve [-listen ADDR] DIR   serve DIR over HTTP on loopback (default 127.0.0.1:8001)
`

// minBuiltinKeys is a primary and a backup. A release with fewer could
// never be updated past a lost key, and one with none never updated at all,
// so `make dist` refuses it (ADR 2026-09.qk6v).
const minBuiltinKeys = 2

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is main without the process, so the tests exercise it in-process.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	fs := flag.NewFlagSet("releasesign "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "where keygen writes the key")
	keyFile := fs.String("key", "", "the key to read")
	listen := fs.String("listen", "127.0.0.1:8001", "where serve listens; loopback only")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	var err error
	switch {
	case args[0] == "keygen" && *out != "" && fs.NArg() == 0:
		err = keygen(*out, stdout)
	case args[0] == "pubkey" && *keyFile != "" && fs.NArg() == 0:
		err = pubkey(*keyFile, stdout)
	case args[0] == "sign" && *keyFile != "" && fs.NArg() == 1:
		err = sign(*keyFile, fs.Arg(0), stdout)
	case args[0] == "builtin" && fs.NArg() == 0:
		err = builtin(stdout)
	case args[0] == "serve" && fs.NArg() == 1:
		err = serve(*listen, fs.Arg(0), stdout)
	default:
		fmt.Fprint(stderr, usageText)
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "releasesign: %v\n", err)
		return 1
	}
	return 0
}

func keygen(path string, stdout io.Writer) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // the path the person running the tool gave
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintln(stdout, base64.StdEncoding.EncodeToString(pub))
	return nil
}

func readKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the path the person running the tool gave
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s: not an unencrypted PKCS#8 PEM key", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an Ed25519 key", path)
	}
	return key, nil
}

func pubkey(path string, stdout io.Writer) error {
	key, err := readKey(path)
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, base64.StdEncoding.EncodeToString(key[ed25519.SeedSize:]))
	return nil
}

func sign(path, dir string, stdout io.Writer) error {
	key, err := readKey(path)
	if err != nil {
		return err
	}
	sums, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS.txt")) //nolint:gosec // the directory the person running the tool named
	if err != nil {
		return err
	}
	if len(sums) == 0 {
		return errors.New("SHA256SUMS.txt is empty")
	}
	out := filepath.Join(dir, "SHA256SUMS.txt.sig")
	if err := os.WriteFile(out, []byte(update.Sign(key, sums)+"\n"), 0o644); err != nil { //nolint:gosec // beside the checksums the person running the tool named
		return err
	}
	fmt.Fprintf(stdout, "signed %s\n", out)
	return nil
}

func builtin(stdout io.Writer) error {
	keys := update.ReleaseKeys()
	for _, k := range keys {
		fmt.Fprintln(stdout, base64.StdEncoding.EncodeToString(k))
	}
	if len(keys) < minBuiltinKeys {
		return fmt.Errorf("%d release keys are built in (internal/update/keys.go), fewer than %d", len(keys), minBuiltinKeys)
	}
	return nil
}

// serve is a release server for trying the self-update where there is no
// Python to run one (the Windows CI job): the files in dir, on loopback, until
// interrupted. The agent reads plain HTTP from loopback only.
func serve(listen, dir string, stdout io.Writer) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("-listen %s: serve only on loopback", listen)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", listen)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: http.FileServer(http.Dir(dir)), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	fmt.Fprintf(stdout, "serving %s on http://%s\n", dir, ln.Addr())
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
