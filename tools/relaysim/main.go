// Command relaysim serves the in-memory fake relay of internal/relay/relaytest
// on a local port, so `clair daemon`, `clair pair` and tools/phonesim can be
// run end to end as real processes before a real relay is reachable.
// Development only; it forgets everything when it stops.
//
//	go run ./tools/relaysim [-listen 127.0.0.1:3000]
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"claircode.app/clair-agent/internal/relay/relaytest"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:3000", "address to serve the fake relay on")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, *listen, os.Stdout)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, listen string, stdout *os.File) int {
	fake := relaytest.New()
	defer fake.Close()
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "relaysim:", err)
		return 1
	}
	srv := &http.Server{Handler: fake.Server.Config.Handler, ReadHeaderTimeout: relaytest.ReadHeaderTimeout}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	fmt.Fprintf(stdout, "fake relay listening on http://%s — pair with: clair pair -relay http://%s\n", ln.Addr(), ln.Addr())
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "relaysim:", err)
		return 1
	}
	return 0
}
