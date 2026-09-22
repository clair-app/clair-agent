// Command clair is the host-side agent of Clair: a blind, end-to-end encrypted
// tunnel between Claude Code's http hooks on loopback and the phone, by way of
// a relay that only ever sees ciphertext.
//
// The design is `docs/RELAY.md` in the clair repository; `.agents/context/design.md`
// maps its sections onto this codebase. Nothing below the version command is
// implemented yet.
package main

import (
	"fmt"
	"io"
	"os"
	"runtime/debug"
)

// Set by the linker from the Makefile (`-X main.version=…`). The build-info
// fallback in [buildVersion] covers a plain `go build` / `go install`.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is main without the process: arguments in, exit status out, so the
// dispatch is testable without forking.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}

	switch args[0] {
	case "version":
		v, c := buildVersion()
		fmt.Fprintf(stdout, "clair %s (%s, %s)\n", v, c, date)
		return 0
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "clair: unknown command %q\n\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage: clair <command>

commands:
  version   print the agent version
  help      print this message
`)
}

// buildVersion prefers the linker-injected values and falls back to what the
// Go toolchain recorded about the main module and its VCS checkout, so a
// `go install claircode.app/clair-agent/cmd/clair@vX` still reports vX.
func buildVersion() (ver, rev string) {
	ver, rev = version, commit
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ver, rev
	}
	if ver == "dev" && info.Main.Version != "" && info.Main.Version != "(devel)" {
		ver = info.Main.Version
	}
	if rev == "none" {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 7 {
				rev = s.Value[:7]
			}
		}
	}
	return ver, rev
}
