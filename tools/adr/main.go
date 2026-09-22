// Command adr mints and indexes architecture decision records.
//
//	go run ./tools/adr new "<title>" [-topics a,b,c]
//	go run ./tools/adr index [-check]
//	go run ./tools/adr -C <dir> …
//
// Decisions live one-per-file in `.agents/memory/decisions/`, and
// `.agents/memory/decisions.md` is a **generated** router over them.
//
// Why ids are random. Sibling repositories (clair, knit-next, whatsnew-app) once
// numbered ADRs in sequence and appended each to one long file. Worked in several
// git worktrees at once, two branches adding a decision on the same afternoon
// collided twice over: once on the number (both read "067", both took "068") and
// once on the append. This repository starts with the fix and never had the
// sequence: every id is `YYYY-MM.suffix`, the suffix minted at random, so there is
// nothing to pick and nothing to collide. The router's only churn is one table row,
// and `.gitattributes` gives it `merge=union` so even that resolves itself.
//
// Go, not a script. This is a Go module, so `go run` is the one tool every
// contributor and CI image already has; a cached `go run` of a stdlib-only program
// costs well under a second. Stdlib only, including the frontmatter parser: it is
// five known keys, and `.agents/rules/go.md` asks for a reason before any new
// dependency, which a thirty-line parser is plainly the cheaper side of.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

const usageText = `usage: adr [-C <dir>] <command> [flags] [args]

commands:
  new "<title>" [-topics a,b,c]   scaffold a decision with a collision-free id
  index [-check]                  regenerate ` + routerPath + ` (-check: fail if stale)

-C <dir>   use <dir> as the repository root instead of walking up to go.mod
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is main without the process, so the whole CLI is exercised in-process by
// the tests. Every failure is reported as `✗ <message>` on stderr, never a stack.
func run(args []string, stdout, stderr io.Writer) int {
	global := flag.NewFlagSet("adr", flag.ContinueOnError)
	global.SetOutput(io.Discard)
	rootFlag := global.String("C", "", "repository root")
	if err := global.Parse(args); err != nil {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	rest := global.Args()
	if len(rest) == 0 {
		fmt.Fprint(stderr, usageText)
		return 2
	}

	root := *rootFlag
	if root == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fail(stderr, err)
		}
		root, err = findRepoRoot(cwd)
		if err != nil {
			return fail(stderr, err)
		}
	}

	var err error
	switch rest[0] {
	case "new":
		err = commandNew(root, rest[1:], stdout)
	case "index":
		err = commandIndex(root, rest[1:], stdout)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usageText)
	default:
		fmt.Fprintf(stderr, "adr: unknown command %q\n\n%s", rest[0], usageText)
		return 2
	}
	if err != nil {
		return fail(stderr, err)
	}
	return 0
}

func fail(stderr io.Writer, err error) int {
	if _, ok := errors.AsType[*usageError](err); ok {
		fmt.Fprintf(stderr, "✗ %v\n\n%s", err, usageText)
		return 2
	}
	fmt.Fprintf(stderr, "✗ %v\n", err)
	return 1
}
