package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Repo-relative, so the tool works from any cwd inside any worktree.
const (
	decisionsDir = ".agents/memory/decisions"
	routerPath   = ".agents/memory/decisions.md"
)

// Suffix alphabet: Crockford-ish base32 minus the characters that are misread
// aloud or mistyped out of a code comment — 0/O, 1/l/I. 31^4 ≈ 923k, so two
// worktrees minting on the same day collide with probability ~1e-6, and `new`
// refuses to overwrite anyway.
const (
	suffixAlphabet = "23456789abcdefghjkmnpqrstuvwxyz"
	suffixLength   = 4
	maxSlugLength  = 80
)

var (
	// `2026-09.k3f9`: the only id form this repository has ever had.
	idPattern   = regexp.MustCompile(`^\d{4}-\d{2}\.[` + suffixAlphabet + `]{` + strconv.Itoa(suffixLength) + `}$`)
	datePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	// The clause and word splitters behind [slugFor].
	clauseSplit = regexp.MustCompile(`[:;—–,(]`)
	nonWord     = regexp.MustCompile(`[^a-z0-9]+`)
)

var frontmatterKeys = []string{"id", "slug", "title", "date", "topics"}

// usageError is a refused invocation: reported with the usage text and exit 2,
// where a malformed ADR is exit 1.
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

// parseInterspersed is flag.FlagSet.Parse for a command whose flags may follow
// its positionals (`new "<title>" -topics a,b`): the standard parser stops at
// the first non-flag, so this resumes it after each one.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return positional, nil
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}

// adr is one validated decision file.
type adr struct {
	ID     string
	Slug   string
	Title  string
	Date   string // ISO, YYYY-MM-DD
	Topics []string
	File   string // basename, e.g. `2026-09-k3f9-the-queue-is-bounded.md`
}

// findRepoRoot walks up to the directory holding go.mod.
//
// Not the cwd: run from `cmd/clair/`, the tool would otherwise read a
// non-existent decisions directory and report "0 decisions", which for a
// generator means happily truncating the router instead of failing.
func findRepoRoot(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		if info, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && !info.IsDir() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod above %s", start)
		}
		dir = parent
	}
}

// mintID mints a fresh id. `now` and the entropy source are injected so the
// tests can pin both; production passes time.Now and crypto/rand.
func mintID(now time.Time, entropy io.Reader) (string, error) {
	raw := make([]byte, suffixLength)
	if _, err := io.ReadFull(entropy, raw); err != nil {
		return "", fmt.Errorf("mint id: %w", err)
	}
	suffix := make([]byte, suffixLength)
	for i, b := range raw {
		suffix[i] = suffixAlphabet[int(b)%len(suffixAlphabet)]
	}
	return now.Format("2006-01") + "." + string(suffix), nil
}

// fileNameFor is the filename an id + slug must have.
//
// The `.` in the id becomes `-`, so the name has exactly one extension:
// `2026-09.k3f9-foo.md` reads to plenty of tooling as a file called `2026-09`
// with a very long extension.
func fileNameFor(id, slug string) string {
	return strings.ReplaceAll(id, ".", "-") + "-" + slug + ".md"
}

// slugFor derives a kebab slug from a title: first clause, ASCII only, and at
// most 80 characters cut on a word boundary.
func slugFor(title string) string {
	firstClause := clauseSplit.Split(title, 2)[0]
	lowered := strings.ToLower(strings.ReplaceAll(firstClause, "`", ""))
	words := strings.Split(strings.Trim(nonWord.ReplaceAllString(lowered, "-"), "-"), "-")
	words = slices.DeleteFunc(words, func(w string) bool { return w == "" })
	slug := strings.Join(words, "-")
	if len(slug) > maxSlugLength {
		slug = slug[:maxSlugLength]
		if cut := strings.LastIndex(slug, "-"); cut > 0 {
			slug = slug[:cut]
		}
	}
	return strings.Trim(slug, "-")
}

// citation is how an ADR is cited in prose and in code comments.
func citation(id string) string {
	return "ADR " + id
}

// parseFrontmatter parses the five-key block. Deliberately strict: a typo in a
// key name has to be an error here, or it becomes a silently missing router row.
func parseFrontmatter(text, file string) (map[string]string, error) {
	if !strings.HasPrefix(text, "---\n") {
		return nil, fmt.Errorf("%s: no frontmatter block", file)
	}
	end := strings.Index(text[4:], "\n---\n")
	if end == -1 {
		return nil, fmt.Errorf("%s: unterminated frontmatter", file)
	}
	fields := make(map[string]string)
	for line := range strings.SplitSeq(text[4:4+end], "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("%s: unparseable frontmatter line %q", file, line)
		}
		fields[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return fields, nil
}

// unquote strips the quoting `new` applies to ids and titles (titles carry `:` and `"`).
func unquote(value string) string {
	if !strings.HasPrefix(value, `"`) || len(value) < 2 {
		return value
	}
	inner := value[1 : len(value)-1]
	return strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(inner)
}

func quote(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
}

func parseTopics(value, file string) ([]string, error) {
	if !strings.HasPrefix(value, "[") || !strings.HasSuffix(value, "]") {
		return nil, fmt.Errorf("%s: topics must be an inline list, got %q", file, value)
	}
	var topics []string
	for t := range strings.SplitSeq(value[1:len(value)-1], ",") {
		if t = strings.TrimSpace(t); t != "" {
			topics = append(topics, t)
		}
	}
	return topics, nil
}

// readADRs reads and validates every decision file, sorted by id — which is
// chronological by month, then arbitrary but stable within one.
//
// Every check here exists because its absence would produce a *plausible* router
// rather than a loud failure: a duplicate id silently shadows a decision, and a
// heading that disagrees with its frontmatter breaks the grep anchor every
// `ADR …` citation in the tree relies on.
func readADRs(root string) ([]adr, error) {
	dir := filepath.Join(root, decisionsDir)
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("%s/ does not exist", decisionsDir)
	}
	paths, err := filepath.Glob(filepath.Join(dir, "*.md"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)

	var adrs []adr
	seen := make(map[string]string)
	for _, path := range paths {
		file := filepath.Base(path)
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		text := string(raw)

		fields, err := parseFrontmatter(text, file)
		if err != nil {
			return nil, err
		}
		for _, key := range frontmatterKeys {
			if _, ok := fields[key]; !ok {
				return nil, fmt.Errorf("%s: missing frontmatter key %q", file, key)
			}
		}

		id, title := unquote(fields["id"]), unquote(fields["title"])
		slug, date := fields["slug"], fields["date"]

		if !idPattern.MatchString(id) {
			return nil, fmt.Errorf("%s: %q is not a valid ADR id", file, id)
		}
		if other, dup := seen[id]; dup {
			return nil, fmt.Errorf("duplicate ADR id %q: %s and %s", id, other, file)
		}
		seen[id] = file

		if expected := fileNameFor(id, slug); file != expected {
			return nil, fmt.Errorf("%s: id + slug say the filename should be %s", file, expected)
		}
		if !datePattern.MatchString(date) {
			return nil, fmt.Errorf("%s: date %q is not YYYY-MM-DD", file, date)
		}

		// The grep anchor. Every `ADR …` citation in the tree resolves by finding
		// this line, so it must match the frontmatter exactly.
		heading := "# " + citation(id) + " — " + title
		if !strings.Contains(text, "\n"+heading+"\n") {
			return nil, fmt.Errorf("%s: expected heading %q", file, heading)
		}

		topics, err := parseTopics(fields["topics"], file)
		if err != nil {
			return nil, err
		}
		adrs = append(adrs, adr{ID: id, Slug: slug, Title: title, Date: date, Topics: topics, File: file})
	}

	slices.SortFunc(adrs, func(a, b adr) int { return strings.Compare(a.ID, b.ID) })
	return adrs, nil
}

const scaffold = `---
id: %[1]s
slug: %[2]s
title: %[3]s
date: %[4]s
topics: [%[5]s]
---

# %[6]s — %[7]s

Status: Accepted (%[4]s)

**What was observed**, and what it was mistaken for. Numbers where there are numbers.

**What changed**, and what the alternative was — including the one a reader would
reach for first, and why it does not work here.

**What it costs**, what it does not cover, and the trap the next person will hit. Name
the test, gate or invariant that keeps this true.
`

func commandNew(root string, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("adr new", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	topicsFlag := fs.String("topics", "", "comma-separated router topics")
	words, err := parseInterspersed(fs, args)
	if err != nil {
		return &usageError{`usage: adr new "<title>" [-topics a,b,c]`}
	}
	title := strings.TrimSpace(strings.Join(words, " "))
	if title == "" {
		return &usageError{`usage: adr new "<title>" [-topics a,b,c]`}
	}
	slug := slugFor(title)
	if slug == "" {
		return fmt.Errorf("could not derive a slug from %q", title)
	}

	dir := filepath.Join(root, decisionsDir)
	if err = os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	now := time.Now()
	id, err := mintID(now, rand.Reader)
	if err != nil {
		return err
	}
	file := fileNameFor(id, slug)
	path := filepath.Join(dir, file)

	var topics []string
	for t := range strings.SplitSeq(*topicsFlag, ",") {
		if t = strings.TrimSpace(t); t != "" {
			topics = append(topics, t)
		}
	}
	body := fmt.Sprintf(scaffold,
		quote(id), slug, quote(title), now.Format("2006-01-02"),
		strings.Join(topics, ", "), citation(id), title)

	// O_EXCL: only reachable on a ~1e-6 suffix collision, but a silent overwrite
	// here destroys another worktree's decision.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists — rerun to mint a different suffix", file)
		}
		return err
	}
	if _, err := f.WriteString(body); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	fmt.Fprintf(stdout, "✓ %s/%s\n", decisionsDir, file)
	fmt.Fprintf(stdout, "  cite as:  (%s)\n", citation(id))
	fmt.Fprintln(stdout, "  then run: go run ./tools/adr index")
	return nil
}

const preamble = `# Architecture decision records

The load-bearing decisions and *why* they hold, so future work stays consistent. One
file each, in [` + "`decisions/`" + `](decisions/) — this page is the router. Open the file whose
row matches; don't guess from the title alone. Supersede by writing a new ADR and
changing the old one's ` + "`Status:`" + ` — never by deleting it.

**This file is generated. Do not edit it by hand.** Add a decision with
` + "`go run ./tools/adr new \"<title>\" -topics a,b`" + `, write the body, then
` + "`go run ./tools/adr index`" + ` (` + "`make adr-index`" + `).

**Ids are ` + "`YYYY-MM.suffix`" + `** (` + "`ADR 2026-09.k3f9`" + `), minted at random from day one. A
sequence number is itself a merge conflict — parallel worktrees all read the same "next
number" and all take it — so nobody picks one. Cite the id an ADR carries; never renumber.`

func row(a adr) string {
	// No title carries a `|` today, but one would silently break the table.
	title := strings.ReplaceAll(a.Title, "|", `\|`)
	return fmt.Sprintf("| [%s](%s/%s) | %s | %s |", a.ID, filepath.Base(decisionsDir), a.File, title, strings.Join(a.Topics, ", "))
}

// render is the preamble, then nothing but table rows. No decision COUNT, on
// purpose: `.gitattributes` gives the router `merge=union`, which is right for a
// file whose only churn is appended rows but wrong for any line that CHANGES —
// two branches each adding an ADR would union into two count lines rather than
// conflicting, and the stale one never leaves. Every line here is append-only,
// as union assumes.
func render(adrs []adr) string {
	var b strings.Builder
	b.WriteString(preamble)
	b.WriteString("\n\n| ADR | Decision | Topics |\n| --- | --- | --- |\n")
	for _, a := range adrs {
		b.WriteString(row(a))
		b.WriteByte('\n')
	}
	return b.String()
}

func commandIndex(root string, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("adr index", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	check := fs.Bool("check", false, "fail instead of writing (CI / hooks)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return &usageError{"usage: adr index [-check]"}
	}

	adrs, err := readADRs(root)
	if err != nil {
		return err
	}
	rendered := render(adrs)

	path := filepath.Join(root, routerPath)
	current, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if string(current) == rendered {
		fmt.Fprintf(stdout, "✓ %s is up to date (%d decisions)\n", routerPath, len(adrs))
		return nil
	}
	if *check {
		return fmt.Errorf("%s is stale — run `go run ./tools/adr index`", routerPath)
	}
	if err := os.WriteFile(path, []byte(rendered), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "✓ wrote %s (%d decisions)\n", routerPath, len(adrs))
	return nil
}
