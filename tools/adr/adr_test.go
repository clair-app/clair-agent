package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSlugFor(t *testing.T) {
	t.Parallel()

	tests := []struct{ title, want string }{
		{"The queue is bounded", "the-queue-is-bounded"},
		{"Ids are `YYYY-MM.suffix`: no sequence", "ids-are-yyyy-mm-suffix"},
		{"Static-static DH, salted with k (not signatures)", "static-static-dh"},
		{"Wake hints — now, soon, no", "wake-hints"},
		{"  spaces   and   CAPS  ", "spaces-and-caps"},
		{strings.Repeat("word ", 30), strings.Trim(strings.Repeat("word-", 16), "-")},
		// 21-character words: the 80-char cut lands mid-word and backs up to the boundary.
		{strings.Repeat("internationalization ", 5), strings.Trim(strings.Repeat("internationalization-", 3), "-")},
		{"— ( : ;", ""},
	}
	for _, tt := range tests {
		if got := slugFor(tt.title); got != tt.want {
			t.Errorf("slugFor(%q) = %q, want %q", tt.title, got, tt.want)
		}
	}
}

func TestMintID(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 21, 12, 0, 0, 0, time.UTC)

	id, err := mintID(now, bytes.NewReader([]byte{0, 1, 30, 31}))
	if err != nil {
		t.Fatal(err)
	}
	// 0 → '2', 1 → '3', 30 → 'z', 31 → wraps to '2'.
	if id != "2026-09.23z2" {
		t.Errorf("mintID = %q, want 2026-09.23z2", id)
	}
	if !idPattern.MatchString(id) {
		t.Errorf("mintID = %q does not match its own pattern", id)
	}

	if _, err := mintID(now, bytes.NewReader(nil)); err == nil {
		t.Error("mintID with no entropy: want error")
	}
}

func TestIDPatternRejectsAmbiguousCharacters(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{"2026-09.k0f9", "2026-09.k1f9", "2026-09.klf9", "2026-09.kOf9", "2026-09.KABC", "001", "2026-09-k3f9", "2026-09.k3f"} {
		if idPattern.MatchString(bad) {
			t.Errorf("idPattern accepted %q", bad)
		}
	}
	if !idPattern.MatchString("2026-09.k3f9") {
		t.Error("idPattern rejected a valid id")
	}
}

func TestFileNameFor(t *testing.T) {
	t.Parallel()

	if got := fileNameFor("2026-09.k3f9", "the-queue-is-bounded"); got != "2026-09-k3f9-the-queue-is-bounded.md" {
		t.Errorf("fileNameFor = %q", got)
	}
}

func TestQuoteRoundTrip(t *testing.T) {
	t.Parallel()

	for _, s := range []string{`plain`, `has "quotes"`, `back\slash`, `both \"mixed\"`, ``} {
		if got := unquote(quote(s)); got != s {
			t.Errorf("unquote(quote(%q)) = %q", s, got)
		}
	}
	if got := unquote("bare"); got != "bare" {
		t.Errorf("unquote(bare) = %q", got)
	}
}

func TestFindRepoRoot(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module example.test\n")
	nested := filepath.Join(root, "cmd", "deep")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := findRepoRoot(nested)
	if err != nil {
		t.Fatal(err)
	}
	if got != root {
		t.Errorf("findRepoRoot = %q, want %q", got, root)
	}

	if _, err := findRepoRoot(t.TempDir()); err == nil {
		t.Error("findRepoRoot outside any module: want error")
	}
}

// TestNewThenIndex is the whole workflow in-process: mint, read back, index,
// check, then prove the check catches a stale router.
func TestNewThenIndex(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	var stdout, stderr bytes.Buffer

	status := run([]string{"-C", root, "new", "The queue is bounded: 2 000 records", "-topics", "queue, ordering"}, &stdout, &stderr)
	if status != 0 {
		t.Fatalf("new: status %d, stderr %q", status, stderr.String())
	}
	if !strings.Contains(stdout.String(), "cite as:  (ADR 20") {
		t.Errorf("new: stdout = %q", stdout.String())
	}

	adrs, err := readADRs(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(adrs) != 1 {
		t.Fatalf("readADRs: %d decisions, want 1", len(adrs))
	}
	got := adrs[0]
	if got.Title != "The queue is bounded: 2 000 records" || got.Slug != "the-queue-is-bounded" {
		t.Errorf("readADRs: %+v", got)
	}
	if strings.Join(got.Topics, ",") != "queue,ordering" {
		t.Errorf("topics = %v", got.Topics)
	}
	if got.File != fileNameFor(got.ID, got.Slug) {
		t.Errorf("file = %q, want %q", got.File, fileNameFor(got.ID, got.Slug))
	}

	// A fresh router is stale by definition.
	stdout.Reset()
	stderr.Reset()
	if status := run([]string{"-C", root, "index", "-check"}, &stdout, &stderr); status != 1 {
		t.Fatalf("index -check before index: status %d, want 1 (stderr %q)", status, stderr.String())
	}
	if !strings.Contains(stderr.String(), "is stale") {
		t.Errorf("index -check: stderr = %q", stderr.String())
	}

	stdout.Reset()
	if status := run([]string{"-C", root, "index"}, &stdout, &stderr); status != 0 {
		t.Fatalf("index: status %d, stderr %q", status, stderr.String())
	}
	router := readFile(t, filepath.Join(root, routerPath))
	if !strings.Contains(router, "| ["+got.ID+"](decisions/"+got.File+") | The queue is bounded: 2 000 records | queue, ordering |") {
		t.Errorf("router row missing:\n%s", router)
	}
	if strings.Contains(router, "decisions)") {
		t.Error("router carries a count line; every line must be append-only for merge=union")
	}

	stdout.Reset()
	if status := run([]string{"-C", root, "index", "-check"}, &stdout, &stderr); status != 0 {
		t.Fatalf("index -check after index: status %d", status)
	}

	// A second ADR without re-indexing is what the pre-commit hook exists to catch.
	if status := run([]string{"-C", root, "new", "Another decision"}, &stdout, &stderr); status != 0 {
		t.Fatalf("second new: status %d, stderr %q", status, stderr.String())
	}
	if status := run([]string{"-C", root, "index", "-check"}, &stdout, &stderr); status != 1 {
		t.Errorf("index -check with an unindexed ADR: status %d, want 1", status)
	}
}

func TestReadADRsRejectsMalformedFiles(t *testing.T) {
	t.Parallel()

	const good = "---\nid: \"2026-09.k3f9\"\nslug: good\ntitle: \"Good\"\ndate: 2026-09-21\ntopics: [a, b]\n---\n\n# ADR 2026-09.k3f9 — Good\n\nbody\n"

	tests := []struct {
		name    string
		file    string
		content string
		wantErr string
	}{
		{"valid", "2026-09-k3f9-good.md", good, ""},
		{"no frontmatter", "2026-09-k3f9-good.md", "# ADR\n", "no frontmatter block"},
		{"unterminated", "2026-09-k3f9-good.md", "---\nid: x\n", "unterminated frontmatter"},
		{"missing key", "2026-09-k3f9-good.md", strings.Replace(good, "topics: [a, b]\n", "", 1), `missing frontmatter key "topics"`},
		{"typo in key", "2026-09-k3f9-good.md", strings.Replace(good, "topics:", "topic:", 1), `missing frontmatter key "topics"`},
		{"bad id", "2026-09-k0f9-good.md", strings.ReplaceAll(good, "k3f9", "k0f9"), "is not a valid ADR id"},
		{"filename disagrees", "2026-09-k3f9-other.md", good, "filename should be 2026-09-k3f9-good.md"},
		{"bad date", "2026-09-k3f9-good.md", strings.Replace(good, "2026-09-21", "21/09/2026", 1), "is not YYYY-MM-DD"},
		{"heading disagrees", "2026-09-k3f9-good.md", strings.Replace(good, "# ADR 2026-09.k3f9 — Good", "# ADR 2026-09.k3f9 — Renamed", 1), "expected heading"},
		{"topics not a list", "2026-09-k3f9-good.md", strings.Replace(good, "[a, b]", "a, b", 1), "topics must be an inline list"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			root := t.TempDir()
			writeFile(t, filepath.Join(root, decisionsDir, tt.file), tt.content)

			_, err := readADRs(root)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case tt.wantErr != "" && err == nil:
				t.Errorf("want error containing %q, got nil", tt.wantErr)
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
				t.Errorf("error = %q, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestReadADRsRejectsDuplicateIDs(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	for _, slug := range []string{"one", "two"} {
		content := "---\nid: \"2026-09.k3f9\"\nslug: " + slug + "\ntitle: \"T\"\ndate: 2026-09-21\ntopics: []\n---\n\n# ADR 2026-09.k3f9 — T\n"
		writeFile(t, filepath.Join(root, decisionsDir, "2026-09-k3f9-"+slug+".md"), content)
	}
	_, err := readADRs(root)
	if err == nil || !strings.Contains(err.Error(), "duplicate ADR id") {
		t.Errorf("err = %v, want duplicate id", err)
	}
}

func TestReadADRsRequiresTheDirectory(t *testing.T) {
	t.Parallel()

	if _, err := readADRs(t.TempDir()); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("err = %v, want 'does not exist'", err)
	}
}

func TestRenderEscapesPipes(t *testing.T) {
	t.Parallel()

	out := render([]adr{{ID: "2026-09.k3f9", Title: "a | b", File: "f.md", Topics: []string{"x"}}})
	if !strings.Contains(out, `| a \| b |`) {
		t.Errorf("render did not escape the pipe:\n%s", out)
	}
}

func TestRunUsage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		args   []string
		status int
		stderr string
	}{
		{"no command", []string{"-C", "/nonexistent"}, 2, "usage: adr"},
		{"unknown command", []string{"-C", "/nonexistent", "frobnicate"}, 2, `unknown command "frobnicate"`},
		{"new without title", []string{"-C", "/nonexistent", "new"}, 2, `usage: adr new`},
		{"index with args", []string{"-C", "/nonexistent", "index", "extra"}, 2, `usage: adr index`},
		{"index on a missing tree", []string{"-C", "/nonexistent", "index"}, 1, "does not exist"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer
			if got := run(tt.args, &stdout, &stderr); got != tt.status {
				t.Errorf("status = %d, want %d (stderr %q)", got, tt.status, stderr.String())
			}
			if !strings.Contains(stderr.String(), tt.stderr) {
				t.Errorf("stderr = %q, want substring %q", stderr.String(), tt.stderr)
			}
		})
	}

	var stdout, stderr bytes.Buffer
	if got := run([]string{"-C", "/nonexistent", "help"}, &stdout, &stderr); got != 0 || !strings.Contains(stdout.String(), "usage: adr") {
		t.Errorf("help: status %d, stdout %q", got, stdout.String())
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
