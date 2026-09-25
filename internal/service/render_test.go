package service

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"
)

const testSID = "S-1-5-21-1004336348-1177238915-682003330-1001"

func testEnv(home string, env map[string]string) Env {
	return Env{
		Getenv: func(k string) string { return env[k] },
		Home:   home,
		UID:    501,
		SID:    testSID,
	}
}

// The specs each golden is rendered from: what `clair service install`
// builds on a plain machine, and one whose paths and values need every
// escape the format has.
var renderCases = []struct {
	golden string
	goos   string
	home   string
	spec   Spec
}{
	{
		golden: "clair.service", goos: "linux", home: "/home/jane",
		spec: Spec{
			Exe:  "/home/jane/.local/bin/clair",
			Args: []string{"daemon", "-config-dir", "/home/jane/.config/clair"},
			Env:  []string{"CLAUDE_CONFIG_DIR=/home/jane/.claude-work", "HTTPS_PROXY=http://proxy.corp:3128"},
		},
	},
	{
		golden: "clair-escaped.service", goos: "linux", home: "/home/Jane Doe",
		spec: Spec{
			Exe:  `/home/Jane Doe/bin/clair "dev"`,
			Args: []string{"daemon", "-config-dir", `/home/Jane Doe/.config/100%$HOME\clair`, "-relay-ca", "/etc/ssl/corp-ca.pem"},
			Env:  []string{`HTTPS_PROXY=http://user:p%40ss$word@proxy:3128`, "NO_PROXY=localhost,.corp"},
		},
	},
	{
		golden: "app.claircode.clair.plist", goos: "darwin", home: "/Users/jane",
		spec: Spec{
			Exe:  "/Users/jane/.local/bin/clair",
			Args: []string{"daemon", "-config-dir", "/Users/jane/Library/Application Support/clair", "-log-file", "/Users/jane/Library/Logs/clair/daemon.log"},
			Env:  []string{"HTTPS_PROXY=http://proxy.corp:3128"},
		},
	},
	{
		golden: "app.claircode.clair-escaped.plist", goos: "darwin", home: "/Users/J&J <dev>",
		spec: Spec{
			Exe:  "/Users/J&J <dev>/bin/clair",
			Args: []string{"daemon", "-config-dir", "/Users/J&J <dev>/Library/Application Support/clair"},
		},
	},
	{
		golden: "clair-task.xml", goos: "windows", home: `C:\Users\jane`,
		spec: Spec{
			Exe:  `C:\Users\jane\AppData\Local\Programs\clair\clair.exe`,
			Args: []string{"daemon", "-config-dir", `C:\Users\jane\AppData\Roaming\clair`, "-log-file", `C:\Users\jane\AppData\Local\clair\daemon.log`},
			Env:  []string{"HTTPS_PROXY=http://proxy.corp:3128"},
		},
	},
	{
		golden: "clair-task-escaped.xml", goos: "windows", home: `C:\Users\Jane Doe`,
		spec: Spec{
			Exe:  `C:\Users\Jane Doe\bin\clair.exe`,
			Args: []string{"daemon", "-config-dir", `C:\Users\Jane Doe\R&D <x>\`, "-relay-ca", `C:\ca\say "hi".pem`},
		},
	},
}

func TestRenderMatchesTheGoldens(t *testing.T) {
	t.Parallel()

	for _, tc := range renderCases {
		t.Run(tc.golden, func(t *testing.T) {
			t.Parallel()

			m, err := ForOS(tc.goos, testEnv(tc.home, nil))
			if err != nil {
				t.Fatalf("ForOS(%s): %v", tc.goos, err)
			}
			got, err := m.Render(tc.spec)
			if err != nil {
				t.Fatalf("Render: %v", err)
			}
			want, err := os.ReadFile(filepath.Join("testdata", tc.golden))
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("Render differs from testdata/%s:\n--- got\n%s\n--- want\n%s", tc.golden, got, want)
			}
		})
	}
}

func TestSystemdRefusesALineBreak(t *testing.T) {
	t.Parallel()

	m := newSystemd(testEnv("/home/jane", nil))
	for _, spec := range []Spec{
		{Exe: "/bin/clair", Args: []string{"daemon", "-config-dir", "/a\nb"}},
		{Exe: "/bin/clair", Env: []string{"HTTPS_PROXY=http://a\r\nInjected=1"}},
	} {
		if _, err := m.Render(spec); err == nil {
			t.Errorf("Render(%q) succeeded, want a refusal", spec)
		}
	}
}

func TestWindowsArgRoundTripsThroughCommandLineToArgv(t *testing.T) {
	t.Parallel()

	for arg, want := range map[string]string{
		"":                            `""`,
		"daemon":                      "daemon",
		`C:\Users\jane\clair.exe`:     `C:\Users\jane\clair.exe`,
		`C:\Users\Jane Doe\clair`:     `"C:\Users\Jane Doe\clair"`,
		`C:\Users\Jane Doe\`:          `"C:\Users\Jane Doe\\"`,
		`say "hi"`:                    `"say \"hi\""`,
		`a\"b`:                        `a\\\"b`,
		"tab\there":                   "\"tab\there\"",
		`C:\dir with space\\`:         `"C:\dir with space\\\\"`,
		`C:\no-space\trailing\`:       `C:\no-space\trailing\`,
		`C:\no-space\quote"\` + `x`:   `C:\no-space\quote\"\x`,
		`C:\a b\quote"\` + `\"end`:    `"C:\a b\quote\"\\\\\"end"`,
		`C:\Users\J&J <dev>\clair`:    `"C:\Users\J&J <dev>\clair"`,
		`%SystemRoot%\System32\x.exe`: `%SystemRoot%\System32\x.exe`,
	} {
		if got := windowsArg(arg); got != want {
			t.Errorf("windowsArg(%q) = %s, want %s", arg, got, want)
			continue
		}
		if back := commandLineToArgv(windowsArg(arg)); len(back) != 1 || back[0] != arg {
			t.Errorf("CommandLineToArgv(windowsArg(%q)) = %q, want it back", arg, back)
		}
	}
}

// commandLineToArgv is the parsing rule CommandLineToArgvW documents, so
// the quoting is checked against the reader, not only against literals.
func commandLineToArgv(s string) []string {
	var args []string
	var cur strings.Builder
	inQuotes, have := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\':
			n := 0
			for i < len(s) && s[i] == '\\' {
				n++
				i++
			}
			if i < len(s) && s[i] == '"' {
				cur.WriteString(strings.Repeat(`\`, n/2))
				if n%2 == 1 {
					cur.WriteByte('"')
				} else {
					inQuotes = !inQuotes
				}
			} else {
				cur.WriteString(strings.Repeat(`\`, n))
				i--
			}
			have = true
		case c == '"':
			inQuotes = !inQuotes
			have = true
		case (c == ' ' || c == '\t') && !inQuotes:
			if have {
				args = append(args, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteByte(c)
			have = true
		}
	}
	if have {
		args = append(args, cur.String())
	}
	return args
}

func TestTaskXMLIsWrittenAsUTF16WithABOM(t *testing.T) {
	t.Parallel()

	text := []byte("<?xml?>\n<Task>J&J — ok</Task>\n")
	enc := utf16LE(text)
	if !bytes.HasPrefix(enc, []byte{0xFF, 0xFE}) {
		t.Fatalf("encoded prefix = %x, want the little-endian BOM fffe", enc[:2])
	}
	units := make([]uint16, 0, len(enc)/2-1)
	for i := 2; i < len(enc); i += 2 {
		units = append(units, binary.LittleEndian.Uint16(enc[i:]))
	}
	if got := string(utf16.Decode(units)); got != string(text) {
		t.Errorf("decoded = %q, want %q", got, text)
	}
}

func TestForOS(t *testing.T) {
	t.Parallel()

	for goos, kind := range map[string]string{"linux": "systemd user unit", "darwin": "launchd agent", "windows": "scheduled task"} {
		m, err := ForOS(goos, testEnv("/home/jane", nil))
		if err != nil || m.Kind() != kind {
			t.Errorf("ForOS(%s) = %v, %v; want a %s", goos, m, err, kind)
		}
	}
	if _, err := ForOS("plan9", testEnv("/home/jane", nil)); !errors.Is(err, ErrUnsupported) {
		t.Errorf("ForOS(plan9): %v, want ErrUnsupported", err)
	}
}

func TestPaths(t *testing.T) {
	t.Parallel()

	home := filepath.FromSlash("/home/jane")
	tests := []struct {
		goos          string
		env           map[string]string
		path, logFile string
	}{
		{goos: "linux", path: filepath.Join(home, ".config", "systemd", "user", "clair.service")},
		{goos: "linux", env: map[string]string{"XDG_CONFIG_HOME": "/xdg"}, path: filepath.FromSlash("/xdg/systemd/user/clair.service")},
		// A LaunchAgent's paths are POSIX paths, whatever host renders them.
		{goos: "darwin", path: path.Join(home, "Library", "LaunchAgents", "app.claircode.clair.plist"), logFile: path.Join(home, "Library", "Logs", "clair", "daemon.log")},
		{goos: "windows", path: `\clair`, logFile: filepath.Join(home, "AppData", "Local", "clair", "daemon.log")},
		{goos: "windows", env: map[string]string{"LOCALAPPDATA": "/lad"}, path: `\clair`, logFile: filepath.FromSlash("/lad/clair/daemon.log")},
	}
	for _, tc := range tests {
		m, err := ForOS(tc.goos, testEnv(home, tc.env))
		if err != nil {
			t.Fatal(err)
		}
		if m.Path() != tc.path || m.LogFile() != tc.logFile {
			t.Errorf("%s %v: path %q, log %q; want %q, %q", tc.goos, tc.env, m.Path(), m.LogFile(), tc.path, tc.logFile)
		}
	}
}

func TestCaptureEnvTakesOnlyWhatTheDaemonNeeds(t *testing.T) {
	t.Parallel()

	env := map[string]string{
		"HTTPS_PROXY":       "http://proxy:3128",
		"no_proxy":          "localhost",
		"CLAUDE_CONFIG_DIR": "/home/jane/.claude-work",
		"CLAIR_CONFIG_DIR":  "/elsewhere",
		"PATH":              "/usr/bin",
		"SSL_CERT_FILE":     "",
	}
	got := CaptureEnv(func(k string) string { return env[k] })
	want := []string{"CLAUDE_CONFIG_DIR=/home/jane/.claude-work", "HTTPS_PROXY=http://proxy:3128", "no_proxy=localhost"}
	if !slices.Equal(got, want) {
		t.Errorf("CaptureEnv = %q, want %q", got, want)
	}
}

func TestResolveExe(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(filepath.Join(bin, "go-build123"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(bin, "clair")
	if err := os.WriteFile(target, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "clair-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	built := filepath.Join(bin, "go-build123", "clair")
	if err := os.WriteFile(built, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	notTemp := filepath.Join(root, "elsewhere")

	if got, err := ResolveExe(link, notTemp); err != nil || got != mustEval(t, target) {
		t.Errorf("ResolveExe(link) = %q, %v; want the link's target %q", got, err, target)
	}
	if _, err := ResolveExe(built, notTemp); err == nil {
		t.Error("ResolveExe accepted a go run build")
	}
	if _, err := ResolveExe(target, root); err == nil {
		t.Error("ResolveExe accepted a binary under the temporary directory")
	}
	if _, err := ResolveExe(filepath.Join(root, "missing"), notTemp); err == nil {
		t.Error("ResolveExe accepted a missing binary")
	}
}

func mustEval(t *testing.T, path string) string {
	t.Helper()
	p, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
