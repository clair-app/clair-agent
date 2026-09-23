// Package claudecfg edits Claude Code's settings.json the way the phone's
// installer does (RELAY.md §6.5, the phone's setup.sh): it renders the hooks
// block, substitutes a phone-supplied snippet's placeholders and rebuilds it,
// merges either into settings.json without touching anything else, wraps the
// user's statusLine in `clair statusline`, and undoes all of it on unpair.
package claudecfg

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"claircode.app/clair-agent/internal/ojson"
	"claircode.app/clair-agent/internal/record"
)

// What the phone's HooksSnippet pins.
const (
	// Marker is the substring of every URL (or command) the installer wrote;
	// it is how a later install recognises its own entries.
	Marker = record.Marker
	// The phone's defaults: a prompt stays answerable for a day, an event
	// costs at most 2 s when nothing is listening.
	permissionTimeoutSec = 86400
	eventTimeoutSec      = 2
	// Claude Code shows this while a decide hook runs; the ellipsis is
	// U+2026, as the phone writes it.
	statusPermission = "Clair: also on your watch…"
	// The placeholders a phone snippet carries (§6.5), the host one the LAN
	// installer substituted, and the one that names this binary for the
	// SessionStart command hook.
	PlaceholderPort  = "__PORT__"
	PlaceholderToken = "__TOKEN__"
	PlaceholderHost  = "__CLAIR_HOST__"
	PlaceholderExe   = "__CLAIR_EXE__"
)

// ErrSnippetRejected is a phone snippet that would install anything but the
// agent's own http hooks.
var ErrSnippetRejected = errors.New("claudecfg: snippet rejected")

// eventHooks are the fire-and-forget events and their matchers, in the
// phone's order.
var eventHooks = []struct{ event, matcher string }{
	{"PreToolUse", ""},
	{"PostToolUse", ""},
	{"PostToolUseFailure", ""},
	{"UserPromptSubmit", ""},
	{"Stop", ""},
	{"Notification", "idle_prompt"},
	{"PreCompact", ""},
	{"SessionEnd", ""},
}

// SnippetConfig shapes the built-in hooks block.
type SnippetConfig struct {
	// BaseURL is the agent's loopback origin, e.g. http://127.0.0.1:7317.
	BaseURL string
	// Token is the hook bearer.
	Token string
	// Host is the X-Clair-Host value; empty omits the header.
	Host string
	// PermissionTimeoutSec and EventTimeoutSec override the defaults when positive.
	PermissionTimeoutSec int
	EventTimeoutSec      int
	// IncludeSessionStart adds the SessionStart hook.
	IncludeSessionStart bool
	// ClairExe is this binary's path. Claude Code (2.1.278) refuses http hooks
	// for SessionStart, so it is a `command` hook running `<ClairExe>
	// hook-event`; empty renders an http hook instead.
	ClairExe string
}

// HookEventCommand is the SessionStart command hook: this binary forwarding
// its stdin to the loopback listener, the way the LAN installer's curl did.
// The path is an argument so the command carries Marker, the one rule every
// installer (this one and the phone's) uses to recognise its own entries.
func HookEventCommand(exe string) string {
	return quoteForShell(exe) + " hook-event " + record.PathEvent
}

// RenderHooks builds `{"hooks": {...}}` exactly as the phone's HooksSnippet
// does, with SessionStart as a command hook running this binary.
func RenderHooks(c SnippetConfig) *ojson.Object {
	permission := c.PermissionTimeoutSec
	if permission <= 0 {
		permission = permissionTimeoutSec
	}
	event := c.EventTimeoutSec
	if event <= 0 {
		event = eventTimeoutSec
	}
	hooks := ojson.NewObject()
	hooks.Set("PermissionRequest", group("", c.httpHook(decidePath(permission), permission, statusPermission)))
	for _, e := range eventHooks {
		hooks.Set(e.event, group(e.matcher, c.httpHook(record.PathEvent, event, "")))
	}
	if c.IncludeSessionStart {
		if c.ClairExe != "" {
			hooks.Set("SessionStart", group("", commandHook(c.ClairExe)))
		} else {
			hooks.Set("SessionStart", group("", c.httpHook(record.PathEvent, event, "")))
		}
	}
	out := ojson.NewObject()
	out.Set("hooks", hooks)
	return out
}

// httpHook is the one shape of the agent's http hooks, whoever asked for
// it: the bearer and the host header are always the agent's own, and there
// is never an allowedEnvVars (ADR 2026-09.ut2g). A timeout of 0 is omitted,
// as is an empty status.
func (c SnippetConfig) httpHook(path string, timeout int, status string) *ojson.Object {
	h := ojson.NewObject()
	h.Set("type", "http")
	h.Set("url", strings.TrimSuffix(c.BaseURL, "/")+path)
	headers := ojson.NewObject()
	headers.Set("Authorization", "Bearer "+c.Token)
	if c.Host != "" {
		headers.Set(record.HostHeader, c.Host)
	}
	h.Set("headers", headers)
	if timeout > 0 {
		h.Set("timeout", json.Number(strconv.Itoa(timeout)))
	}
	if status != "" {
		h.Set("statusMessage", status)
	}
	return h
}

func commandHook(exe string) *ojson.Object {
	cmd := ojson.NewObject()
	cmd.Set("type", "command")
	cmd.Set("command", HookEventCommand(exe))
	return cmd
}

func decidePath(timeout int) string {
	return record.PathDecide + "?" + record.TimeoutQuery + "=" + strconv.Itoa(timeout)
}

func group(matcher string, hooks ...ojson.Value) []ojson.Value {
	g := ojson.NewObject()
	if matcher != "" {
		g.Set("matcher", matcher)
	}
	g.Set("hooks", hooks)
	return []ojson.Value{g}
}

// Substitute fills a phone snippet's placeholders; exe is quoted for the
// platform shell, as HookEventCommand does.
func Substitute(snippet []byte, port int, token, host, exe string) []byte {
	r := strings.NewReplacer(PlaceholderPort, strconv.Itoa(port), PlaceholderToken, token, PlaceholderHost, host, PlaceholderExe, quoteForShell(exe))
	return []byte(r.Replace(string(snippet)))
}

// ValidateSnippet parses a substituted snippet and rebuilds it from the
// agent's own template (ADR 2026-09.3gre, 2026-09.ut2g). It is accepted only
// if it is `{"hooks": {...}}` whose every hook is one of:
//
//   - for PermissionRequest, an http hook to the decide endpoint, with an
//     optional `?timeout=<seconds>`;
//   - for any other event, an http hook to the event endpoint, or the one
//     `command` hook that runs this binary's hook-event.
//
// Of a phone's hook only the endpoint, a timeout and a statusMessage are
// kept, and of a group only its matcher; the headers are the agent's own
// (c.Token, c.Host) and nothing else a phone sent — allowedEnvVars above all,
// which would have Claude Code copy its environment into a header the agent
// forwards — reaches settings.json. A compromised phone shapes the agent's
// own hooks and nothing else, and cannot route an event it is only told
// about to the endpoint whose answer Claude Code obeys.
func ValidateSnippet(snippet []byte, c SnippetConfig) (*ojson.Object, error) {
	if len(snippet) > maxSnippetBytes {
		return nil, fmt.Errorf("%w: %d bytes, over %d", ErrSnippetRejected, len(snippet), maxSnippetBytes)
	}
	v, err := ojson.ParseBytes(snippet)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSnippetRejected, err)
	}
	top := ojson.AsObject(v)
	if top == nil {
		return nil, fmt.Errorf("%w: not an object", ErrSnippetRejected)
	}
	hooksVal, ok := top.Get("hooks")
	hooks := ojson.AsObject(hooksVal)
	if !ok || hooks == nil {
		return nil, fmt.Errorf("%w: no hooks object", ErrSnippetRejected)
	}
	rebuilt := ojson.NewObject()
	for _, event := range hooks.Keys() {
		groupsVal, _ := hooks.Get(event)
		groups := ojson.AsArray(groupsVal)
		if len(groups) == 0 {
			return nil, fmt.Errorf("%w: %s is not a non-empty array", ErrSnippetRejected, event)
		}
		out := make([]ojson.Value, 0, len(groups))
		for _, g := range groups {
			grp, err := c.rebuildGroup(event, g)
			if err != nil {
				return nil, err
			}
			out = append(out, grp)
		}
		rebuilt.Set(event, out)
	}
	res := ojson.NewObject()
	res.Set("hooks", rebuilt)
	return res, nil
}

func (c SnippetConfig) rebuildGroup(event string, g ojson.Value) (*ojson.Object, error) {
	grp := ojson.AsObject(g)
	if grp == nil {
		return nil, fmt.Errorf("%w: %s has a non-object group", ErrSnippetRejected, event)
	}
	out := ojson.NewObject()
	if m, ok := grp.Get("matcher"); ok {
		if _, isString := m.(string); !isString {
			return nil, fmt.Errorf("%w: %s has a matcher that is not a string", ErrSnippetRejected, event)
		}
		out.Set("matcher", m)
	}
	innerVal, _ := grp.Get("hooks")
	inner := ojson.AsArray(innerVal)
	if len(inner) == 0 {
		return nil, fmt.Errorf("%w: %s has a group whose hooks are not a non-empty array", ErrSnippetRejected, event)
	}
	hooks := make([]ojson.Value, 0, len(inner))
	for _, h := range inner {
		hook, err := c.rebuildHook(event, ojson.AsObject(h))
		if err != nil {
			return nil, err
		}
		hooks = append(hooks, hook)
	}
	out.Set("hooks", hooks)
	return out, nil
}

func (c SnippetConfig) rebuildHook(event string, hook *ojson.Object) (*ojson.Object, error) {
	if hook == nil {
		return nil, fmt.Errorf("%w: %s has a non-object hook", ErrSnippetRejected, event)
	}
	decide := event == "PermissionRequest"
	endpoint := record.PathEvent
	if decide {
		endpoint = record.PathDecide
	}
	typ, _ := hook.Get("type")
	switch typ {
	case "http":
		url, _ := hook.Get("url")
		path, err := c.endpointPath(ojson.AsString(url), endpoint, decide)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrSnippetRejected, event, err)
		}
		timeout := 0
		if t, ok := hook.Get("timeout"); ok {
			if timeout, ok = seconds(t); !ok {
				return nil, fmt.Errorf("%w: %s has a timeout that is not 1 to %d seconds", ErrSnippetRejected, event, maxTimeoutSec)
			}
		}
		status, _ := hook.Get("statusMessage")
		return c.httpHook(path, timeout, ojson.AsString(status)), nil
	case "command":
		cmd, _ := hook.Get("command")
		if decide || c.ClairExe == "" || ojson.AsString(cmd) != HookEventCommand(c.ClairExe) {
			return nil, fmt.Errorf("%w: %s has a command hook other than %q", ErrSnippetRejected, event, HookEventCommand(c.ClairExe))
		}
		return commandHook(c.ClairExe), nil
	default:
		return nil, fmt.Errorf("%w: %s has a hook that is neither http nor this binary's hook-event", ErrSnippetRejected, event)
	}
}

// maxSnippetBytes bounds a phone snippet before it is parsed: the phone's
// own is under 4 KiB, and an envelope could carry a thousand times that.
const maxSnippetBytes = 64 << 10

// maxTimeoutSec bounds a snippet's timeouts: the phone's own maximum
// (HooksConfig.MAX_PERMISSION_TIMEOUT_SEC) and record.MaxDecideTimeout.
const maxTimeoutSec = permissionTimeoutSec

// endpointPath checks a phone hook's URL against the one endpoint its event
// may reach and returns the path to render: the endpoint, plus for a decide
// the timeout query re-rendered from its number.
func (c SnippetConfig) endpointPath(url, endpoint string, decide bool) (string, error) {
	rest, ok := strings.CutPrefix(url, strings.TrimSuffix(c.BaseURL, "/"))
	if !ok {
		return "", fmt.Errorf("url is not on %s", c.BaseURL)
	}
	path, query, hasQuery := strings.Cut(rest, "?")
	if path != endpoint {
		return "", fmt.Errorf("url is not %s", endpoint)
	}
	if !hasQuery {
		return path, nil
	}
	raw, ok := strings.CutPrefix(query, record.TimeoutQuery+"=")
	if !decide || !ok {
		return "", fmt.Errorf("url has a query other than %s=<seconds> on %s", record.TimeoutQuery, record.PathDecide)
	}
	secs, ok := seconds(json.Number(raw))
	if !ok {
		return "", fmt.Errorf("url's %s is not 1 to %d seconds", record.TimeoutQuery, maxTimeoutSec)
	}
	return decidePath(secs), nil
}

// seconds reads a timeout: a JSON integer from 1 to maxTimeoutSec.
func seconds(v ojson.Value) (int, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	secs, err := strconv.Atoi(string(n))
	if err != nil || secs < 1 || secs > maxTimeoutSec {
		return 0, false
	}
	return secs, true
}

// isClair reports whether a hook group was written by a Clair installer:
// any of its hooks has a url or a command containing Marker.
func isClair(group ojson.Value) bool {
	g := ojson.AsObject(group)
	if g == nil {
		return false
	}
	inner, _ := g.Get("hooks")
	for _, h := range ojson.AsArray(inner) {
		hook := ojson.AsObject(h)
		if hook == nil {
			continue
		}
		url, _ := hook.Get("url")
		cmd, _ := hook.Get("command")
		if strings.Contains(ojson.AsString(url), Marker) || strings.Contains(ojson.AsString(cmd), Marker) {
			return true
		}
	}
	return false
}

// mergeHooks removes every Clair group from settings' hooks and appends the
// new ones, event by event, as setup.sh does: foreign groups and the order
// of events the user already had are preserved.
func mergeHooks(settings, fresh *ojson.Object) {
	existingVal, _ := settings.Get("hooks")
	existing := ojson.AsObject(existingVal)
	if existing == nil {
		existing = ojson.NewObject()
	}
	for _, event := range existing.Keys() {
		groupsVal, _ := existing.Get(event)
		var kept []ojson.Value
		for _, g := range ojson.AsArray(groupsVal) {
			if !isClair(g) {
				kept = append(kept, g)
			}
		}
		if len(kept) == 0 {
			existing.Delete(event)
		} else {
			existing.Set(event, kept)
		}
	}
	freshVal, _ := fresh.Get("hooks")
	if freshHooks := ojson.AsObject(freshVal); freshHooks != nil {
		for _, event := range freshHooks.Keys() {
			add, _ := freshHooks.Get(event)
			have, _ := existing.Get(event)
			existing.Set(event, append(ojson.AsArray(have), ojson.AsArray(add)...))
		}
	}
	if existing.Len() == 0 {
		settings.Delete("hooks")
	} else {
		settings.Set("hooks", existing)
	}
}
