// Package claudecfg edits Claude Code's settings.json the way the phone's
// installer does (RELAY.md §6.5, the phone's setup.sh): it renders the hooks
// block, substitutes a phone-supplied snippet's placeholders and checks it,
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
	base := strings.TrimSuffix(c.BaseURL, "/")
	permission := c.PermissionTimeoutSec
	if permission <= 0 {
		permission = permissionTimeoutSec
	}
	event := c.EventTimeoutSec
	if event <= 0 {
		event = eventTimeoutSec
	}
	httpHook := func(path string, timeout int, status string) *ojson.Object {
		h := ojson.NewObject()
		h.Set("type", "http")
		h.Set("url", base+path)
		headers := ojson.NewObject()
		headers.Set("Authorization", "Bearer "+c.Token)
		if c.Host != "" {
			headers.Set(record.HostHeader, c.Host)
		}
		h.Set("headers", headers)
		h.Set("timeout", json.Number(strconv.Itoa(timeout)))
		if status != "" {
			h.Set("statusMessage", status)
		}
		return h
	}
	group := func(matcher string, hook *ojson.Object) []ojson.Value {
		g := ojson.NewObject()
		if matcher != "" {
			g.Set("matcher", matcher)
		}
		g.Set("hooks", []ojson.Value{hook})
		return []ojson.Value{g}
	}
	hooks := ojson.NewObject()
	hooks.Set("PermissionRequest", group("", httpHook(record.PathDecide+"?"+record.TimeoutQuery+"="+strconv.Itoa(permission), permission, statusPermission)))
	for _, e := range eventHooks {
		hooks.Set(e.event, group(e.matcher, httpHook(record.PathEvent, event, "")))
	}
	if c.IncludeSessionStart {
		if c.ClairExe != "" {
			cmd := ojson.NewObject()
			cmd.Set("type", "command")
			cmd.Set("command", HookEventCommand(c.ClairExe))
			hooks.Set("SessionStart", group("", cmd))
		} else {
			hooks.Set("SessionStart", group("", httpHook(record.PathEvent, event, "")))
		}
	}
	out := ojson.NewObject()
	out.Set("hooks", hooks)
	return out
}

// Substitute fills a phone snippet's placeholders; exe is quoted for the
// platform shell, as HookEventCommand does.
func Substitute(snippet []byte, port int, token, host, exe string) []byte {
	r := strings.NewReplacer(PlaceholderPort, strconv.Itoa(port), PlaceholderToken, token, PlaceholderHost, host, PlaceholderExe, quoteForShell(exe))
	return []byte(r.Replace(string(snippet)))
}

// ValidateSnippet parses a substituted snippet and accepts it only if it is
// `{"hooks": {...}}` whose every hook is `type: "http"` with a URL under
// baseURL + Marker, or the one `command` hook that runs this binary's
// hook-event: the phone shapes the agent's own hooks and nothing else (a
// compromised phone must not install `command` hooks on the host).
func ValidateSnippet(snippet []byte, baseURL, exe string) (*ojson.Object, error) {
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
	prefix := strings.TrimSuffix(baseURL, "/") + Marker
	ownCommand := HookEventCommand(exe)
	for _, event := range hooks.Keys() {
		groupsVal, _ := hooks.Get(event)
		groups := ojson.AsArray(groupsVal)
		if groups == nil {
			return nil, fmt.Errorf("%w: %s is not an array", ErrSnippetRejected, event)
		}
		for _, g := range groups {
			group := ojson.AsObject(g)
			if group == nil {
				return nil, fmt.Errorf("%w: %s has a non-object group", ErrSnippetRejected, event)
			}
			innerVal, _ := group.Get("hooks")
			for _, h := range ojson.AsArray(innerVal) {
				hook := ojson.AsObject(h)
				if hook == nil {
					return nil, fmt.Errorf("%w: %s has a non-object hook", ErrSnippetRejected, event)
				}
				typ, _ := hook.Get("type")
				url, _ := hook.Get("url")
				cmd, _ := hook.Get("command")
				switch {
				case ojson.AsString(typ) == "http" && strings.HasPrefix(ojson.AsString(url), prefix):
				case ojson.AsString(typ) == "command" && exe != "" && ojson.AsString(cmd) == ownCommand:
				default:
					return nil, fmt.Errorf("%w: %s has a hook that is neither an http hook to %s nor %q", ErrSnippetRejected, event, prefix, ownCommand)
				}
			}
		}
	}
	out := ojson.NewObject()
	out.Set("hooks", hooks)
	return out, nil
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
