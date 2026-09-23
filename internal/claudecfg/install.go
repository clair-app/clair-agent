package claudecfg

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"claircode.app/clair-agent/internal/ojson"
	"claircode.app/clair-agent/internal/state"
)

const (
	// The user's own statusLine is kept beside settings.json under the name
	// the LAN installer used, so a LAN install migrates; legacyShim is the
	// shell shim that installer wrote.
	originalFile = "clair-statusline.sh.original.json"
	legacyShim   = "clair-statusline.sh"
	// EnvConfigDir is Claude Code's own override of its config directory.
	EnvConfigDir = "CLAUDE_CONFIG_DIR"
	settingsFile = "settings.json"
	indent       = "  "
	// Every rewrite holds an advisory lock on settings.json plus lockSuffix;
	// the lock file itself is never removed.
	lockSuffix = ".lock"
	// A settings.json the agent creates gets newFileMode, as it holds the
	// hook bearer. An existing file keeps its own mode.
	newFileMode = 0o600
)

// SettingsPath is `${CLAUDE_CONFIG_DIR:-$HOME/.claude}/settings.json`.
func SettingsPath(getenv func(string) string, home func() (string, error)) (string, error) {
	if dir := getenv(EnvConfigDir); dir != "" {
		return filepath.Join(dir, settingsFile), nil
	}
	h, err := home()
	if err != nil {
		return "", fmt.Errorf("claudecfg: no home directory: %w", err)
	}
	return filepath.Join(h, ".claude", settingsFile), nil
}

// IsOurStatusLine reports whether a statusLine command is a Clair agent's,
// by its shape alone: `<clair binary> statusline`, where the binary is named
// clair or clair-<anything> (a release build is clair-<os>-<arch>), or the
// LAN installer's shell shim. Installer.isOurs also knows this binary's own
// path, whatever it is named.
func IsOurStatusLine(command string) bool {
	if strings.Contains(command, legacyShim) {
		return true
	}
	exe, rest := splitCommand(command)
	return rest == "statusline" && isClairName(exe)
}

// runsStatuslineOf reports whether command is `<exe> statusline` for the
// same file as exe, however it was spelt or linked.
func runsStatuslineOf(command, exe string) bool {
	if exe == "" {
		return false
	}
	first, rest := splitCommand(command)
	if rest != "statusline" || first == "" {
		return false
	}
	a, err := os.Stat(first) //nolint:gosec // only compared with our own executable, never opened
	if err != nil {
		return false
	}
	b, err := os.Stat(exe)
	return err == nil && os.SameFile(a, b)
}

// isClairName reports whether a path's base name is clair's: `clair`, or
// `clair` then one of `-`, `_` or `.` and anything, with or without `.exe`.
func isClairName(path string) bool {
	base := path[strings.LastIndexAny(path, `/\`)+1:]
	base = strings.TrimSuffix(strings.TrimSuffix(base, ".exe"), ".EXE")
	if base == "clair" {
		return true
	}
	rest, ok := strings.CutPrefix(base, "clair")
	return ok && rest != "" && strings.ContainsRune("-_.", rune(rest[0]))
}

// splitCommand splits a command into its first shell word, unquoted, and the
// rest, trimmed. It reads the quoting quoteForShell writes on either platform
// — '…' runs (a quote inside is '"'"'), "…" runs — and nothing fancier; an
// unbalanced quote gives no word.
func splitCommand(command string) (first, rest string) {
	s := strings.TrimLeft(command, " \t")
	var b strings.Builder
	for i := 0; i < len(s); {
		switch c := s[i]; c {
		case ' ', '\t':
			return b.String(), strings.TrimSpace(s[i:])
		case '\'', '"':
			j := strings.IndexByte(s[i+1:], c)
			if j < 0 {
				return "", ""
			}
			b.WriteString(s[i+1 : i+1+j])
			i += j + 2
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String(), ""
}

// Installer edits one settings.json.
type Installer struct {
	// SettingsPath is the file to edit.
	SettingsPath string
	// ClairExe is the absolute path of this binary, for the statusLine command.
	ClairExe string
	// Now stamps backups; nil means time.Now.
	Now func() time.Time
	// Stderr receives the one warning the installer may print; nil discards.
	Stderr io.Writer
}

// Report says what an install or uninstall did.
type Report struct {
	// Backup is the path settings.json was copied to, or "" when there was none.
	Backup string
	// StatusLine is wrapped, kept (not a command; left alone), restored,
	// removed or none.
	StatusLine string
	// Unchanged is an edit that found settings.json already as it would have
	// written it: nothing was written and nothing backed up.
	Unchanged bool
}

// Install merges a hooks block and wraps the statusLine.
func (in Installer) Install(hooks *ojson.Object) (Report, error) {
	return in.edit(func(settings *ojson.Object) (string, error) {
		mergeHooks(settings, hooks)
		return in.wrapStatusLine(settings)
	})
}

// Uninstall removes every Clair hook group and restores the statusLine.
func (in Installer) Uninstall() (Report, error) {
	return in.edit(func(settings *ojson.Object) (string, error) {
		mergeHooks(settings, ojson.NewObject())
		return in.unwrapStatusLine(settings), nil
	})
}

// current is settings.json as read: the file a symlink at SettingsPath
// resolves to, its bytes and mode, and whether it existed.
type current struct {
	target string
	data   []byte
	mode   fs.FileMode
	exists bool
}

// edit runs one read-modify-write of settings.json under the lock beside
// it, so concurrent installs — the daemon's snippets, `clair pair`, `clair
// unpair` — never lose each other's changes or the user's (ADR 2026-09.y34x).
// An edit that changes nothing writes nothing: the phone may send the same
// snippet again, and each would otherwise leave a backup (ADR 2026-09.bckr).
func (in Installer) edit(change func(*ojson.Object) (string, error)) (Report, error) {
	unlock, err := in.lock()
	if err != nil {
		return Report{}, err
	}
	defer unlock()
	cur, settings, err := in.load()
	if err != nil {
		return Report{}, err
	}
	var report Report
	if report.StatusLine, err = change(settings); err != nil {
		return Report{}, err
	}
	if cur.exists {
		if before, perr := ojson.ParseBytes(cur.data); perr == nil && ojson.Equal(before, settings) {
			report.Unchanged = true
			return report, nil
		}
	}
	report.Backup, err = in.save(cur, settings)
	return report, err
}

// lock takes the advisory lock beside settings.json, creating its directory
// with Claude Code's default mode if need be.
func (in Installer) lock() (func(), error) {
	if err := os.MkdirAll(filepath.Dir(in.SettingsPath), 0o755); err != nil { //nolint:gosec // Claude Code's own directory; its default mode
		return nil, fmt.Errorf("claudecfg: create %s: %w", filepath.Dir(in.SettingsPath), err)
	}
	path := in.SettingsPath + lockSuffix
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("claudecfg: open %s: %w", path, err)
	}
	if err := lockFile(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("claudecfg: lock %s: %w", path, err)
	}
	return func() {
		_ = unlockFile(f)
		_ = f.Close()
	}, nil
}

// load reads settings.json, through a symlink; a missing file is an empty
// object, anything but an object is refused.
func (in Installer) load() (current, *ojson.Object, error) {
	cur := current{target: in.SettingsPath, mode: newFileMode}
	if target, err := filepath.EvalSymlinks(in.SettingsPath); err == nil {
		cur.target = target
	} else if !errors.Is(err, fs.ErrNotExist) {
		return cur, nil, fmt.Errorf("claudecfg: resolve %s: %w", in.SettingsPath, err)
	}
	data, err := os.ReadFile(cur.target)
	if errors.Is(err, fs.ErrNotExist) {
		return cur, ojson.NewObject(), nil
	}
	if err != nil {
		return cur, nil, fmt.Errorf("claudecfg: read %s: %w", in.SettingsPath, err)
	}
	info, err := os.Stat(cur.target)
	if err != nil {
		return cur, nil, fmt.Errorf("claudecfg: stat %s: %w", in.SettingsPath, err)
	}
	cur.data, cur.mode, cur.exists = data, info.Mode().Perm(), true
	v, err := ojson.ParseBytes(data)
	if err != nil {
		return cur, nil, fmt.Errorf("claudecfg: %s: %w", in.SettingsPath, err)
	}
	obj := ojson.AsObject(v)
	if obj == nil {
		return cur, nil, fmt.Errorf("claudecfg: %s is not a JSON object; not touching it", in.SettingsPath)
	}
	return cur, obj, nil
}

// save backs the old file up by copy — so settings.json never goes missing,
// even for a moment — then replaces it atomically with its own mode kept.
func (in Installer) save(cur current, settings *ojson.Object) (string, error) {
	data, err := ojson.Marshal(settings, indent)
	if err != nil {
		return "", fmt.Errorf("claudecfg: encode settings: %w", err)
	}
	backup := ""
	if cur.exists {
		if backup, err = in.backup(cur); err != nil {
			return "", err
		}
	}
	if err := state.WriteFile(cur.target, append(data, '\n'), cur.mode); err != nil {
		return "", fmt.Errorf("claudecfg: %w", err)
	}
	return backup, nil
}

// backup writes the old bytes to settings.json.bak-<stamp>[-n], created
// exclusively with the old file's mode.
func (in Installer) backup(cur current) (string, error) {
	now := in.Now
	if now == nil {
		now = time.Now
	}
	stamp := in.SettingsPath + ".bak-" + now().Format("20060102150405")
	for i := 0; ; i++ {
		path := stamp
		if i > 0 {
			path = fmt.Sprintf("%s-%d", stamp, i)
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, cur.mode)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("claudecfg: back up %s: %w", in.SettingsPath, err)
		}
		_, err = f.Write(cur.data)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			_ = os.Remove(path)
			return "", fmt.Errorf("claudecfg: back up %s: %w", in.SettingsPath, err)
		}
		return path, nil
	}
}

// isOurs reports whether a statusLine command is the agent's: by shape
// (IsOurStatusLine), or because it runs this very binary's statusline under
// any name.
func (in Installer) isOurs(command string) bool {
	return IsOurStatusLine(command) || runsStatuslineOf(command, in.ClairExe)
}

func (in Installer) originalPath() string {
	return filepath.Join(filepath.Dir(in.SettingsPath), originalFile)
}

// loadOriginal reads the saved statusLine; nil when absent, unreadable, or
// itself a Clair statusline — running that would have the statusline run
// itself, without end (AG-6).
func (in Installer) loadOriginal() ojson.Value {
	data, err := os.ReadFile(in.originalPath())
	if err != nil {
		return nil
	}
	v, err := ojson.ParseBytes(data)
	if err != nil {
		return nil
	}
	if in.isOurs(commandOf(v)) {
		return nil
	}
	return v
}

func commandOf(status ojson.Value) string {
	obj := ojson.AsObject(status)
	if obj == nil {
		return ""
	}
	cmd, _ := obj.Get("command")
	return ojson.AsString(cmd)
}

// wrapStatusLine points statusLine at `clair statusline`, keeping the user's
// own statusLine in the original file so the shim can run it and unpair can
// put it back. A statusLine that is not a command is left alone.
func (in Installer) wrapStatusLine(settings *ojson.Object) (string, error) {
	status, _ := settings.Get("statusLine")
	var original ojson.Value
	if in.isOurs(commandOf(status)) {
		original = in.loadOriginal()
	} else {
		original = status
	}
	if obj := ojson.AsObject(original); obj != nil {
		typ, ok := obj.Get("type")
		if ok && ojson.AsString(typ) != "command" {
			if in.Stderr != nil {
				fmt.Fprintln(in.Stderr, "Clair: your statusLine is not a command; leaving it alone (no usage on the watch).")
			}
			return "kept", nil
		}
	}
	saved, err := ojson.Marshal(original, "")
	if err != nil {
		return "", fmt.Errorf("claudecfg: encode the original statusLine: %w", err)
	}
	saved = append(saved, '\n')
	if have, rerr := os.ReadFile(in.originalPath()); rerr != nil || !bytes.Equal(have, saved) {
		if err := state.WriteFile(in.originalPath(), saved, newFileMode); err != nil {
			return "", fmt.Errorf("claudecfg: %w", err)
		}
	}
	wrapped := ojson.NewObject()
	wrapped.Set("type", "command")
	wrapped.Set("command", StatusLineCommand(in.ClairExe))
	if obj := ojson.AsObject(original); obj != nil {
		if padding, ok := obj.Get("padding"); ok {
			wrapped.Set("padding", padding)
		}
	}
	settings.Set("statusLine", wrapped)
	_ = os.Remove(filepath.Join(filepath.Dir(in.SettingsPath), legacyShim))
	return "wrapped", nil
}

// unwrapStatusLine restores the user's statusLine and removes the files.
func (in Installer) unwrapStatusLine(settings *ojson.Object) string {
	result := "none"
	status, _ := settings.Get("statusLine")
	if in.isOurs(commandOf(status)) {
		if original := in.loadOriginal(); original == nil {
			settings.Delete("statusLine")
			result = "removed"
		} else {
			settings.Set("statusLine", original)
			result = "restored"
		}
	}
	_ = os.Remove(in.originalPath())
	_ = os.Remove(filepath.Join(filepath.Dir(in.SettingsPath), legacyShim))
	return result
}

// SnippetInstaller is the daemon's Installer: it fills a phone snippet's
// placeholders with this host's values, checks it and installs it.
type SnippetInstaller struct {
	Installer

	// BaseURL, Port, Token and Host are the loopback endpoint and the header.
	BaseURL string
	Port    int
	Token   string
	Host    string
}

// SnippetReport says what installing a phone snippet did.
type SnippetReport struct {
	Report

	// Dropped names the snippet's events the agent's template does not
	// know; they were left out.
	Dropped []string
	// Refused is why the phone's snippet was refused, when InstallAtPairing
	// wrote the built-in block in its place.
	Refused error
}

// Warnings says, as sentences for a person, where the install differs from
// what the phone asked for.
func (r SnippetReport) Warnings() []string {
	var out []string
	if r.Refused != nil {
		out = append(out, fmt.Sprintf("the phone's hooks were refused (%v); the built-in hooks were written instead", r.Refused))
	}
	if len(r.Dropped) > 0 {
		out = append(out, "the phone's hooks name events this agent does not hook, left out: "+eventList(r.Dropped))
	}
	return out
}

// eventList quotes phone-supplied event names for a message, bounded in
// number and length: a snippet may carry many, and long ones.
func eventList(names []string) string {
	const maxNames, maxLen = 5, 40
	quoted := make([]string, 0, min(len(names), maxNames)+1)
	for i, name := range names {
		if i == maxNames {
			quoted = append(quoted, fmt.Sprintf("and %d more", len(names)-maxNames))
			break
		}
		if len(name) > maxLen {
			name = name[:maxLen] + "…"
		}
		quoted = append(quoted, strconv.Quote(name))
	}
	return strings.Join(quoted, ", ")
}

func (s SnippetInstaller) config() SnippetConfig {
	return SnippetConfig{BaseURL: s.BaseURL, Token: s.Token, Host: s.Host, ClairExe: s.ClairExe}
}

// InstallSnippet substitutes, validates and installs a phone snippet. A
// refused one is ErrSnippetRejected and leaves settings.json as it was.
func (s SnippetInstaller) InstallSnippet(snippet json.RawMessage) (SnippetReport, error) {
	hooks, dropped, err := ValidateSnippet(Substitute(snippet, s.Port, s.Token, s.Host, s.ClairExe), s.config())
	if err != nil {
		return SnippetReport{}, err
	}
	report, err := s.Install(hooks)
	return SnippetReport{Report: report, Dropped: dropped}, err
}

// InstallDefault installs the built-in block: the phone's HooksSnippet with
// its defaults, SessionStart included.
func (s SnippetInstaller) InstallDefault() (Report, error) {
	c := s.config()
	c.IncludeSessionStart = true
	return s.Install(RenderHooks(c))
}

// InstallAtPairing installs what a new pair's hello asked for: the phone's
// snippet, or the built-in block when it sent none or its snippet is refused
// (ADR 2026-09.3gre, 2026-09.bckr), so a phone never leaves a new pair
// without hooks. An error means no hooks were written at all.
func (s SnippetInstaller) InstallAtPairing(snippet json.RawMessage) (SnippetReport, error) {
	if len(bytes.TrimSpace(snippet)) == 0 || string(bytes.TrimSpace(snippet)) == "null" {
		report, err := s.InstallDefault()
		return SnippetReport{Report: report}, err
	}
	report, err := s.InstallSnippet(snippet)
	if !errors.Is(err, ErrSnippetRejected) {
		return report, err
	}
	fallback, ferr := s.InstallDefault()
	return SnippetReport{Report: fallback, Refused: err}, ferr
}

// Uninstall removes the hooks and restores the statusLine.
func (s SnippetInstaller) Uninstall() error {
	_, err := s.Installer.Uninstall()
	return err
}
