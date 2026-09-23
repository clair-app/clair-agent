package claudecfg

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"claircode.app/clair-agent/internal/ojson"
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
)

// ourStatusLine matches a statusLine command that runs this binary's
// statusline subcommand, however the path was quoted.
var ourStatusLine = regexp.MustCompile(`clair(\.exe)?['"]?\s+statusline\b`)

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

// IsOurStatusLine reports whether a statusLine command is the agent's, or
// the LAN installer's shell shim.
func IsOurStatusLine(command string) bool {
	return ourStatusLine.MatchString(command) || strings.Contains(command, legacyShim)
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
	// Backup is the path settings.json was moved to, or "" when there was none.
	Backup string
	// StatusLine is wrapped, kept (not a command; left alone), restored,
	// removed or none.
	StatusLine string
}

// Install merges a hooks block and wraps the statusLine.
func (in Installer) Install(hooks *ojson.Object) (Report, error) {
	settings, err := in.load()
	if err != nil {
		return Report{}, err
	}
	mergeHooks(settings, hooks)
	var report Report
	report.StatusLine, err = in.wrapStatusLine(settings)
	if err != nil {
		return Report{}, err
	}
	report.Backup, err = in.save(settings)
	return report, err
}

// Uninstall removes every Clair hook group and restores the statusLine.
func (in Installer) Uninstall() (Report, error) {
	settings, err := in.load()
	if err != nil {
		return Report{}, err
	}
	mergeHooks(settings, ojson.NewObject())
	var report Report
	report.StatusLine = in.unwrapStatusLine(settings)
	report.Backup, err = in.save(settings)
	return report, err
}

// load reads settings.json; a missing file is an empty object, anything but
// an object is refused.
func (in Installer) load() (*ojson.Object, error) {
	data, err := os.ReadFile(in.SettingsPath)
	if errors.Is(err, fs.ErrNotExist) {
		return ojson.NewObject(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("claudecfg: read %s: %w", in.SettingsPath, err)
	}
	v, err := ojson.ParseBytes(data)
	if err != nil {
		return nil, fmt.Errorf("claudecfg: %s: %w", in.SettingsPath, err)
	}
	obj := ojson.AsObject(v)
	if obj == nil {
		return nil, fmt.Errorf("claudecfg: %s is not a JSON object; not touching it", in.SettingsPath)
	}
	return obj, nil
}

// save backs the old file up by rename, then writes the new one atomically.
func (in Installer) save(settings *ojson.Object) (string, error) {
	now := in.Now
	if now == nil {
		now = time.Now
	}
	backup := ""
	if _, err := os.Stat(in.SettingsPath); err == nil {
		backup = in.SettingsPath + ".bak-" + now().Format("20060102150405")
		for i := 1; ; i++ {
			if _, err := os.Stat(backup); errors.Is(err, fs.ErrNotExist) {
				break
			}
			backup = fmt.Sprintf("%s.bak-%s-%d", in.SettingsPath, now().Format("20060102150405"), i)
		}
		if err := os.Rename(in.SettingsPath, backup); err != nil {
			return "", fmt.Errorf("claudecfg: back up %s: %w", in.SettingsPath, err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(in.SettingsPath), 0o755); err != nil { //nolint:gosec // Claude Code's own directory; its default mode
		return "", fmt.Errorf("claudecfg: create %s: %w", filepath.Dir(in.SettingsPath), err)
	}
	data, err := ojson.Marshal(settings, indent)
	if err != nil {
		return "", fmt.Errorf("claudecfg: encode settings: %w", err)
	}
	tmp := in.SettingsPath + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o644); err != nil { //nolint:gosec // settings.json is not a secret; Claude Code writes it 0644 too
		return "", fmt.Errorf("claudecfg: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, in.SettingsPath); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("claudecfg: replace %s: %w", in.SettingsPath, err)
	}
	return backup, nil
}

func (in Installer) originalPath() string {
	return filepath.Join(filepath.Dir(in.SettingsPath), originalFile)
}

// loadOriginal reads the saved statusLine; nil when absent or unreadable.
func (in Installer) loadOriginal() ojson.Value {
	data, err := os.ReadFile(in.originalPath())
	if err != nil {
		return nil
	}
	v, err := ojson.ParseBytes(data)
	if err != nil {
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
	if IsOurStatusLine(commandOf(status)) {
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
	if err := os.WriteFile(in.originalPath(), append(saved, '\n'), 0o644); err != nil { //nolint:gosec // beside settings.json, same mode
		return "", fmt.Errorf("claudecfg: write %s: %w", in.originalPath(), err)
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
	if IsOurStatusLine(commandOf(status)) {
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

// InstallSnippet substitutes, validates and installs a phone snippet.
func (s SnippetInstaller) InstallSnippet(snippet json.RawMessage) error {
	hooks, err := ValidateSnippet(Substitute(snippet, s.Port, s.Token, s.Host, s.ClairExe), SnippetConfig{
		BaseURL: s.BaseURL, Token: s.Token, Host: s.Host, ClairExe: s.ClairExe,
	})
	if err != nil {
		return err
	}
	_, err = s.Install(hooks)
	return err
}

// Uninstall removes the hooks and restores the statusLine.
func (s SnippetInstaller) Uninstall() error {
	_, err := s.Installer.Uninstall()
	return err
}
