package service

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

// MissingFromUserEnv returns the KEY=VALUE pairs of env that the user's
// persistent environment (HKCU\Environment) does not hold with the same
// value. A Scheduled Task starts with that environment, not this shell's,
// so a variable set only here never reaches the daemon.
func MissingFromUserEnv(env []string) []string {
	k, err := registry.OpenKey(registry.CURRENT_USER, "Environment", registry.QUERY_VALUE)
	if err != nil {
		return env
	}
	defer func() { _ = k.Close() }()
	var missing []string
	for _, kv := range env {
		key, want, _ := strings.Cut(kv, "=")
		got, _, err := k.GetStringValue(key)
		if err != nil || got != want {
			missing = append(missing, kv)
		}
	}
	return missing
}
