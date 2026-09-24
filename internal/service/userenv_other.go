//go:build !windows

package service

// MissingFromUserEnv is Windows' concern only: systemd and launchd carry the
// environment in the unit and the plist.
func MissingFromUserEnv([]string) []string { return nil }
