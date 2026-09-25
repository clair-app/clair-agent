package update

import "crypto/ed25519"

// releaseKeyText are the public halves of the keys that sign releases, in
// standard base64: the primary, then a backup kept offline apart from it, so
// a lost or leaked primary is replaced by a release the backup signs. The
// private halves never touch a server; clair-web's `agent-release.mjs pin`
// signs with them and carries the same list (RELEASE_PUBLIC_KEYS).
func releaseKeyText() []string {
	return []string{
		"EfVkMOXX2VIz/T+yabekxn8yobHHZTuBrJx9ms3dYJ0=", // primary
		"yYvU5sXWz7y6CNo56gHmwsLKYrLni4XPbJbIv2SBAlY=", // backup, kept offline apart from the primary
	}
}

// ReleaseKeys returns the keys built into this agent.
func ReleaseKeys() []ed25519.PublicKey {
	texts := releaseKeyText()
	keys := make([]ed25519.PublicKey, 0, len(texts))
	for _, text := range texts {
		k, err := ParseKey(text)
		if err != nil {
			panic(err) // a constant this package's tests check
		}
		keys = append(keys, k)
	}
	return keys
}
