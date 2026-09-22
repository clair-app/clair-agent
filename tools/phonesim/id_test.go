package main

import (
	"encoding/base64"
	"fmt"
)

// decodeID turns a relay-minted pairing id into the payload field.
func decodeID(id string) ([16]byte, error) {
	var out [16]byte
	raw, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil || len(raw) != 16 {
		return out, fmt.Errorf("pairing id %q is not 16 bytes", id)
	}
	copy(out[:], raw)
	return out, nil
}
