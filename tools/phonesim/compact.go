package main

import (
	"io"

	"claircode.app/clair-agent/internal/ojson"
)

// writeCompact renders an ojson value without whitespace.
func writeCompact(w io.Writer, v ojson.Value) error {
	data, err := ojson.Marshal(v, "")
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}
