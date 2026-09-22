package pairing

import (
	"fmt"
	"io"
	"strings"

	"rsc.io/qr"
)

// QRMode selects how the code is drawn.
type QRMode string

// The modes of --qr.
const (
	// QRUnicode draws two modules per character with ▀ ▄ █: a 41-module code
	// is 21 lines, which fits an 80×24 terminal, over SSH too (RELAY.md §6.1).
	QRUnicode QRMode = "unicode"
	// QRASCII draws one module per character with # and space, for a
	// terminal without UTF-8.
	QRASCII QRMode = "ascii"
	// QRNone prints the URL only, to be typed into the app.
	QRNone QRMode = "none"
)

// qrLevel is the error-correction level: L keeps the default payload at
// version 6, and a phone reading a screen has contrast to spare.
const qrLevel = qr.L

// qrQuiet is the quiet zone in modules on each side.
const qrQuiet = 2

// RenderQR draws text as a QR code. With invert, dark modules are drawn as
// blocks, for a light terminal; the default draws light modules as blocks,
// which is what a dark terminal wants. Scanners read both. It returns the
// code's size in modules.
func RenderQR(w io.Writer, text string, mode QRMode, invert bool) (int, error) {
	code, err := qr.Encode(text, qrLevel)
	if err != nil {
		return 0, fmt.Errorf("pairing: encode QR: %w", err)
	}
	if mode == QRNone {
		return code.Size, nil
	}
	// dark reports whether a module (including the quiet zone) is dark, then
	// flips it for the terminal's background.
	dark := func(x, y int) bool {
		d := x >= 0 && y >= 0 && x < code.Size && y < code.Size && code.Black(x, y)
		return d != !invert
	}
	var b strings.Builder
	switch mode {
	case QRASCII:
		for y := -qrQuiet; y < code.Size+qrQuiet; y++ {
			for x := -qrQuiet; x < code.Size+qrQuiet; x++ {
				if dark(x, y) {
					b.WriteString("##")
				} else {
					b.WriteString("  ")
				}
			}
			b.WriteByte('\n')
		}
	default:
		for y := -qrQuiet; y < code.Size+qrQuiet; y += 2 {
			for x := -qrQuiet; x < code.Size+qrQuiet; x++ {
				top, bottom := dark(x, y), y+1 < code.Size+qrQuiet && dark(x, y+1)
				switch {
				case top && bottom:
					b.WriteRune('█')
				case top:
					b.WriteRune('▀')
				case bottom:
					b.WriteRune('▄')
				default:
					b.WriteByte(' ')
				}
			}
			b.WriteByte('\n')
		}
	}
	if _, err := io.WriteString(w, b.String()); err != nil {
		return 0, fmt.Errorf("pairing: write QR: %w", err)
	}
	return code.Size, nil
}
