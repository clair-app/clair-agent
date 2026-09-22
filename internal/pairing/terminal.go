package pairing

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// Terminal asks the user a yes/no question. It is the controlling terminal,
// not stdin, so `curl … | sh` and a piped stdout still get a real answer
// (RELAY.md §6.3); nil means headless.
type Terminal interface {
	// Confirm prints the prompt and reads one line; empty is the default.
	Confirm(ctx context.Context, prompt string, def bool) (bool, error)
}

// tty is the controlling terminal.
type tty struct {
	f *os.File
}

// OpenTerminal opens the controlling terminal, or returns nil when there is
// none (a service, CI, a pipe on both ends).
func OpenTerminal() Terminal {
	f, err := openTTY()
	if err != nil {
		return nil
	}
	if !term.IsTerminal(int(f.Fd())) {
		_ = f.Close()
		return nil
	}
	return &tty{f: f}
}

// Confirm implements Terminal. The read runs on its own goroutine so a
// cancelled context returns without waiting for a key.
func (t *tty) Confirm(ctx context.Context, prompt string, def bool) (bool, error) {
	hint := "[y/N]"
	if def {
		hint = "[Y/n]"
	}
	fmt.Fprintf(t.f, "%s %s ", prompt, hint)
	type line struct {
		text string
		err  error
	}
	got := make(chan line, 1)
	go func() {
		text, err := bufio.NewReader(t.f).ReadString('\n')
		got <- line{text: text, err: err}
	}()
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case l := <-got:
		if l.err != nil && l.text == "" {
			return false, fmt.Errorf("pairing: read terminal: %w", l.err)
		}
		return parseYesNo(l.text, def), nil
	}
}

// Close releases the terminal.
func (t *tty) Close() error { return t.f.Close() }

func parseYesNo(text string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(text)) {
	case "y", "yes":
		return true
	case "n", "no":
		return false
	default:
		return def
	}
}
