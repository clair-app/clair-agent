package pairing

import (
	"bufio"
	"context"
	"errors"
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

// tty is the controlling terminal: in reads the answer, out shows the
// prompt. They are one file except on Windows.
type tty struct {
	in, out *os.File
}

// OpenTerminal opens the controlling terminal, or returns nil when there is
// none (a service, CI, a pipe on both ends).
func OpenTerminal() Terminal {
	in, out, err := openTTY()
	if err != nil {
		return nil
	}
	t := &tty{in: in, out: out}
	if !term.IsTerminal(int(in.Fd())) || !term.IsTerminal(int(out.Fd())) {
		_ = t.Close()
		return nil
	}
	return t
}

// Confirm implements Terminal. The read runs on its own goroutine so a
// cancelled context returns without waiting for a key.
func (t *tty) Confirm(ctx context.Context, prompt string, def bool) (bool, error) {
	hint := "[y/N]"
	if def {
		hint = "[Y/n]"
	}
	if _, err := fmt.Fprintf(t.out, "%s %s ", prompt, hint); err != nil {
		return false, fmt.Errorf("pairing: write terminal: %w", err)
	}
	type line struct {
		text string
		err  error
	}
	got := make(chan line, 1)
	go func() {
		text, err := bufio.NewReader(t.in).ReadString('\n')
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
func (t *tty) Close() error {
	err := t.in.Close()
	if t.out != t.in {
		err = errors.Join(err, t.out.Close())
	}
	return err
}

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
