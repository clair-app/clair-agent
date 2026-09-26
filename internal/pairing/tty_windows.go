//go:build windows

package pairing

import "os"

// openTTY opens the console whatever stdin and stdout are. CONIN$ is only
// the input buffer: a write to it fails, so a prompt written there never
// shows and `clair pair` sits at an unseen question. The prompt goes to
// CONOUT$.
func openTTY() (in, out *os.File, err error) {
	in, err = os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}
	out, err = os.OpenFile("CONOUT$", os.O_RDWR, 0)
	if err != nil {
		_ = in.Close()
		return nil, nil, err
	}
	return in, out, nil
}
