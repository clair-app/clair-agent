package presence

import (
	"errors"
	"os"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestLocalSeesAKeystroke pins the kernel behaviour the package rests on:
// a slave's access time moves when the process on it reads input. It opens
// a pseudo-terminal pair, feeds one line through it and expects the host's
// sampler to report an idle time of seconds, not the age of the newest
// other terminal.
func TestLocalSeesAKeystroke(t *testing.T) {
	t.Parallel()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
		t.Skipf("no pseudo-terminals here: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = master.Close() }()
	if unlockErr := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); unlockErr != nil {
		t.Fatalf("unlock the pty: %v", unlockErr)
	}
	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatalf("pty number: %v", err)
	}
	slave, err := os.OpenFile("/dev/pts/"+strconv.Itoa(n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = slave.Close() }()

	if _, err := master.WriteString("x\n"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	if _, err := slave.Read(buf); err != nil {
		t.Fatal(err)
	}
	s := Local().Sample()
	// tty_update_time rounds to 8 s; give the slow machine some room too.
	if !s.Known || s.Source != "pty" || s.Idle > 20*time.Second {
		t.Errorf("Sample() after a read on /dev/pts/%d = %+v, want a fresh pty reading", n, s)
	}
}
