package presence

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// console reads the session's last input through GetLastInputInfo: every
// keyboard or mouse event on this desktop, not only the terminal's, because
// a ConPTY has no node whose access time could be read. A session without a
// desktop (a service, an SSH login) reports nothing.
type console struct {
	lastInput *windows.LazyProc
	tickCount *windows.LazyProc
}

// lastInputInfo is the Win32 LASTINPUTINFO structure.
type lastInputInfo struct {
	size uint32
	tick uint32
}

func host() Sampler {
	user32 := windows.NewLazySystemDLL("user32.dll")
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	return console{lastInput: user32.NewProc("GetLastInputInfo"), tickCount: kernel32.NewProc("GetTickCount")}
}

// Sample compares the last input's tick with the current one; both are
// 32-bit millisecond counters, so the subtraction survives their wrap.
func (c console) Sample() Sample {
	var info lastInputInfo
	info.size = uint32(unsafe.Sizeof(info))
	ok, _, _ := c.lastInput.Call(uintptr(unsafe.Pointer(&info))) //nolint:gosec // GetLastInputInfo fills the struct it is handed a pointer to
	if ok == 0 || info.tick == 0 {
		return Sample{}
	}
	now, _, _ := c.tickCount.Call()
	idle := time.Duration(uint32(now)-info.tick) * time.Millisecond //nolint:gosec // both counters are 32-bit by contract
	return Sample{Idle: idle, Known: true, Source: "console"}
}
