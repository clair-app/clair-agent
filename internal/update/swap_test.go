package update

import (
	"errors"
	"io/fs"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

var (
	errDenied = errors.New("access denied")
	errBusy   = errors.New("sharing violation")
)

// windowsDir models what Windows does to a running executable: it can be
// renamed, but not replaced or deleted, and the running image follows its
// file through a rename. The busy counts make the next renames of a source
// fail as another process holding it would.
type windowsDir struct {
	files   map[string]string // path → content
	running map[string]bool   // content → a process runs it
	busy    map[string]int    // source path → renames still to refuse
	sleeps  int
}

func (w *windowsDir) ops() fileOps {
	return fileOps{
		rename: w.rename,
		remove: w.remove,
		sleep:  func(time.Duration) { w.sleeps++ },
		transient: func(err error) bool {
			return errors.Is(err, errBusy)
		},
	}
}

func (w *windowsDir) rename(oldpath, newpath string) error {
	if w.busy[oldpath] > 0 {
		w.busy[oldpath]--
		return errBusy
	}
	content, ok := w.files[oldpath]
	if !ok {
		return fs.ErrNotExist
	}
	if existing, ok := w.files[newpath]; ok && w.running[existing] {
		return errDenied
	}
	delete(w.files, oldpath)
	w.files[newpath] = content
	return nil
}

func (w *windowsDir) remove(path string) error {
	content, ok := w.files[path]
	if !ok {
		return fs.ErrNotExist
	}
	if w.running[content] {
		return errDenied
	}
	delete(w.files, path)
	return nil
}

func (w *windowsDir) names() []string {
	return slices.Sorted(maps.Keys(w.files))
}

func TestRenameAsideLikeWindows(t *testing.T) {
	t.Parallel()

	const target = `C:\clair\clair.exe`
	w := &windowsDir{
		files:   map[string]string{target: "v1", `C:\clair\.clair-update-1.exe`: "v2"},
		running: map[string]bool{"v1": true},
		busy:    map[string]int{`C:\clair\.clair-update-1.exe`: 2},
	}
	if err := renameAside(w.ops(), `C:\clair\.clair-update-1.exe`, target, `C:\clair\.clair-old-a.exe`); err != nil {
		t.Fatalf("first swap: %v", err)
	}
	if w.files[target] != "v2" || w.files[`C:\clair\.clair-old-a.exe`] != "v1" || w.sleeps != 2 {
		t.Fatalf("after the first swap: %v, %d sleeps; want v2 in place, the running v1 aside, 2 retries", w.files, w.sleeps)
	}

	// A second update before a restart: v1 still runs from its aside copy,
	// so the new aside needs a name of its own; v2 runs nowhere and goes.
	w.files[`C:\clair\.clair-update-2.exe`] = "v3"
	if err := renameAside(w.ops(), `C:\clair\.clair-update-2.exe`, target, `C:\clair\.clair-old-b.exe`); err != nil {
		t.Fatalf("second swap: %v", err)
	}
	want := []string{`C:\clair\.clair-old-a.exe`, target}
	if got := w.names(); !slices.Equal(got, want) || w.files[target] != "v3" {
		t.Fatalf("after the second swap: %v, want %v with v3 in place", w.files, want)
	}
}

func TestRenameAsideRollsBack(t *testing.T) {
	t.Parallel()

	const target = `C:\clair\clair.exe`
	tmp := `C:\clair\.clair-update-1.exe`
	w := &windowsDir{
		files:   map[string]string{target: "v1", tmp: "v2"},
		running: map[string]bool{"v1": true},
		busy:    map[string]int{tmp: swapRetries + 1},
	}
	err := renameAside(w.ops(), tmp, target, `C:\clair\.clair-old-a.exe`)
	if !errors.Is(err, errBusy) {
		t.Fatalf("renameAside = %v, want the busy error", err)
	}
	if w.files[target] != "v1" || len(w.files) != 2 {
		t.Fatalf("after the rollback: %v, want v1 back in place and the download left for the caller", w.files)
	}
}

func TestRenameAsideStopsOnHardErrors(t *testing.T) {
	t.Parallel()

	w := &windowsDir{files: map[string]string{`D:\tools\.clair-update-1.exe`: "v2"}, running: make(map[string]bool)}
	err := renameAside(w.ops(), `D:\tools\.clair-update-1.exe`, `D:\tools\clair.exe`, `D:\tools\.clair-old-a.exe`)
	if !errors.Is(err, fs.ErrNotExist) || w.sleeps != 0 {
		t.Fatalf("renameAside with no binary = %v after %d sleeps, want ErrNotExist at once", err, w.sleeps)
	}
}

func TestAsideName(t *testing.T) {
	t.Parallel()

	a, err := asideName(someExe(), strings.NewReader("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(filepath.Dir(someExe()), asidePrefix+"3031323334353637.exe"); a != want {
		t.Errorf("asideName = %q, want %q", a, want)
	}
	if _, err := asideName(someExe(), strings.NewReader("")); err == nil {
		t.Error("asideName without entropy succeeded")
	}
}
