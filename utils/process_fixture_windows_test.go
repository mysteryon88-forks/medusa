package utils

import (
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

type fixtureEndpoint = *windowsFixtureEndpoint

type windowsFixtureEndpoint struct{ handle syscall.Handle }

// os.NewFile can block querying a pipe while another process is reading it.
func newFixtureEndpoint(handle uintptr) fixtureEndpoint {
	return &windowsFixtureEndpoint{handle: syscall.Handle(handle)}
}

func (f *windowsFixtureEndpoint) Fd() uintptr { return uintptr(f.handle) }

func (f *windowsFixtureEndpoint) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n, err := syscall.Read(f.handle, p)
	if n == 0 && err == nil {
		return 0, io.EOF
	}
	return n, err
}

func (f *windowsFixtureEndpoint) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n, err := syscall.Write(f.handle, p)
	if n < len(p) && err == nil {
		return n, io.ErrShortWrite
	}
	return n, err
}

func inheritProcessFixture(c *exec.Cmd, files []*os.File) (func(), error) {
	handles := make([]uintptr, 0, len(files))
	for _, file := range files {
		handles = append(handles, file.Fd())
	}
	return inheritFixtureHandles(c, handles)
}

func inheritFixtureEndpoints(c *exec.Cmd, files []fixtureEndpoint) (func(), error) {
	handles := make([]uintptr, 0, len(files))
	for _, file := range files {
		handles = append(handles, file.Fd())
	}
	return inheritFixtureHandles(c, handles)
}

func inheritFixtureHandles(c *exec.Cmd, files []uintptr) (func(), error) {
	var duplicates []windows.Handle
	closeDuplicates := func() {
		for _, h := range duplicates {
			_ = windows.CloseHandle(h)
		}
	}
	attr := syscall.SysProcAttr{HideWindow: true}
	if c.SysProcAttr != nil {
		attr = *c.SysProcAttr
	}
	var handles []string
	for _, handle := range files {
		var duplicate windows.Handle
		if err := windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(handle), windows.CurrentProcess(), &duplicate, 0, true, windows.DUPLICATE_SAME_ACCESS); err != nil {
			closeDuplicates()
			return nil, err
		}
		duplicates = append(duplicates, duplicate)
		attr.AdditionalInheritedHandles = append(attr.AdditionalInheritedHandles, syscall.Handle(duplicate))
		handles = append(handles, strconv.FormatUint(uint64(duplicate), 10))
	}
	c.SysProcAttr = &attr
	c.Env = append(c.Env, "MEDUSA_FIXTURE_HANDLES="+strings.Join(handles, ","))
	return closeDuplicates, nil
}

func TestWindowsFixtureEndpointPipe(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	r := newFixtureEndpoint(reader.Fd())
	w := newFixtureEndpoint(writer.Fd())
	if n, err := r.Read(nil); n != 0 || err != nil {
		t.Fatalf("empty read = %d, %v", n, err)
	}
	if n, err := w.Write(nil); n != 0 || err != nil {
		t.Fatalf("empty write = %d, %v", n, err)
	}
	if n, err := w.Write([]byte("x")); n != 1 || err != nil {
		t.Fatalf("write = %d, %v", n, err)
	}
	var data [1]byte
	if n, err := r.Read(data[:]); n != 1 || err != nil || data[0] != 'x' {
		t.Fatalf("read = %d, %v, %q", n, err, data)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if n, err := r.Read(data[:]); n != 0 || err != io.EOF {
		t.Fatalf("closed pipe read = %d, %v", n, err)
	}
}
