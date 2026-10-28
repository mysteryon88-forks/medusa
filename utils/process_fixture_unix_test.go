//go:build !windows

package utils

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fixtureEndpoint = *os.File

func newFixtureEndpoint(handle uintptr) fixtureEndpoint {
	return os.NewFile(handle, "fixture-endpoint")
}

func inheritFixtureEndpoints(c *exec.Cmd, files []fixtureEndpoint) (func(), error) {
	return inheritProcessFixture(c, files)
}

func inheritProcessFixture(c *exec.Cmd, files []*os.File) (func(), error) {
	var handles []string
	for _, file := range files {
		c.ExtraFiles = append(c.ExtraFiles, file)
		handles = append(handles, strconv.Itoa(2+len(c.ExtraFiles)))
	}
	c.Env = append(c.Env, "MEDUSA_FIXTURE_HANDLES="+strings.Join(handles, ","))
	return func() {}, nil
}

func TestFixtureLifetimeEscaped(t *testing.T) {
	dir := t.TempDir()
	f := newProcessFixtureLifetime(t, "fixture-escape-root", dir)
	f.start(func(c *exec.Cmd) error { return c.Run() })
	f.waitAck(t)
	t.Logf("escaped descendant PID %s", waitProcessFile(t, dir+string(os.PathSeparator)+"grandchild"))
	select {
	case <-f.done:
	case <-time.After(5 * time.Second):
		t.Fatal("escaped root did not exit")
	}
	if err := f.waitDescendantEOF(25 * time.Millisecond); !errors.Is(err, errFixturePending) {
		t.Fatalf("escaped lifetime is not pending: %v", err)
	}
	if err := f.shutdown(); err != nil {
		t.Fatal(err)
	}
}

func TestFixtureLifetimeSelfInterrupt(t *testing.T) {
	f := newProcessFixtureLifetime(t, "fixture-single", t.TempDir())
	f.start(func(c *exec.Cmd) error { return c.Run() })
	f.waitAck(t)
	if _, err := f.control.Write([]byte{'I'}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.done:
	case <-time.After(5 * time.Second):
		t.Fatal("self interrupt was lost")
	}
	if !fixtureSIGINT(f.runErr) {
		t.Fatalf("self interrupt did not terminate by SIGINT: %v", f.runErr)
	}
	if err := f.shutdown(); err != nil {
		t.Fatal(err)
	}
}

func fixtureSIGINT(err error) bool {
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		return false
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	return ok && status.Signaled() && status.Signal() == syscall.SIGINT
}

func TestFixtureLifetimeProtocolExit(t *testing.T) {
	f := newProcessFixtureLifetime(t, "fixture-protocol-error", t.TempDir())
	f.start(func(c *exec.Cmd) error { return c.Run() })
	if err := f.waitReleased(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	var exit *exec.ExitError
	if !errors.As(f.runErr, &exit) || exit.ExitCode() != 98 {
		t.Fatalf("wrong protocol error fixture exit: %v", f.runErr)
	}
	if fixtureSIGINT(f.runErr) {
		t.Fatal("protocol exit 98 was accepted as SIGINT")
	}
	if err := f.shutdown(); err != nil {
		t.Fatal(err)
	}
}
