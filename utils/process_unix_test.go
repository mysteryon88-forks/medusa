//go:build !windows

package utils

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func escapeProcessFixture(directory string) {
	if _, err := syscall.Setsid(); err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "grandchild"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		panic(err)
	}
	select {}
}

func forkProcessFixture(directory string) {
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, syscall.SIGTERM)
	defer signal.Stop(interrupts)
	if err := os.WriteFile(filepath.Join(directory, "ready"), []byte("ready"), 0600); err != nil {
		panic(err)
	}
	<-interrupts
	child := processFixture("grandchild", directory)
	if err := startProcessFixtureChild(child); err != nil {
		panic(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "grandchild")); err == nil {
			os.Exit(7)
		}
		time.Sleep(time.Millisecond)
	}
}

func observedProcessFixture(t *testing.T, role string) (*exec.Cmd, <-chan commandExit, string) {
	t.Helper()
	dir := t.TempDir()
	f := newProcessFixtureLifetime(t, role, dir)
	observed, reap := make(chan commandExit, 1), make(chan struct{})
	started := make(chan struct{})
	var startErr error
	f.beforeJoin = func() { close(reap) }
	f.start(func(c *exec.Cmd) error {
		cleanup, err := startCommandTree(c)
		startErr = err
		close(started)
		if err != nil {
			return err
		}
		observerDone := make(chan struct{})
		go func() { observed <- observeCommandExit(c); close(observerDone) }()
		<-reap
		// The sole Wait stays after every group signal, including failure cleanup.
		cleanupErr := cleanup()
		waitErr := c.Wait()
		<-observerDone
		return errors.Join(cleanupErr, waitErr)
	})
	select {
	case <-started:
		require.NoError(t, startErr)
	case <-time.After(5 * time.Second):
		t.Fatal("observed fixture did not start")
	}
	f.waitAck(t)
	waitProcessFile(t, filepath.Join(dir, "ready"))
	return f.command, observed, dir
}

func TestProcessContextInspectionError(t *testing.T) {
	c, observed, _ := observedProcessFixture(t, "single")
	want := errors.New("injected process inspection failure")
	err := cleanupCommandGroup(c.Process.Pid, func(int) (bool, error) { return false, want })
	require.ErrorIs(t, err, want)
	select {
	case result := <-observed:
		require.NoError(t, result.err)
	case <-time.After(5 * time.Second):
		t.Fatal("inspection failure bypassed termination")
	}
}

func TestProcessContextForkOnTerm(t *testing.T) {
	c, observed, dir := observedProcessFixture(t, "fork-parent")
	first := true
	err := cleanupCommandGroup(c.Process.Pid, func(group int) (bool, error) {
		if first {
			first = false
			waitProcessFile(t, filepath.Join(dir, "grandchild"))
			// Model a stale negative scan while the TERM handler's new child lives.
			return false, nil
		}
		return commandGroupRunning(group)
	})
	require.NoError(t, err)
	pid, err := strconv.Atoi(string(waitProcessFile(t, filepath.Join(dir, "grandchild"))))
	require.NoError(t, err)
	require.True(t, fixtureProcessGone(pid), "TERM-handler child survived cleanup")
	select {
	case result := <-observed:
		require.NoError(t, result.err)
	case <-time.After(5 * time.Second):
		t.Fatal("forking root survived cleanup")
	}
}

func TestProcessContextEscapedPipe(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := newProcessFixtureLifetime(t, "escaped-root", dir)
	f.beforeJoin = cancel
	result := make(chan error, 1)
	f.start(func(c *exec.Cmd) error {
		_, _, _, err := RunCommandWithContext(ctx, c)
		result <- err
		return err
	})
	f.waitAck(t)
	pid, err := strconv.Atoi(string(waitProcessFile(t, filepath.Join(dir, "grandchild"))))
	require.NoError(t, err)
	select {
	case err := <-result:
		require.ErrorContains(t, err, "output drain exceeded")
		require.False(t, fixtureProcessGone(pid), "runner signaled a process outside its group")
		require.NoError(t, f.waitReleased(time.Second))
		require.ErrorIs(t, f.waitDescendantEOF(25*time.Millisecond), errFixturePending, "escaped fixture must retain its lifetime endpoint")
	case <-time.After(5 * time.Second):
		t.Fatal("escaped pipe held runner open")
	}
}

func TestProcessContextForeground(t *testing.T) {
	dir := t.TempDir()
	result := make(chan error, 1)
	f := newProcessFixtureLifetime(t, "single", dir)
	f.start(func(c *exec.Cmd) error {
		_, _, _, err := RunCommandWithContext(context.Background(), c)
		result <- err
		return err
	})
	f.waitAck(t)
	pid, err := strconv.Atoi(string(waitProcessFile(t, filepath.Join(dir, "root"))))
	require.NoError(t, err)
	group, err := syscall.Getpgid(pid)
	require.NoError(t, err)
	require.Equal(t, syscall.Getpgrp(), group)
	_, err = f.control.Write([]byte{'I'})
	require.NoError(t, err)
	select {
	case err := <-result:
		require.True(t, fixtureSIGINT(err), "foreground exit must be SIGINT: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("foreground interrupt was lost")
	}
}
