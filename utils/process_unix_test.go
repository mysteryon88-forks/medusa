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
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func fixtureProcessGone(pid int) bool {
	if b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat"); err == nil {
		// An orphan may await init's reaper after it has stopped executing.
		return strings.HasPrefix(string(b)[strings.LastIndex(string(b), ")")+1:], " Z")
	}
	return syscall.Kill(pid, 0) == syscall.ESRCH
}

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
	if err := child.Start(); err != nil {
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
	c := processFixture(role, dir)
	cleanup, err := startCommandTree(c)
	require.NoError(t, err)
	observed, finished := make(chan commandExit, 1), make(chan struct{})
	go func() { defer close(finished); observed <- observeCommandExit(c) }()
	t.Cleanup(func() {
		_ = cleanup()
		_ = c.Wait()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("process observer leaked")
		}
	})
	waitProcessFile(t, filepath.Join(dir, "ready"))
	return c, observed, dir
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
	result, finished := make(chan error, 1), make(chan struct{})
	go func() {
		defer close(finished)
		_, _, _, err := RunCommandWithContext(ctx, processFixture("escaped-root", dir))
		result <- err
	}()
	pid, err := strconv.Atoi(string(waitProcessFile(t, filepath.Join(dir, "grandchild"))))
	require.NoError(t, err)
	p, err := os.FindProcess(pid)
	require.NoError(t, err)
	defer func() { _ = p.Kill(); _ = p.Release() }()
	t.Cleanup(func() {
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("escaped pipe reader leaked")
		}
	})
	select {
	case err := <-result:
		require.ErrorContains(t, err, "output drain exceeded")
		require.False(t, fixtureProcessGone(pid), "runner signaled a process outside its group")
	case <-time.After(5 * time.Second):
		t.Fatal("escaped pipe held runner open")
	}
}

func TestProcessContextForeground(t *testing.T) {
	dir := t.TempDir()
	result := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		_, _, _, err := RunCommandWithContext(context.Background(), processFixture("single", dir))
		result <- err
	}()
	t.Cleanup(func() {
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("foreground process leaked")
		}
	})
	pid, err := strconv.Atoi(string(waitProcessFile(t, filepath.Join(dir, "root"))))
	require.NoError(t, err)
	p, err := os.FindProcess(pid)
	require.NoError(t, err)
	defer func() { _ = p.Kill(); _ = p.Release() }()
	group, err := syscall.Getpgid(pid)
	require.NoError(t, err)
	require.Equal(t, syscall.Getpgrp(), group)
	require.NoError(t, p.Signal(os.Interrupt))
	select {
	case err := <-result:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("foreground interrupt was lost")
	}
}
