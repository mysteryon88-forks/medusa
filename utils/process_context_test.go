package utils

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func processFixture(role, directory string) *exec.Cmd {
	c := exec.Command(os.Args[0], "-test.run=^TestProcessContextHelper$", "--", role, directory)
	c.Env = append(os.Environ(), "MEDUSA_PROCESS_FIXTURE=1")
	return c
}

func waitProcessFile(t *testing.T, path string) []byte {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
			return b
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("fixture did not create %s", path)
	return nil
}

func TestProcessContextHelper(t *testing.T) {
	if os.Getenv("MEDUSA_PROCESS_FIXTURE") != "1" {
		return
	}
	role, directory := os.Args[len(os.Args)-2], os.Args[len(os.Args)-1]
	time.AfterFunc(20*time.Second, func() { os.Exit(99) })
	if role == "escape" {
		escapeProcessFixture(directory)
		return
	}
	if role == "fork-parent" {
		forkProcessFixture(directory)
		return
	}
	if role == "output" || role == "output-success" {
		if _, err := fmt.Fprint(os.Stdout, "stdout"); err != nil {
			panic(err)
		}
		if _, err := fmt.Fprint(os.Stderr, "stderr"); err != nil {
			panic(err)
		}
		if role == "output-success" {
			os.Exit(0)
		}
		os.Exit(7)
	}
	name := "root"
	if role == "child" || role == "grandchild" {
		name = role
		interrupts := make(chan os.Signal, 1)
		signal.Notify(interrupts, syscall.SIGTERM)
		defer signal.Stop(interrupts)
		go func() {
			for range interrupts {
				_ = os.WriteFile(filepath.Join(directory, "term-"+role), []byte("ready"), 0600)
			}
		}()
	}
	require.NoError(t, os.WriteFile(filepath.Join(directory, name), []byte(strconv.Itoa(os.Getpid())), 0600))
	if name != "grandchild" && role != "single" && role != "controlled-exit" {
		next := "child"
		if name == "child" {
			next = "grandchild"
		} else if role == "escaped-root" {
			next = "escape"
		}
		c := processFixture(next, directory)
		// Closing the root's pipes must not hide live descendants from cleanup.
		if _, err := os.Stat(filepath.Join(directory, "closePipes")); err != nil {
			c.Stdout, c.Stderr = os.Stdout, os.Stderr
		}
		require.NoError(t, c.Start())
		waitProcessFile(t, filepath.Join(directory, "grandchild"))
	}
	if name == "root" {
		require.NoError(t, os.WriteFile(filepath.Join(directory, "ready"), []byte("ready"), 0600))
		if role == "success-tree" {
			os.Exit(0)
		}
		if role == "exit" || role == "escaped-root" {
			os.Exit(7)
		}
		if role == "controlled-exit" {
			for {
				if _, err := os.Stat(filepath.Join(directory, "exit")); err == nil {
					os.Exit(0)
				}
				time.Sleep(time.Millisecond)
			}
		}
	}
	select {}
}

func TestProcessContextWaitFailure(t *testing.T) {
	dir := t.TempDir()
	outer, cancelOuter := context.WithCancel(context.Background())
	inner, cancelInner := context.WithCancel(context.Background())
	defer cancelOuter()
	defer cancelInner()
	base := processFixture("controlled-exit", dir)
	c := exec.CommandContext(inner, base.Path, base.Args[1:]...)
	c.Env = append(base.Env, "GORACE="+os.Getenv("GORACE")+" atexit_sleep_ms=0")
	want := errors.New("cancel callback failed")
	called := make(chan struct{})
	c.Cancel = func() error { close(called); return want }
	result, finished := make(chan error, 1), make(chan struct{})
	go func() {
		defer close(finished)
		_, _, _, err := RunCommandWithContext(outer, c)
		result <- err
	}()
	t.Cleanup(func() {
		cancelOuter()
		cancelInner()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("command with failing Cancel leaked")
		}
	})
	waitProcessFile(t, filepath.Join(dir, "ready"))
	cancelInner()
	select {
	case <-called:
	case <-time.After(5 * time.Second):
		t.Fatal("Cancel callback was not called")
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "exit"), []byte("exit"), 0600))
	select {
	case err := <-result:
		require.ErrorIs(t, err, want)
		require.ErrorIs(t, err, ErrCommandControl)
	case <-time.After(5 * time.Second):
		t.Fatal("Wait control failure did not return")
	}
}

type blockingCommandInput struct{ release <-chan struct{} }

func (r blockingCommandInput) Read([]byte) (int, error) { <-r.release; return 0, io.EOF }

func TestProcessContextStdin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	c := processFixture("single", t.TempDir())
	c.Stdin = blockingCommandInput{release: release}
	result := make(chan error, 1)
	go func() { _, _, _, err := RunCommandWithContext(ctx, c); result <- err }()
	select {
	case err := <-result:
		require.ErrorContains(t, err, "stdin")
		require.Nil(t, c.Process)
	case <-time.After(time.Second):
		cancel()
		t.Error("blocking stdin was accepted")
		// Let a faulty implementation's copy goroutine finish before teardown.
		unblock()
		select {
		case <-result:
		case <-time.After(5 * time.Second):
			t.Error("stdin copy leaked")
		}
	}
}

func TestProcessContextIsolation(t *testing.T) {
	start := func() (context.CancelFunc, <-chan error, int) {
		ctx, cancel := context.WithCancel(context.Background())
		dir := t.TempDir()
		result, finished := make(chan error, 1), make(chan struct{})
		go func() {
			defer close(finished)
			_, _, _, err := RunCommandWithContext(ctx, processFixture("tree", dir))
			result <- err
		}()
		t.Cleanup(func() {
			cancel()
			select {
			case <-finished:
			case <-time.After(5 * time.Second):
				t.Error("isolated command leaked")
			}
		})
		waitProcessFile(t, filepath.Join(dir, "ready"))
		var owned []*os.Process
		for _, name := range []string{"root", "child", "grandchild"} {
			pid, err := strconv.Atoi(string(waitProcessFile(t, filepath.Join(dir, name))))
			require.NoError(t, err)
			p, err := os.FindProcess(pid)
			if err == nil {
				owned = append(owned, p)
			}
		}
		t.Cleanup(func() {
			for _, p := range owned {
				_ = p.Kill()
				_ = p.Release()
			}
		})
		pid, err := strconv.Atoi(string(waitProcessFile(t, filepath.Join(dir, "child"))))
		require.NoError(t, err)
		return cancel, result, pid
	}
	cancelA, resultA, _ := start()
	cancelB, resultB, pidB := start()
	cancelA()
	select {
	case err := <-resultA:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("first operation did not stop")
	}
	require.False(t, fixtureProcessGone(pidB), "second operation was terminated")
	cancelB()
	select {
	case err := <-resultB:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("second operation did not stop")
	}
}

func TestProcessContextCanceled(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, _, err := RunCommandWithContext(ctx, processFixture("tree", dir))
	require.ErrorIs(t, err, context.Canceled)
	_, err = os.Stat(filepath.Join(dir, "root"))
	require.True(t, os.IsNotExist(err))
}

func TestProcessContextOutput(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stdout, stderr, combined, err := RunCommandWithContext(ctx, processFixture("output", t.TempDir()))
	require.Equal(t, "stdout", string(stdout))
	require.Equal(t, "stderr", string(stderr))
	require.Contains(t, string(combined), "stdout")
	require.Contains(t, string(combined), "stderr")
	var exitError *exec.ExitError
	require.ErrorAs(t, err, &exitError)
	require.Equal(t, 7, exitError.ExitCode())
	require.False(t, errors.Is(err, context.Canceled))
	require.EqualError(t, err, exitError.Error())
}

func TestProcessContextSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stdout, stderr, _, err := RunCommandWithContext(ctx, processFixture("output-success", t.TempDir()))
	require.NoError(t, err)
	require.Equal(t, "stdout", string(stdout))
	require.Equal(t, "stderr", string(stderr))
}

func TestProcessContextTree(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline", "rootExited", "success", "lateCancel"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "lateCancel" && runtime.GOOS == "windows" {
				t.Skip("Windows uses forced Job Object cleanup, with no SIGTERM phase")
			}
			dir := t.TempDir()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			role := "tree"
			if mode == "rootExited" || mode == "lateCancel" {
				role = "exit"
				require.NoError(t, os.WriteFile(filepath.Join(dir, "closePipes"), []byte("1"), 0600))
			}
			if mode == "success" {
				role = "success-tree"
				require.NoError(t, os.WriteFile(filepath.Join(dir, "closePipes"), []byte("1"), 0600))
			}
			finished := make(chan struct{})
			result := make(chan error, 1)
			if mode == "deadline" {
				var deadlineCancel context.CancelFunc
				ctx, deadlineCancel = context.WithTimeout(ctx, 2*time.Second)
				defer deadlineCancel()
			}
			go func() {
				defer close(finished)
				_, _, _, err := RunCommandWithContext(ctx, processFixture(role, dir))
				result <- err
			}()
			t.Cleanup(func() {
				cancel()
				select {
				case <-finished:
				case <-time.After(6 * time.Second):
					t.Error("process runner leaked")
				}
			})
			waitProcessFile(t, filepath.Join(dir, "ready"))
			owned := make([]*os.Process, 0, 3)
			for _, name := range []string{"root", "child", "grandchild"} {
				pid, err := strconv.Atoi(string(waitProcessFile(t, filepath.Join(dir, name))))
				require.NoError(t, err)
				p, err := os.FindProcess(pid)
				if err == nil {
					owned = append(owned, p)
				}
			}
			defer func() {
				for _, p := range owned {
					_ = p.Kill()
					_ = p.Release()
				}
			}()
			start := time.Now()
			switch mode {
			case "cancel":
				cancel()
			case "lateCancel":
				waitProcessFile(t, filepath.Join(dir, "term-child"))
				cancel()
			}
			var err error
			select {
			case err = <-result:
			case <-time.After(5 * time.Second):
				t.Fatal("process cleanup exceeded budget")
			}
			require.Less(t, time.Since(start), 5*time.Second)
			switch mode {
			case "cancel":
				require.ErrorIs(t, err, context.Canceled)
			case "deadline":
				require.ErrorIs(t, err, context.DeadlineExceeded)
			case "success":
				require.NoError(t, err)
			default:
				var exitError *exec.ExitError
				require.ErrorAs(t, err, &exitError)
				require.Equal(t, 7, exitError.ExitCode())
				require.False(t, errors.Is(err, context.Canceled))
				require.EqualError(t, err, exitError.Error())
			}
			for _, p := range owned {
				require.True(t, fixtureProcessGone(p.Pid), "PID %d survived cleanup", p.Pid)
			}
		})
	}
}
