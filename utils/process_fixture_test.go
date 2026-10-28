package utils

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"
)

var errFixturePending = errors.New("fixture lifecycle still pending")
var errFixtureOwnerActive = errors.New("fixture owner still holds transfer copies")
var errFixtureLifetimeData = errors.New("fixture lifetime contained unexpected data or watchdog fallback")

func TestFixtureLifetimePending(t *testing.T) {
	f := &processFixtureLifetime{eof: make(chan struct{})}
	if err := f.waitEOF(time.Millisecond); !errors.Is(err, errFixturePending) {
		t.Fatalf("open lifetime must be pending, got %v", err)
	}
	for _, terminal := range []error{nil, io.ErrUnexpectedEOF, errors.New("watchdog failure")} {
		f := &processFixtureLifetime{eof: make(chan struct{}), eofErr: terminal}
		close(f.eof)
		if err := f.waitEOF(time.Millisecond); err != terminal || errors.Is(err, errFixturePending) {
			t.Fatalf("terminal %v misclassified as %v", terminal, err)
		}
	}
	owner := &processFixtureLifetime{done: make(chan struct{}), eof: make(chan struct{})}
	if err := owner.waitDescendantEOF(time.Millisecond); !errors.Is(err, errFixtureOwnerActive) || errors.Is(err, errFixturePending) {
		t.Fatalf("owner writer accepted as descendant proof: %v", err)
	}
}

func TestFixtureLifetimeFailureBeforeEOF(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	f := &processFixtureLifetime{eof: make(chan struct{}), failure: make(chan struct{})}
	go func() {
		f.eofErr = readFixtureLifetimeWithFailure(r, func(err error) { f.failureErr = err; close(f.failure) })
		close(f.eof)
	}()
	defer func() { _ = w.Close(); <-f.eof; _ = r.Close() }()
	if _, err := w.Write([]byte{'W'}); err != nil {
		t.Fatal(err)
	}
	if err := waitFixtureDone(f.failure, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := f.waitEOF(time.Millisecond); !errors.Is(err, errFixtureLifetimeData) || errors.Is(err, errFixturePending) {
		t.Fatalf("watchdog data accepted as pending: %v", err)
	}
	select {
	case <-f.eof:
		t.Fatal("lifetime reader returned before real EOF")
	default:
	}
}

func TestFixtureLifetimeShutdownRetry(t *testing.T) {
	gate := make(chan struct{})
	var release sync.Once
	unblock := func() { release.Do(func() { close(gate) }) }
	var waiters sync.WaitGroup
	defer func() { unblock(); waiters.Wait() }()
	f := newProcessFixtureLifetime(t, "fixture-single", t.TempDir())
	var stops, runs atomic.Int32
	f.beforeJoin = func() { stops.Add(1) }
	// Model a late Run join without starting a process, even on an assertion failure.
	f.start(func(*exec.Cmd) error { runs.Add(1); <-gate; return nil })
	if err := f.shutdownWithin(time.Millisecond); !errors.Is(err, errFixturePending) {
		t.Fatalf("blocked Run must remain pending, got %v", err)
	}
	unblock()
	results := make(chan error, 4)
	for i := 0; i < 4; i++ {
		waiters.Add(1)
		go func() { defer waiters.Done(); results <- f.shutdownWithin(5 * time.Second) }()
	}
	for i := 0; i < 4; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if stops.Load() != 1 || runs.Load() != 1 {
		t.Fatalf("repeated control/reap: stops=%d runs=%d", stops.Load(), runs.Load())
	}
	if err := f.waitEOF(time.Second); err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.ackDone:
	default:
		t.Fatal("ACK reader not joined")
	}
	t.Log("in-process Run model joined after pending shutdown")
}

func TestFixtureLifetimeReadRequiresEOF(t *testing.T) {
	for _, tc := range []struct {
		name      string
		reader    io.Reader
		wantError bool
	}{
		{"eof", strings.NewReader(""), false},
		{"data", strings.NewReader("unexpected"), true},
		{"read-error", iotest.ErrReader(io.ErrUnexpectedEOF), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := readFixtureLifetime(tc.reader); (err != nil) != tc.wantError {
				t.Fatalf("lifetime read error = %v, want error %v", err, tc.wantError)
			}
		})
	}
}

func readFixtureLifetime(r io.Reader) error {
	return readFixtureLifetimeWithFailure(r, nil)
}

func readFixtureLifetimeWithFailure(r io.Reader, failure func(error)) error {
	var b [1]byte
	var dataErr error
	reported := false
	report := func(err error) {
		if !reported && failure != nil {
			reported = true
			failure(err)
		}
	}
	for {
		n, err := r.Read(b[:])
		if n != 0 {
			dataErr = errFixtureLifetimeData
			report(dataErr)
		}
		if err == io.EOF {
			return dataErr
		}
		if err != nil {
			result := errors.Join(dataErr, fmt.Errorf("fixture lifetime did not reach EOF: %w", err))
			report(result)
			return result
		}
	}
}

// Only the trusted fixture processes hold the writer, until os.Exit or a signal.
type processFixtureLifetime struct {
	command                             *exec.Cmd
	control                             *os.File
	lifetime                            *os.File
	ack                                 *os.File
	release                             func()
	ackDone, done, eof                  chan struct{}
	failure                             chan struct{}
	failureErr                          error
	ackErr, runErr, eofErr, shutdownErr error
	started                             bool
	beforeJoin                          func()
	mu                                  sync.Mutex
	stopOnce                            sync.Once
	cleanupDone                         chan struct{}
	closed                              bool
}

func newProcessFixtureLifetime(t *testing.T, role, dir string) *processFixtureLifetime {
	t.Helper()
	constructed := false
	pipe := func() (*os.File, *os.File) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if !constructed {
				_ = r.Close()
				_ = w.Close()
			}
		})
		return r, w
	}
	controlR, controlW := pipe()
	lifetimeR, lifetimeW := pipe()
	ackR, ackW := pipe()
	f := &processFixtureLifetime{command: processFixture(role, dir), control: controlW,
		lifetime: lifetimeR, ack: ackR, ackDone: make(chan struct{}), done: make(chan struct{}), eof: make(chan struct{}), failure: make(chan struct{}), cleanupDone: make(chan struct{})}
	closeInherited, err := inheritProcessFixture(f.command, []*os.File{controlR, lifetimeW, ackW})
	if err != nil {
		t.Fatal(err)
	}
	var releaseOnce sync.Once
	f.release = func() {
		releaseOnce.Do(func() {
			closeInherited()
			_ = controlR.Close()
			_ = lifetimeW.Close()
			_ = ackW.Close()
		})
	}
	f.command.Env = append(f.command.Env, "MEDUSA_FIXTURE_DEADLINE="+strconv.FormatInt(time.Now().Add(20*time.Second).UnixNano(), 10))
	go func() {
		var b [1]byte
		n, err := ackR.Read(b[:])
		if n != 1 || b[0] != 'A' || err != nil {
			f.ackErr = fmt.Errorf("fixture startup ACK missing: n=%d err=%v", n, err)
		}
		close(f.ackDone)
	}()
	go func() {
		f.eofErr = readFixtureLifetimeWithFailure(lifetimeR, func(err error) { f.failureErr = err; close(f.failure) })
		close(f.eof)
	}()
	t.Cleanup(func() { f.finalCleanup(t) })
	constructed = true
	return f
}

func (f *processFixtureLifetime) start(run func(*exec.Cmd) error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.started || f.closed {
		panic("fixture root already started or shutdown")
	}
	f.started = true
	go func() {
		f.runErr = run(f.command)
		// Cross-process ACK does not order File.Close against Cmd.Start's File.Fd.
		f.release()
		close(f.done)
	}()
}

func (f *processFixtureLifetime) waitAck(t *testing.T) {
	t.Helper()
	select {
	case <-f.ackDone:
		if f.ackErr != nil {
			t.Fatal(f.ackErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fixture startup ACK timed out")
	}
}

func (f *processFixtureLifetime) waitEOF(timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-f.failure:
		return f.failureErr
	case <-f.eof:
		return f.eofErr
	case <-timer.C:
		select {
		case <-f.failure:
			return f.failureErr
		default:
		}
		select {
		case <-f.eof:
			return f.eofErr
		default:
			return errFixturePending
		}
	}
}

func waitFixtureDone(done <-chan struct{}, timeout time.Duration) error {
	select {
	case <-done:
		return nil
	default:
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		select {
		case <-done:
			return nil
		default:
			return errFixturePending
		}
	}
}

func (f *processFixtureLifetime) waitReleased(timeout time.Duration) error {
	return waitFixtureDone(f.done, timeout)
}

func (f *processFixtureLifetime) waitDescendantEOF(timeout time.Duration) error {
	select {
	case <-f.done:
	default:
		return errFixtureOwnerActive
	}
	return f.waitEOF(timeout)
}

func (f *processFixtureLifetime) shutdownWithin(timeout time.Duration) error {
	f.stopOnce.Do(func() {
		f.mu.Lock()
		f.closed = true
		started := f.started
		f.mu.Unlock()
		_ = f.control.Close()
		if f.beforeJoin != nil {
			f.beforeJoin()
		}
		go func() {
			// A bounded waiter never closes files still in use by Start/Run.
			if started {
				<-f.done
			} else {
				f.release()
				close(f.done)
			}
			<-f.eof
			<-f.ackDone
			f.shutdownErr = errors.Join(f.eofErr, f.ack.Close(), f.lifetime.Close())
			close(f.cleanupDone)
		}()
	})
	if err := waitFixtureDone(f.cleanupDone, timeout); err != nil {
		return err
	}
	return f.shutdownErr
}

func (f *processFixtureLifetime) shutdown() error { return f.shutdownWithin(25 * time.Second) }

func (f *processFixtureLifetime) finalCleanup(t *testing.T) {
	t.Helper()
	err := f.shutdown()
	if errors.Is(err, errFixturePending) {
		t.Error("fixture cleanup exceeded budget; waiting for owned lifecycle")
		<-f.cleanupDone
		err = f.shutdownErr
	}
	if err != nil {
		t.Error(err)
	}
}

// Kept strongly reachable for the whole fixture lifetime, including delayed startup.
var processFixtureEndpoints []fixtureEndpoint
var processFixtureBootstrapControl fixtureEndpoint
var processFixtureBootstrapWatchdog *time.Timer

func processFixtureDeadline() time.Time {
	deadline := time.Now().Add(20 * time.Second)
	if value := os.Getenv("MEDUSA_FIXTURE_DEADLINE"); value != "" {
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			panic(err)
		}
		deadline = time.Unix(0, n)
	}
	return deadline
}

func processFixtureHandles() []uintptr {
	var handles []uintptr
	if os.Getenv("MEDUSA_FIXTURE_HANDLES") == "" {
		return nil
	}
	for _, value := range strings.Split(os.Getenv("MEDUSA_FIXTURE_HANDLES"), ",") {
		n, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			panic(err)
		}
		handles = append(handles, uintptr(n))
	}
	return handles
}

func bootstrapDelayedProcessFixture(dir string) {
	handles := processFixtureHandles()
	if len(handles) != 2 {
		panic("delayed fixture missing inherited handles")
	}
	processFixtureBootstrapControl = newFixtureEndpoint(handles[0])
	watchProcessFixtureControl(processFixtureBootstrapControl)
	// The lifetime FD stays raw until protocol initialization after the gate.
	processFixtureBootstrapWatchdog = time.AfterFunc(time.Until(processFixtureDeadline()), func() {
		file := newFixtureEndpoint(handles[1])
		defer runtime.KeepAlive(file)
		_, _ = file.Write([]byte{'W'})
		os.Exit(99)
	})
	if err := os.WriteFile(filepath.Join(dir, "bootstrapped"), []byte("ready"), 0600); err != nil {
		panic(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "initialize")); err == nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

func initializeProcessFixture() {
	deadline := processFixtureDeadline()
	handles := processFixtureHandles()
	if len(handles) == 0 {
		time.AfterFunc(time.Until(deadline), func() { os.Exit(99) })
		return
	}
	for i, handle := range handles {
		file := processFixtureBootstrapControl
		if i != 0 || file == nil {
			file = newFixtureEndpoint(handle)
		}
		processFixtureEndpoints = append(processFixtureEndpoints, file)
	}
	if processFixtureBootstrapWatchdog != nil {
		processFixtureBootstrapWatchdog.Stop()
	}
	time.AfterFunc(time.Until(deadline), func() {
		_, _ = processFixtureEndpoints[1].Write([]byte{'W'})
		os.Exit(99)
	})
	if len(processFixtureEndpoints) == 3 {
		if _, err := processFixtureEndpoints[2].Write([]byte{'A'}); err != nil {
			os.Exit(98)
		}
	}
	if processFixtureBootstrapControl == nil {
		watchProcessFixtureControl(processFixtureEndpoints[0])
	}
}

func watchProcessFixtureControl(control fixtureEndpoint) {
	go func() {
		var b [1]byte
		for {
			n, err := control.Read(b[:])
			if n == 1 && b[0] == 'I' {
				self, err := os.FindProcess(os.Getpid())
				if err != nil {
					os.Exit(98)
				}
				if err := self.Signal(os.Interrupt); err != nil {
					os.Exit(98)
				}
			}
			if err == io.EOF {
				os.Exit(0)
			}
			if err != nil {
				os.Exit(98)
			}
		}
	}()
}

func startProcessFixtureChild(c *exec.Cmd) error {
	if len(processFixtureEndpoints) == 0 {
		return errors.New("descendant has no lifetime endpoint")
	}
	closeInherited, err := inheritFixtureEndpoints(c, processFixtureEndpoints[:2])
	if err != nil {
		return err
	}
	defer closeInherited()
	return c.Start()
}

func fixtureLifetimeRole(role, dir string) bool {
	switch role {
	case "fixture-delayed-root", "fixture-escape-root":
		next := "fixture-delayed-child"
		if role == "fixture-escape-root" {
			next = "escape"
		}
		child := processFixture(next, dir)
		if err := startProcessFixtureChild(child); err != nil {
			panic(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "spawned"), []byte(strconv.Itoa(child.Process.Pid)), 0600); err != nil {
			panic(err)
		}
		os.Exit(0)
	case "fixture-delayed-child":
		if err := os.WriteFile(filepath.Join(dir, "initialized"), []byte("ready"), 0600); err != nil {
			panic(err)
		}
		select {}
	case "fixture-single":
		select {}
	case "fixture-protocol-error":
		os.Exit(98)
	default:
		return false
	}
	return true
}

func TestFixtureLifetimeOwned(t *testing.T) {
	for _, mode := range []string{"before-ready", "failed-start", "single", "delayed", "delayed-before-init"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			role := "fixture-single"
			if mode == "delayed" || mode == "delayed-before-init" {
				role = "fixture-delayed-root"
			}
			f := newProcessFixtureLifetime(t, role, dir)
			if mode == "failed-start" {
				f.command.Path = filepath.Join(dir, "missing")
			}
			f.start(func(c *exec.Cmd) error { return c.Run() })
			if mode == "single" || mode == "delayed" || mode == "delayed-before-init" {
				f.waitAck(t)
				if mode != "single" {
					select {
					case <-f.done:
					case <-time.After(5 * time.Second):
						t.Fatal("root did not exit")
					}
					t.Logf("delayed descendant PID %s", waitProcessFile(t, filepath.Join(dir, "spawned")))
					waitProcessFile(t, filepath.Join(dir, "bootstrapped"))
					if _, err := os.Stat(filepath.Join(dir, "initialized")); !os.IsNotExist(err) {
						t.Fatalf("protocol initialized before gate: %v", err)
					}
				}
				want := errFixturePending
				if mode == "single" {
					want = errFixtureOwnerActive
				}
				if err := f.waitDescendantEOF(25 * time.Millisecond); !errors.Is(err, want) {
					t.Fatalf("lifetime state = %v, want %v", err, want)
				}
				if mode == "delayed" {
					if err := os.WriteFile(filepath.Join(dir, "initialize"), []byte("go"), 0600); err != nil {
						t.Fatal(err)
					}
					waitProcessFile(t, filepath.Join(dir, "initialized"))
					if err := f.waitDescendantEOF(25 * time.Millisecond); !errors.Is(err, errFixturePending) {
						t.Fatalf("initialized child lifetime = %v", err)
					}
				}
			}
			if err := f.shutdown(); err != nil {
				t.Fatal(err)
			}
			if err := f.shutdown(); err != nil {
				t.Fatal(err)
			}
			if mode == "failed-start" && f.runErr == nil {
				t.Fatal("missing executable succeeded")
			}
			if mode != "failed-start" && f.runErr != nil {
				t.Fatal(f.runErr)
			}
			pid := 0
			if f.command.Process != nil {
				pid = f.command.Process.Pid
			}
			t.Logf("root PID %d, Run/Wait joined, lifetime EOF confirmed", pid)
		})
	}
}
