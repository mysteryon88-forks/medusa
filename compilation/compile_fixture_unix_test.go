//go:build !windows

package compilation_test

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var errCompilerFixturePending = errors.New("compiler fixture lifecycle still pending")
var errCompilerFixtureOwnerActive = errors.New("compiler fixture root has not joined")
var errCompilerFixtureLifetimeData = errors.New("compiler fixture lifetime contained unexpected data or watchdog fallback")

type compilerFixtureConnection struct {
	conn       *net.UnixConn
	done       chan struct{}
	err        error
	failure    chan struct{}
	failureErr error
	failOnce   sync.Once
}

func (owned *compilerFixtureConnection) reportFailure(err error) {
	if err != nil {
		owned.failOnce.Do(func() { owned.failureErr = err; close(owned.failure) })
	}
}

func (owned *compilerFixtureConnection) startReader(reader io.Reader, ackErr error) {
	owned.reportFailure(ackErr)
	go func() {
		var b [1]byte
		for {
			n, err := reader.Read(b[:])
			if n != 0 {
				owned.err = errCompilerFixtureLifetimeData
				owned.reportFailure(owned.err)
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				owned.err = errors.Join(owned.err, fmt.Errorf("compiler fixture lifetime did not reach EOF: %w", err))
				owned.reportFailure(owned.err)
				break
			}
		}
		owned.err = errors.Join(owned.err, ackErr)
		close(owned.done)
	}()
}

type compilerFixtureOwner struct {
	listener                       *net.UnixListener
	directory                      string
	capability                     string
	mu                             sync.Mutex
	connections                    []*compilerFixtureConnection
	stopping                       bool
	acceptDone, registered, done   chan struct{}
	acceptErr, runErr, shutdownErr error
	started                        bool
	beforeJoin                     func()
	stopOnce, cleanupOnce          sync.Once
	stopErr                        error
	cleanupDone                    chan struct{}
	finalRegistered                bool
}

func newCompilerFixtureOwner(t *testing.T) *compilerFixtureOwner {
	t.Helper()
	constructed := false
	// A short private path also fits Darwin's sockaddr_un limit.
	dir, err := os.MkdirTemp("", "mcf-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if !constructed {
			_ = os.RemoveAll(dir)
		}
	})
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	var capability [32]byte
	if _, err := rand.Read(capability[:]); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "s")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if !constructed {
			_ = listener.Close()
		}
	})
	f := &compilerFixtureOwner{listener: listener, directory: dir, capability: hex.EncodeToString(capability[:]),
		acceptDone: make(chan struct{}), registered: make(chan struct{}), done: make(chan struct{}), cleanupDone: make(chan struct{})}
	t.Setenv("MEDUSA_TOOL_SOCKET", path)
	t.Setenv("MEDUSA_TOOL_CAPABILITY", f.capability)
	t.Setenv("MEDUSA_TOOL_DEADLINE", strconv.FormatInt(time.Now().Add(20*time.Second).UnixNano(), 10))
	go f.accept()
	t.Cleanup(func() {
		f.mu.Lock()
		final := f.finalRegistered
		f.mu.Unlock()
		if !final {
			f.finalCleanup(t)
		}
	})
	constructed = true
	return f
}

func (f *compilerFixtureOwner) registerCleanup(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	if f.started || f.stopping || f.finalRegistered {
		f.mu.Unlock()
		panic("compiler final cleanup registered out of order")
	}
	f.finalRegistered = true
	f.mu.Unlock()
	// All test-owned environment and directories must be registered before this.
	t.Cleanup(func() { f.finalCleanup(t) })
}

func (f *compilerFixtureOwner) accept() {
	defer close(f.acceptDone)
	for {
		conn, err := f.listener.AcceptUnix()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			f.acceptErr = errors.Join(f.acceptErr, err)
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		capability, err := bufio.NewReader(io.LimitReader(conn, 66)).ReadString('\n')
		if err != nil || capability != f.capability+"\n" {
			f.acceptErr = errors.Join(f.acceptErr, errors.New("compiler fixture capability rejected"), err)
			_ = conn.Close() // An unregistered tool has no permission to spawn.
			continue
		}
		_ = conn.SetReadDeadline(time.Time{})
		owned := &compilerFixtureConnection{conn: conn, done: make(chan struct{}), failure: make(chan struct{})}
		f.mu.Lock()
		f.connections = append(f.connections, owned)
		if len(f.connections) == 1 {
			close(f.registered)
		}
		ack := byte('A')
		if f.stopping {
			ack = 'S'
		}
		_, ackErr := conn.Write([]byte{ack})
		if f.stopping {
			ackErr = errors.Join(ackErr, conn.CloseWrite())
		}
		owned.startReader(conn, ackErr)
		f.mu.Unlock()
	}
}

func (f *compilerFixtureOwner) start(run func() error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.started || f.stopping || !f.finalRegistered {
		panic("compiler fixture already started or stopping")
	}
	f.started = true
	go func() { f.runErr = run(); close(f.done) }()
}

func (f *compilerFixtureOwner) waitRegistered(t *testing.T) {
	t.Helper()
	select {
	case <-f.registered:
	case <-time.After(5 * time.Second):
		t.Fatal("compiler fixture did not register")
	}
}

func (f *compilerFixtureOwner) requestShutdown() error {
	f.stopOnce.Do(func() {
		f.mu.Lock()
		f.stopping = true
		for _, owned := range f.connections {
			err := owned.conn.CloseWrite()
			owned.reportFailure(err)
			f.stopErr = errors.Join(f.stopErr, err)
		}
		f.mu.Unlock()
		if f.beforeJoin != nil {
			f.beforeJoin()
		}
	})
	return f.stopErr
}

func (f *compilerFixtureOwner) waitEOF(timeout time.Duration) error {
	return f.waitEOFReady(timeout, nil)
}

func (f *compilerFixtureOwner) waitEOFReady(timeout time.Duration, ready chan<- struct{}) error {
	f.mu.Lock()
	connections := append([]*compilerFixtureConnection(nil), f.connections...)
	f.mu.Unlock()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	cases := []reflect.SelectCase{{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(deadline.C)}}
	for _, owned := range connections {
		cases = append(cases,
			reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(owned.done)},
			reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(owned.failure)})
	}
	state := func() (bool, error) {
		complete := true
		var err error
		for _, owned := range connections {
			var connectionErr error
			select {
			case <-owned.done:
				connectionErr = owned.err
			default:
				complete = false
			}
			select {
			case <-owned.failure:
				if !errors.Is(connectionErr, owned.failureErr) {
					connectionErr = errors.Join(connectionErr, owned.failureErr)
				}
			default:
			}
			err = errors.Join(err, connectionErr)
		}
		return complete, err
	}
	for {
		if complete, err := state(); complete || err != nil {
			return err
		}
		if ready != nil {
			close(ready)
			ready = nil
		}
		chosen, _, _ := reflect.Select(cases)
		if chosen == 0 {
			if complete, err := state(); complete || err != nil {
				return err
			}
			return errCompilerFixturePending
		}
		// Completed readers must not spin while other readers are still open.
		cases[chosen].Chan = reflect.ValueOf((<-chan struct{})(nil))
	}
}

func (f *compilerFixtureOwner) waitDescendantEOF(timeout time.Duration) error {
	select {
	case <-f.done:
	default:
		return errCompilerFixtureOwnerActive
	}
	return f.waitEOF(timeout)
}

func waitCompilerFixtureDone(done <-chan struct{}, timeout time.Duration) error {
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
			return errCompilerFixturePending
		}
	}
}

func joinCompilerFixtureReaders(connections []*compilerFixtureConnection) error {
	var err error
	for _, owned := range connections {
		<-owned.done
		err = errors.Join(err, owned.err)
	}
	return err
}

func (f *compilerFixtureOwner) shutdownWithin(timeout time.Duration) error {
	stopErr := f.requestShutdown()
	f.cleanupOnce.Do(func() {
		f.mu.Lock()
		started := f.started
		f.mu.Unlock()
		go func() {
			if started {
				<-f.done
			} else {
				close(f.done)
			}
			// Late registrations stay supervised until the SUT actually joins.
			closeErr := f.listener.Close()
			<-f.acceptDone
			f.mu.Lock()
			connections := append([]*compilerFixtureConnection(nil), f.connections...)
			f.mu.Unlock()
			f.shutdownErr = errors.Join(stopErr, closeErr, f.acceptErr, joinCompilerFixtureReaders(connections))
			for _, owned := range connections {
				f.shutdownErr = errors.Join(f.shutdownErr, owned.conn.Close())
			}
			f.shutdownErr = errors.Join(f.shutdownErr, os.RemoveAll(f.directory))
			close(f.cleanupDone)
		}()
	})
	if err := waitCompilerFixtureDone(f.cleanupDone, timeout); err != nil {
		return err
	}
	return f.shutdownErr
}

func (f *compilerFixtureOwner) shutdown() error { return f.shutdownWithin(25 * time.Second) }

func (f *compilerFixtureOwner) finalCleanup(t *testing.T) {
	t.Helper()
	err := f.shutdown()
	if errors.Is(err, errCompilerFixturePending) {
		t.Error("compiler cleanup exceeded budget; retaining test resources until join")
		<-f.cleanupDone
		err = f.shutdownErr
	}
	if err != nil {
		t.Error(err)
	}
}

// Strong references prevent finalizers from closing a lifetime socket before exit.
var compilerLifetimeFiles []*os.File
var compilerLifetimeConnections []*net.UnixConn

func compilerFixtureWatchdog(conn *net.UnixConn) {
	n, err := strconv.ParseInt(os.Getenv("MEDUSA_TOOL_DEADLINE"), 10, 64)
	if err != nil {
		panic(err)
	}
	time.AfterFunc(time.Until(time.Unix(0, n)), func() {
		_, _ = conn.Write([]byte{'W'})
		os.Exit(99)
	})
}

func watchCompilerFixture(conn *net.UnixConn) {
	compilerLifetimeConnections = append(compilerLifetimeConnections, conn)
	compilerFixtureWatchdog(conn)
	go func() {
		var b [1]byte
		n, err := conn.Read(b[:])
		if n == 0 && err == io.EOF {
			os.Exit(0)
		}
		os.Exit(98)
	}()
}

func connectCompilerFixture() *os.File {
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: os.Getenv("MEDUSA_TOOL_SOCKET"), Net: "unix"})
	if err != nil {
		panic(err)
	}
	compilerLifetimeConnections = append(compilerLifetimeConnections, conn)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, os.Getenv("MEDUSA_TOOL_CAPABILITY")+"\n"); err != nil {
		panic(err)
	}
	var ack [1]byte
	if _, err := io.ReadFull(conn, ack[:]); err != nil {
		panic(err)
	}
	if ack[0] == 'S' {
		os.Exit(0)
	}
	if ack[0] != 'A' {
		panic("compiler fixture registration not acknowledged")
	}
	_ = conn.SetDeadline(time.Time{})
	file, err := conn.File()
	if err != nil {
		panic(err)
	}
	compilerLifetimeFiles = append(compilerLifetimeFiles, file)
	watchCompilerFixture(conn)
	return file
}

func fakeCompilerHoldPipes(dir string) {
	file := os.NewFile(3, "compiler-lifetime")
	compilerLifetimeFiles = append(compilerLifetimeFiles, file)
	conn, err := net.FileConn(file)
	if err != nil {
		panic(err)
	}
	watchCompilerFixture(conn.(*net.UnixConn))
	if err := os.WriteFile(filepath.Join(dir, "escaped"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		panic(err)
	}
	select {}
}

func TestCompilerFixtureLifetime(t *testing.T) {
	for _, mode := range []string{"before-ready", "failed-start", "escaped", "late-registration"} {
		t.Run(mode, func(t *testing.T) {
			dir := fakeCompilerPath(t, "")
			f := newCompilerFixtureOwner(t)
			t.Setenv("MEDUSA_CONTROL_FAIL", "solc-version")
			c := exec.Command(filepath.Join(dir, "solc"), "--version")
			c.Env = os.Environ()
			if mode == "failed-start" {
				c.Path = filepath.Join(dir, "missing")
			}
			f.registerCleanup(t)
			if mode == "before-ready" {
				if err := f.shutdown(); err != nil {
					t.Fatal(err)
				}
				if err := f.shutdown(); err != nil {
					t.Fatal(err)
				}
				return
			}
			gate := make(chan struct{})
			var release sync.Once
			unblock := func() { release.Do(func() { close(gate) }) }
			defer unblock()
			f.start(func() error { <-gate; return c.Run() })
			if mode == "late-registration" {
				if err := f.requestShutdown(); err != nil {
					t.Fatal(err)
				}
			}
			unblock()
			select {
			case <-f.done:
			case <-time.After(8 * time.Second):
				t.Fatal("compiler fixture root did not exit")
			}
			if mode != "failed-start" {
				f.waitRegistered(t)
			}
			if mode == "escaped" {
				if err := f.waitDescendantEOF(25 * time.Millisecond); !errors.Is(err, errCompilerFixturePending) {
					t.Fatalf("escaped lifetime is not pending: %v", err)
				}
				b, err := os.ReadFile(filepath.Join(dir, "escaped"))
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("escaped child PID %s retained inherited socket", b)
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
			if mode == "late-registration" {
				if _, err := os.Stat(filepath.Join(dir, "escaped")); !os.IsNotExist(err) {
					t.Fatalf("late registration spawned a descendant: %v", err)
				}
			}
			pid := 0
			if c.Process != nil {
				pid = c.Process.Pid
			}
			t.Logf("root PID %d joined; all registered sockets reached EOF", pid)
		})
	}
}

func TestCompilerFixturePending(t *testing.T) {
	first := &compilerFixtureConnection{done: make(chan struct{})}
	second := &compilerFixtureConnection{done: make(chan struct{})}
	f := &compilerFixtureOwner{connections: []*compilerFixtureConnection{first, second}}
	if err := f.waitEOF(time.Millisecond); !errors.Is(err, errCompilerFixturePending) {
		t.Fatalf("open readers must be pending: %v", err)
	}
	first.err = io.ErrUnexpectedEOF
	close(first.done)
	if err := f.waitEOF(time.Millisecond); !errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, errCompilerFixturePending) {
		t.Fatalf("terminal reader error misclassified: %v", err)
	}
	close(second.done)
	if err := f.waitEOF(time.Millisecond); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("terminal reader error lost: %v", err)
	}
	ended := &compilerFixtureConnection{done: make(chan struct{})}
	close(ended.done)
	f.connections = []*compilerFixtureConnection{ended}
	if err := f.waitEOF(time.Millisecond); err != nil {
		t.Fatal(err)
	}
	failed := &compilerFixtureConnection{done: make(chan struct{}), failure: make(chan struct{}), failureErr: errCompilerFixtureLifetimeData}
	close(failed.failure)
	f.connections = []*compilerFixtureConnection{failed}
	if err := f.waitEOF(time.Millisecond); !errors.Is(err, errCompilerFixtureLifetimeData) || errors.Is(err, errCompilerFixturePending) {
		t.Fatalf("watchdog data accepted as pending: %v", err)
	}
}

func TestCompilerFixtureAckFailureOpenPeer(t *testing.T) {
	r, w := io.Pipe()
	owned := &compilerFixtureConnection{done: make(chan struct{}), failure: make(chan struct{})}
	wantAck := errors.New("ACK write failed")
	wantClose := errors.New("late CloseWrite failed")
	owned.startReader(r, errors.Join(wantAck, wantClose))
	defer func() { _ = w.Close(); <-owned.done; _ = r.Close() }()
	f := &compilerFixtureOwner{connections: []*compilerFixtureConnection{owned}}
	if err := f.waitEOF(time.Second); !errors.Is(err, wantAck) || !errors.Is(err, wantClose) || errors.Is(err, errCompilerFixturePending) {
		t.Fatalf("ACK errors hidden by open peer: %v", err)
	}
	select {
	case <-owned.done:
		t.Fatal("ACK error stopped the reader before peer EOF")
	default:
	}
	_ = w.Close()
	<-owned.done
	if err := joinCompilerFixtureReaders([]*compilerFixtureConnection{owned}); !errors.Is(err, wantAck) || !errors.Is(err, wantClose) {
		t.Fatalf("ACK errors lost after EOF: %v", err)
	}
}

func TestCompilerFixtureFailureWakesWaiter(t *testing.T) {
	first := &compilerFixtureConnection{done: make(chan struct{}), failure: make(chan struct{})}
	second := &compilerFixtureConnection{done: make(chan struct{}), failure: make(chan struct{})}
	f := &compilerFixtureOwner{connections: []*compilerFixtureConnection{first, second}}
	ready, finished := make(chan struct{}), make(chan struct{})
	want := errors.New("connection B failed")
	var result error
	go func() { result = f.waitEOFReady(5*time.Second, ready); close(finished) }()
	defer func() { close(first.done); second.err = want; close(second.done); <-finished }()
	select {
	case <-ready:
	case <-finished:
		t.Fatalf("wait returned before either peer changed: %v", result)
	case <-time.After(time.Second):
		t.Fatal("wait did not reach its receive")
	}
	second.reportFailure(want)
	select {
	case <-finished:
		if !errors.Is(result, want) || errors.Is(result, errCompilerFixturePending) {
			t.Fatalf("wrong wake result: %v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("connection B failure did not wake the wait on open connection A")
	}
}

func TestCompilerFixtureReadersJoin(t *testing.T) {
	first := &compilerFixtureConnection{done: make(chan struct{}), err: io.ErrUnexpectedEOF}
	second := &compilerFixtureConnection{done: make(chan struct{})}
	close(first.done)
	finished := make(chan struct{})
	var err error
	go func() { err = joinCompilerFixtureReaders([]*compilerFixtureConnection{first, second}); close(finished) }()
	var release sync.Once
	unblock := func() { release.Do(func() { close(second.done) }) }
	defer func() { unblock(); <-finished }()
	if result := waitCompilerFixtureDone(finished, time.Millisecond); !errors.Is(result, errCompilerFixturePending) {
		t.Fatalf("reader error skipped other reader join: %v", result)
	}
	unblock()
	<-finished
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("reader error lost after all joins: %v", err)
	}
}

func TestCompilerFixtureShutdownRetry(t *testing.T) {
	f := newCompilerFixtureOwner(t)
	gate := make(chan struct{})
	var release sync.Once
	unblock := func() { release.Do(func() { close(gate) }) }
	var waiters sync.WaitGroup
	defer func() { unblock(); waiters.Wait() }()
	var stops, runs atomic.Int32
	f.beforeJoin = func() { stops.Add(1) }
	f.registerCleanup(t)
	f.start(func() error { runs.Add(1); <-gate; return nil })
	if err := f.shutdownWithin(time.Millisecond); !errors.Is(err, errCompilerFixturePending) {
		t.Fatalf("blocked Run must remain pending: %v", err)
	}
	select {
	case <-f.acceptDone:
		t.Fatal("listener stopped before Run joined")
	default:
	}
	if _, err := os.Stat(f.directory); err != nil {
		t.Fatalf("owner directory removed while pending: %v", err)
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
		t.Fatalf("repeated stop/run: stops=%d runs=%d", stops.Load(), runs.Load())
	}
	if _, err := os.Stat(f.directory); !os.IsNotExist(err) {
		t.Fatalf("joined owner retained directory: %v", err)
	}
}
