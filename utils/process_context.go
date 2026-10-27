package utils

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

// ErrCommandControl identifies process ownership, cleanup or output-capture failures.
var ErrCommandControl = errors.New("command process control failed")

func commandControlError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrCommandControl, err)
}

func commandStartError(err error) error {
	if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return commandControlError(err)
}

func commandWaitError(err error) error {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return err
	}
	return commandControlError(err)
}

type commandExit struct {
	err    error
	reaped bool
}

// RunCommandWithContext captures separate output streams and owns the command's
// process group (Unix) or Job Object (Windows) until cleanup completes. Commands
// must be unstarted. A noncancelable context preserves legacy foreground behavior.
// Cancellable commands support nil or *os.File stdin; arbitrary Go readers cannot
// be interrupted safely while os/exec copies them into a child.
func RunCommandWithContext(ctx context.Context, command *exec.Cmd) (stdout, stderr, combined []byte, err error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, err
	}
	if ctx.Done() == nil {
		return RunCommandWithOutputAndError(command)
	}
	if command.Stdin != nil {
		if file, ok := command.Stdin.(*os.File); !ok || file == nil {
			return nil, nil, nil, commandControlError(errors.New("cancellable command requires nil or *os.File stdin"))
		}
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		return nil, nil, nil, commandControlError(err)
	}
	defer func() { _ = outR.Close(); _ = outW.Close() }()
	errR, errW, err := os.Pipe()
	if err != nil {
		return nil, nil, nil, commandControlError(err)
	}
	defer func() { _ = errR.Close(); _ = errW.Close() }()
	command.Stdout, command.Stderr = outW, errW
	command.WaitDelay = time.Second
	cleanup, err := startCommandTree(command)
	if err != nil {
		return nil, nil, nil, err
	}
	parentCloseErr := errors.Join(outW.Close(), errW.Close())
	var bOut, bErr, bCombined bytes.Buffer
	shared := &synchronizedWriter{writer: &bCombined}
	readers := make(chan error, 2)
	go func() { _, err := io.Copy(io.MultiWriter(&bOut, shared), outR); readers <- err }()
	go func() { _, err := io.Copy(io.MultiWriter(&bErr, shared), errR); readers <- err }()
	finished := make(chan commandExit, 1)
	go func() { finished <- observeCommandExit(command) }()
	var observed commandExit
	var cancellation, cleanupErr error
	select {
	case observed = <-finished:
		cleanupErr = cleanup()
	case <-ctx.Done():
		// A result already received from Wait keeps its original cause even if
		// cancellation arrives during descendant cleanup.
		select {
		case observed = <-finished:
		default:
			cancellation = ctx.Err()
		}
		cleanupErr = cleanup()
		if cancellation != nil {
			observed = <-finished
		}
	}
	runErr := observed.err
	if !observed.reaped {
		runErr = errors.Join(commandControlError(runErr), commandWaitError(command.Wait()))
	} else {
		runErr = commandWaitError(runErr)
	}
	// Own the pipes as well: escaped descendants cannot hold the drain forever.
	drain := time.NewTimer(time.Second)
	defer drain.Stop()
	outputErr := parentCloseErr
	for i := 0; i < 2; i++ {
		select {
		case readErr := <-readers:
			outputErr = errors.Join(outputErr, readErr)
		case <-drain.C:
			_ = outR.Close()
			_ = errR.Close()
			outputErr = errors.Join(outputErr, errors.New("command output drain exceeded one second"))
			for ; i < 2; i++ {
				<-readers
			}
		}
	}
	return bOut.Bytes(), bErr.Bytes(), bCombined.Bytes(), errors.Join(runErr, cancellation, commandControlError(cleanupErr), commandControlError(outputErr))
}
