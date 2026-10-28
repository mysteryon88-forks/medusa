//go:build !windows

package utils

import (
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

func startCommandTree(command *exec.Cmd) (func() error, error) {
	if err := validateCommandPlatform(); err != nil {
		return nil, commandControlError(err)
	}
	attr := syscall.SysProcAttr{}
	if command.SysProcAttr != nil {
		attr = *command.SysProcAttr
	}
	if attr.Pgid != 0 {
		return nil, commandControlError(errors.New("context command cannot join an existing process group"))
	}
	if !attr.Setsid {
		attr.Setpgid = true
	}
	command.SysProcAttr = &attr
	if err := command.Start(); err != nil {
		return nil, commandStartError(err)
	}
	group := command.Process.Pid
	return func() error { return cleanupCommandGroup(group, commandGroupRunning) }, nil
}

func cleanupCommandGroup(group int, inspect func(int) (bool, error)) error {
	return cleanupCommandGroupWith(group, inspect, syscall.Kill, commandGroupCertificate)
}

func commandGroupSignal(group int, signal syscall.Signal, kill func(int, syscall.Signal) error, certify func(int) (bool, error)) error {
	terminal, preErr := certify(group)
	err := kill(-group, signal)
	if !errors.Is(err, syscall.EPERM) {
		return err
	}
	if preErr != nil {
		return errors.Join(err, preErr)
	}
	if !terminal {
		return err
	}
	terminal, postErr := certify(group)
	if postErr != nil {
		return errors.Join(err, postErr)
	}
	if terminal {
		return nil
	}
	return err
}

func cleanupCommandGroupWith(group int, inspect func(int) (bool, error), kill func(int, syscall.Signal) error, certify func(int) (bool, error)) error {
	var inspectionErr error
	err := commandGroupSignal(group, syscall.SIGTERM, kill, certify)
	if err == syscall.ESRCH {
		return nil
	}
	var signalErr error
	if err != nil {
		signalErr = fmt.Errorf("terminate command group: %w", err)
	}
	gracefulDeadline := time.Now().Add(250 * time.Millisecond)
	for time.Now().Before(gracefulDeadline) {
		if running, err := inspect(group); err != nil || !running {
			inspectionErr = err
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := commandGroupSignal(group, syscall.SIGKILL, kill, certify); err != nil && err != syscall.ESRCH {
		return errors.Join(signalErr, inspectionErr, fmt.Errorf("kill command group: %w", err))
	}
	deadline := time.Now().Add(time.Second)
	for {
		running, err := inspect(group)
		if err != nil || !running {
			return errors.Join(signalErr, inspectionErr, err)
		}
		if time.Now().After(deadline) {
			return errors.Join(signalErr, inspectionErr, errors.New("command group cleanup exceeded one second"))
		}
		time.Sleep(time.Millisecond)
	}
}

func observeCommandExit(command *exec.Cmd) commandExit {
	// WNOWAIT retains the group leader as an identity anchor until cleanup has
	// finished, preventing its numeric PGID being reused between signals.
	return commandExit{err: waitCommandExit(command.Process.Pid)}
}
