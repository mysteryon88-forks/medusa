package utils

import (
	"errors"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func fixtureProcessGone(pid int) bool {
	return fixtureTerminal(pid, syscall.Kill(pid, 0), func(pid int) (*unix.KinfoProc, error) {
		return unix.SysctlKinfoProc("kern.proc.pid", pid)
	})
}

func fixtureTerminal(pid int, signalErr error, inspect func(int) (*unix.KinfoProc, error)) bool {
	if errors.Is(signalErr, syscall.ESRCH) {
		return true
	}
	process, err := inspect(pid)
	return err == nil && process != nil && int(process.Proc.P_pid) == pid && process.Proc.P_stat == 5
}

func TestDarwinFixtureOracle(t *testing.T) {
	zombie := &unix.KinfoProc{}
	zombie.Proc.P_pid, zombie.Proc.P_stat = 123, 5
	live := *zombie
	live.Proc.P_stat = 2
	other := *zombie
	other.Proc.P_pid = 124
	inspectionErr := errors.New("inspection failed")
	for _, tc := range []struct {
		name      string
		signalErr error
		process   *unix.KinfoProc
		err       error
		want      bool
	}{
		{"absent", syscall.ESRCH, nil, inspectionErr, true},
		{"owned zombie", syscall.EPERM, zombie, nil, true},
		{"live process", nil, &live, nil, false},
		{"denied and live", syscall.EPERM, &live, nil, false},
		{"denied and inspection failed", syscall.EPERM, nil, inspectionErr, false},
		{"wrong pid", syscall.EPERM, &other, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := fixtureTerminal(123, tc.signalErr, func(int) (*unix.KinfoProc, error) { return tc.process, tc.err }); got != tc.want {
				t.Fatalf("terminal = %v, want %v", got, tc.want)
			}
		})
	}
}
