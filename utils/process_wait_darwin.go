package utils

import (
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func validateCommandPlatform() error { return nil }

func ownedZombieGroup(processes []unix.KinfoProc, group, parent int) bool {
	if len(processes) != 1 {
		return false
	}
	p := processes[0]
	return int(p.Proc.P_pid) == group && int(p.Eproc.Pgid) == group &&
		int(p.Eproc.Ppid) == parent && p.Proc.P_stat == 5 // SZOMB
}

func commandGroupCertificateWith(group, parent int, inspect func(int) ([]unix.KinfoProc, error)) (bool, error) {
	processes, err := inspect(group)
	if err != nil {
		return false, err
	}
	return ownedZombieGroup(processes, group, parent), nil
}

func commandGroupCertificate(group int) (bool, error) {
	return commandGroupCertificateWith(group, os.Getpid(), func(group int) ([]unix.KinfoProc, error) {
		return unix.SysctlKinfoProcSlice("kern.proc.pgrp", group)
	})
}

func waitCommandExit(pid int) error {
	// waitid only writes siginfo_t; no fields are interpreted here. This aligned
	// buffer accommodates Darwin's native siginfo_t on both supported architectures.
	var info [32]uint64
	for {
		_, _, err := syscall.Syscall6(unix.SYS_WAITID, 1 /* P_PID */, uintptr(pid), uintptr(unsafe.Pointer(&info[0])), unix.WEXITED|unix.WNOWAIT, 0, 0)
		if err == unix.EINTR {
			continue
		}
		if err != 0 {
			return err
		}
		return nil
	}
}

func commandGroupRunning(group int) (bool, error) {
	processes, err := unix.SysctlKinfoProcSlice("kern.proc.pgrp", group)
	if err != nil {
		return false, err
	}
	for _, process := range processes {
		if process.Proc.P_stat != 5 { // SZOMB from Darwin's sys/proc.h.
			return true, nil
		}
	}
	return false, nil
}
