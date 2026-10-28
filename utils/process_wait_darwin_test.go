package utils

import (
	"errors"
	"os/exec"
	"strconv"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCommandGroupCertificate(t *testing.T) {
	zombie := unix.KinfoProc{}
	zombie.Proc.P_pid, zombie.Proc.P_stat = 123, 5
	zombie.Eproc.Pgid, zombie.Eproc.Ppid = 123, 456
	for _, tc := range []struct {
		name      string
		processes []unix.KinfoProc
		want      bool
	}{
		{"sole owned zombie", []unix.KinfoProc{zombie}, true},
		{"empty", nil, false},
		{"wrong pid", []unix.KinfoProc{func() unix.KinfoProc { p := zombie; p.Proc.P_pid = 124; return p }()}, false},
		{"wrong group", []unix.KinfoProc{func() unix.KinfoProc { p := zombie; p.Eproc.Pgid = 124; return p }()}, false},
		{"wrong parent", []unix.KinfoProc{func() unix.KinfoProc { p := zombie; p.Eproc.Ppid = 457; return p }()}, false},
		{"live leader", []unix.KinfoProc{func() unix.KinfoProc { p := zombie; p.Proc.P_stat = 2; return p }()}, false},
		{"extra zombie", []unix.KinfoProc{zombie, zombie}, false},
		{"extra live process", []unix.KinfoProc{zombie, func() unix.KinfoProc { p := zombie; p.Proc.P_stat = 2; return p }()}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ownedZombieGroup(tc.processes, 123, 456); got != tc.want {
				t.Fatalf("certificate = %v, want %v", got, tc.want)
			}
		})
	}
	inspectionErr := errors.New("sysctl failed")
	got, err := commandGroupCertificateWith(123, 456, func(int) ([]unix.KinfoProc, error) { return nil, inspectionErr })
	if got || !errors.Is(err, inspectionErr) {
		t.Fatalf("inspection error: got %v, %v", got, err)
	}
}

func TestOwnedZombieGroup(t *testing.T) {
	for _, code := range []int{0, 7} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			command := exec.Command("/bin/sh", "-c", "exit "+strconv.Itoa(code))
			command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			reaped := false
			t.Cleanup(func() {
				if !reaped {
					if err := cleanupCommandGroup(command.Process.Pid, commandGroupRunning); err != nil {
						t.Error(err)
					}
					_ = command.Wait()
				}
			})
			if err := waitCommandExit(command.Process.Pid); err != nil {
				t.Fatal(err)
			}
			terminal, err := commandGroupCertificate(command.Process.Pid)
			if err != nil || !terminal {
				t.Fatalf("owned zombie certificate = %v, %v", terminal, err)
			}
			if err := cleanupCommandGroup(command.Process.Pid, commandGroupRunning); err != nil {
				t.Fatal(err)
			}
			waitErr := command.Wait()
			reaped = true
			if command.ProcessState == nil {
				t.Fatalf("no process state: %v", waitErr)
			}
			if command.ProcessState.ExitCode() != code {
				t.Fatalf("exit code = %d, want %d", command.ProcessState.ExitCode(), code)
			}
			var exitErr *exec.ExitError
			if (code == 0 && waitErr != nil) || (code != 0 && !errors.As(waitErr, &exitErr)) {
				t.Fatalf("exit error = %v", waitErr)
			}
		})
	}
}

func TestFixtureZombieLeaderTerminal(t *testing.T) {
	command := exec.Command("/bin/sh", "-c", "exit 0")
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Wait() })
	if err := waitCommandExit(command.Process.Pid); err != nil {
		t.Fatal(err)
	}
	if !fixtureProcessGone(command.Process.Pid) {
		t.Error("fixture oracle treats an owned zombie as a running process")
	}
}
