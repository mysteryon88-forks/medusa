//go:build !windows && !darwin

package utils

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

func fixtureProcessGone(pid int) bool {
	if b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat"); err == nil {
		// An orphan may await init's reaper after it has stopped executing.
		return strings.HasPrefix(string(b)[strings.LastIndex(string(b), ")")+1:], " Z")
	}
	return syscall.Kill(pid, 0) == syscall.ESRCH
}
