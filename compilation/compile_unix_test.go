//go:build !windows

package compilation_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/crytic/medusa/compilation/platforms"
	"github.com/crytic/medusa/fuzzing"
	"github.com/crytic/medusa/utils"
	"github.com/stretchr/testify/require"
)

func fakeCompilerEscapedChild(dir string) {
	c := exec.Command(os.Args[0], "--hold-pipes")
	c.Env = os.Environ()
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := c.Start(); err != nil {
		panic(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(dir, "escaped")); err == nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
	_ = c.Process.Kill()
	_ = c.Wait()
	panic("escaped tool child did not start")
}

func cleanupCompilerChild(t *testing.T, dir string) {
	t.Helper()
	t.Cleanup(func() {
		if b, err := os.ReadFile(filepath.Join(dir, "escaped")); err == nil {
			pid, err := strconv.Atoi(string(b))
			if err != nil {
				t.Error(err)
				return
			}
			p, err := os.FindProcess(pid)
			if err == nil {
				_ = p.Kill()
				_ = p.Release()
			}
		}
	})
}

func TestCompileContextControlFailure(t *testing.T) {
	for _, stage := range []string{"solc-version", "slither"} {
		t.Run(stage, func(t *testing.T) {
			dir := fakeCompilerPath(t, "")
			cleanupCompilerChild(t, dir)
			t.Setenv("MEDUSA_CONTROL_FAIL", stage)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var err error
			if stage == "solc-version" {
				c := platforms.NewCryticCompilationConfig("unused.sol")
				c.ExportDirectory = filepath.Join(dir, "export")
				c.SolcVersion = "0.8.25"
				_, _, err = c.CompileContext(ctx)
				calls, readErr := os.ReadFile(filepath.Join(dir, "calls"))
				require.NoError(t, readErr)
				require.NotContains(t, string(calls), "solc-select")
				require.NotContains(t, string(calls), "crytic-compile")
			} else {
				_, err = fuzzing.NewFuzzerWithContext(ctx, *contextFuzzerConfig(t))
			}
			require.ErrorIs(t, err, utils.ErrCommandControl)
		})
	}
}
