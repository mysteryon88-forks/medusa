//go:build !windows

package compilation_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/crytic/medusa/compilation/platforms"
	"github.com/crytic/medusa/fuzzing"
	"github.com/crytic/medusa/utils"
	"github.com/stretchr/testify/require"
)

func fakeCompilerEscapedChild(dir string) {
	lifetime := connectCompilerFixture()
	c := exec.Command(os.Args[0], "--hold-pipes")
	c.Env = os.Environ()
	c.ExtraFiles = []*os.File{lifetime}
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
	panic("escaped tool child did not start")
}

func TestCompileContextControlFailure(t *testing.T) {
	for _, stage := range []string{"solc-version", "slither"} {
		t.Run(stage, func(t *testing.T) {
			dir := fakeCompilerPath(t, "")
			fixture := newCompilerFixtureOwner(t)
			t.Setenv("MEDUSA_CONTROL_FAIL", stage)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fixture.beforeJoin = cancel
			run := func() error {
				c := platforms.NewCryticCompilationConfig("unused.sol")
				c.ExportDirectory = filepath.Join(dir, "export")
				c.SolcVersion = "0.8.25"
				_, _, err := c.CompileContext(ctx)
				return err
			}
			if stage == "slither" {
				config := contextFuzzerConfig(t)
				run = func() error { _, err := fuzzing.NewFuzzerWithContext(ctx, *config); return err }
			}
			fixture.registerCleanup(t)
			fixture.start(run)
			select {
			case <-fixture.done:
			case <-time.After(8 * time.Second):
				t.Fatal("compiler operation did not return")
			}
			if stage == "solc-version" {
				calls, readErr := os.ReadFile(filepath.Join(dir, "calls"))
				require.NoError(t, readErr)
				require.NotContains(t, string(calls), "solc-select")
				require.NotContains(t, string(calls), "crytic-compile")
			}
			require.ErrorIs(t, fixture.runErr, utils.ErrCommandControl)
			fixture.waitRegistered(t)
			require.ErrorIs(t, fixture.waitDescendantEOF(25*time.Millisecond), errCompilerFixturePending, "escaped compiler must still hold its lifetime socket before fallback shutdown")
		})
	}
}
