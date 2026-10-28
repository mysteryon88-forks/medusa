package compilation_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/crytic/medusa/compilation/platforms"
	"github.com/crytic/medusa/compilation/types"
	"github.com/crytic/medusa/fuzzing"
	"github.com/crytic/medusa/fuzzing/config"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	if os.Getenv("MEDUSA_FAKE_TOOL") == "1" {
		fakeCompilerTool()
		return
	}
	os.Exit(m.Run())
}

func fakeCompilerTool() {
	if len(os.Args) > 1 && os.Args[1] == "--hold-pipes" {
		fakeCompilerHoldPipes(os.Getenv("MEDUSA_TOOL_LOG"))
		return
	}
	tool := strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe")
	stage := tool
	if tool == "solc" && len(os.Args) > 1 && os.Args[1] == "--version" {
		stage = "solc-version"
	}
	dir := os.Getenv("MEDUSA_TOOL_LOG")
	log, err := os.OpenFile(filepath.Join(dir, "calls"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		panic(err)
	}
	if _, err := fmt.Fprintln(log, stage); err != nil {
		panic(err)
	}
	if err := log.Close(); err != nil {
		panic(err)
	}
	if stage == os.Getenv("MEDUSA_CONTROL_FAIL") {
		fakeCompilerEscapedChild(dir)
		return
	}
	if stage == os.Getenv("MEDUSA_BLOCK_TOOL") {
		if err := os.WriteFile(filepath.Join(dir, "ready"), []byte(stage), 0600); err != nil {
			panic(err)
		}
		time.Sleep(20 * time.Second)
		os.Exit(99)
	}
	if stage == "solc-version" {
		if os.Getenv("MEDUSA_NEED_INSTALL") == "1" {
			os.Exit(1)
		}
		fmt.Println("Version: 0.8.25+commit.fake")
		return
	}
	switch tool {
	case "solc":
		fmt.Println(`{"sources":{},"contracts":{},"version":"0.8.25"}`)
	case "slither":
		fmt.Fprintln(os.Stderr, "ordinary Slither failure")
		os.Exit(9)
	}
}

func fakeCompilerPath(t *testing.T, block string) string {
	t.Helper()
	dir := t.TempDir()
	binary, err := os.Executable()
	require.NoError(t, err)
	for _, tool := range []string{"solc", "solc-select", "crytic-compile", "slither"} {
		if runtime.GOOS == "windows" {
			tool += ".exe"
		}
		path := filepath.Join(dir, tool)
		// Windows keeps every hard link to the running parent image locked.
		linked := runtime.GOOS != "windows" && os.Link(binary, path) == nil
		if !linked {
			b, err := os.ReadFile(binary)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(path, b, 0700))
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("MEDUSA_FAKE_TOOL", "1")
	t.Setenv("MEDUSA_TOOL_LOG", dir)
	t.Setenv("MEDUSA_BLOCK_TOOL", block)
	// Keep the race runtime's exit delay out of fake-tool startup time.
	t.Setenv("GORACE", os.Getenv("GORACE")+" atexit_sleep_ms=0")
	return dir
}

func TestCompileContextCanceled(t *testing.T) {
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "sentinel")
	require.NoError(t, os.WriteFile(sentinel, []byte("preserve"), 0600))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := platforms.NewCryticCompilationConfig("unused.sol")
	c.ExportDirectory = dir
	_, _, err := c.CompileContext(ctx)
	require.ErrorIs(t, err, context.Canceled)
	b, err := os.ReadFile(sentinel)
	require.NoError(t, err)
	require.Equal(t, "preserve", string(b))
}

func TestCompileContextStages(t *testing.T) {
	for _, stage := range []string{"solc-version", "solc", "crytic-compile", "solc-select", "slither", "constructor-slither"} {
		t.Run(stage, func(t *testing.T) {
			block := stage
			if stage == "constructor-slither" {
				block = "slither"
			}
			dir := fakeCompilerPath(t, block)
			if stage == "solc-select" {
				t.Setenv("MEDUSA_NEED_INSTALL", "1")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var constructorConfig *config.ProjectConfig
			if stage == "constructor-slither" {
				constructorConfig = contextFuzzerConfig(t)
			}
			result, finished := make(chan error, 1), make(chan struct{})
			t.Cleanup(func() {
				cancel()
				select {
				case <-finished:
				case <-time.After(6 * time.Second):
					t.Error("preparation did not stop; retaining test resources until join")
					<-finished
				}
			})
			go func() {
				defer close(finished)
				var err error
				switch stage {
				case "slither":
					s := types.SlitherConfig{UseSlither: true}
					_, err = s.RunSlitherContext(ctx, "unused.sol", "")
				case "constructor-slither":
					_, err = fuzzing.NewFuzzerWithContext(ctx, *constructorConfig)
				case "crytic-compile", "solc-select":
					c := platforms.NewCryticCompilationConfig("unused.sol")
					c.ExportDirectory = filepath.Join(dir, "export")
					if stage == "solc-select" {
						c.SolcVersion = "0.8.25"
					}
					_, _, err = c.CompileContext(ctx)
				default:
					_, _, err = platforms.NewSolcCompilationConfig("unused.sol").CompileContext(ctx)
				}
				result <- err
			}()
			deadline := time.Now().Add(5 * time.Second)
			for {
				if _, err := os.Stat(filepath.Join(dir, "ready")); err == nil {
					break
				}
				select {
				case err := <-result:
					t.Fatalf("preparation returned before blocked stage: %v", err)
				default:
				}
				require.True(t, time.Now().Before(deadline), "tool never became ready")
				time.Sleep(10 * time.Millisecond)
			}
			cancel()
			select {
			case err := <-result:
				require.ErrorIs(t, err, context.Canceled)
			case <-time.After(5 * time.Second):
				t.Fatal("cancellation exceeded budget")
			}
			if stage == "solc-select" {
				calls, err := os.ReadFile(filepath.Join(dir, "calls"))
				require.NoError(t, err)
				require.NotContains(t, string(calls), "crytic-compile")
			}
		})
	}
}

func contextFuzzerConfig(t *testing.T) *config.ProjectConfig {
	t.Helper()
	c, err := config.GetDefaultProjectConfig("solc")
	require.NoError(t, err)
	c.Logging.NoColor = true
	c.Fuzzing.CorpusDirectory = t.TempDir()
	c.Slither.CachePath = ""
	return c
}

func TestCompileContextSlitherFallback(t *testing.T) {
	fakeCompilerPath(t, "")
	f, err := fuzzing.NewFuzzerWithContext(context.Background(), *contextFuzzerConfig(t))
	require.NoError(t, err)
	require.NotNil(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = fuzzing.NewFuzzerWithContext(ctx, *contextFuzzerConfig(t))
	require.True(t, errors.Is(err, context.Canceled))
	// Legacy error identity is retained by the compiler wrapper.
	_, err = (&types.SlitherConfig{UseSlither: true}).RunSlither("unused.sol", "")
	var exitError *exec.ExitError
	require.ErrorAs(t, err, &exitError)
}
