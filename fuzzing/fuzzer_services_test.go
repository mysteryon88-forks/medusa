package fuzzing

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/crytic/medusa-geth/core"
	"github.com/crytic/medusa-geth/core/vm"
	"github.com/crytic/medusa/chain"
	"github.com/crytic/medusa/fuzzing/calls"
	"github.com/crytic/medusa/fuzzing/config"
	"github.com/crytic/medusa/fuzzing/executiontracer"
	"github.com/crytic/medusa/fuzzing/reverts"
	"github.com/stretchr/testify/require"
)

func newServicesFuzzer(t *testing.T) *Fuzzer {
	t.Helper()
	c, err := config.GetDefaultProjectConfig("")
	require.NoError(t, err)
	c.Logging.NoColor = true
	c.Fuzzing.Workers = 1
	c.Fuzzing.CoverageEnabled = true
	c.Fuzzing.CoverageFormats = nil
	c.Fuzzing.PruneFrequency = 1
	c.Fuzzing.RevertReporterEnabled = true
	c.Fuzzing.CorpusDirectory = t.TempDir()
	c.Fuzzing.Testing.StopOnNoTests = false
	c.Fuzzing.Testing.AssertionTesting.Enabled = false
	c.Fuzzing.Testing.PropertyTesting.Enabled = false
	c.Fuzzing.Testing.OptimizationTesting.Enabled = false
	require.NoError(t, os.Mkdir(filepath.Join(c.Fuzzing.CorpusDirectory, "coverage"), 0700))
	f, err := NewFuzzer(*c)
	require.NoError(t, err)
	f.Hooks.ChainSetupFunc = func(*Fuzzer, *chain.TestChain) (*executiontracer.ExecutionTrace, error) { return nil, nil }
	return f
}

func queueServiceUpdates(f *Fuzzer, count, failed int) {
	for i := 0; i < count; i++ {
		result := &core.ExecutionResult{}
		if i < failed {
			result.Err = vm.ErrExecutionReverted
		}
		f.revertReporter.RevertMetricsCh <- reverts.RevertMetricsUpdate{ContractName: "C", FunctionName: "f", ExecutionResult: result}
	}
}

func TestFuzzerServicesRuns(t *testing.T) {
	f := newServicesFuzzer(t)
	run := 0
	f.Events.FuzzerStarting.Subscribe(func(FuzzerStartingEvent) error {
		queueServiceUpdates(f, run*100, run*run*10)
		f.Stop()
		return nil
	})
	for run = 1; run <= 3; run++ {
		require.NoError(t, f.Start())
		require.Empty(t, f.revertReporter.RevertMetricsCh)
		b, err := os.ReadFile(filepath.Join(f.revertReporter.Path, "revert_report.json"))
		require.NoError(t, err)
		var metrics reverts.RevertMetrics
		require.NoError(t, json.Unmarshal(b, &metrics))
		m := metrics.ContractRevertMetrics["C"].FunctionRevertMetrics["f"]
		require.EqualValues(t, run*100, m.TotalCalls)
		require.InDelta(t, float64(run)/10, m.Pct, 0.00001)
		require.InDelta(t, float64(run-1)/10, m.PrevPct, 0.00001)
		require.Zero(t, f.Metrics().CallsTested().Sign())
	}
}

func TestFuzzerServicesErrors(t *testing.T) {
	for _, stage := range []string{"setup", "starting"} {
		t.Run(stage, func(t *testing.T) {
			f := newServicesFuzzer(t)
			want := errors.New("service error at " + stage)
			fail := true
			f.Hooks.ChainSetupFunc = func(*Fuzzer, *chain.TestChain) (*executiontracer.ExecutionTrace, error) {
				if stage == "setup" && fail {
					queueServiceUpdates(f, 100, 50)
					return nil, want
				}
				return nil, nil
			}
			f.Events.FuzzerStarting.Subscribe(func(FuzzerStartingEvent) error {
				if stage == "starting" && fail {
					queueServiceUpdates(f, 100, 50)
					return want
				}
				f.Stop()
				return nil
			})
			require.ErrorIs(t, f.Start(), want)
			require.Empty(t, f.revertReporter.RevertMetricsCh)
			require.EqualValues(t, 100, f.revertReporter.RevertMetrics.ContractRevertMetrics["C"].FunctionRevertMetrics["f"].TotalCalls)
			fail = false
			require.NoError(t, f.Start())
			require.Empty(t, f.revertReporter.RevertMetricsCh)
			require.Empty(t, f.revertReporter.RevertMetrics.ContractRevertMetrics)
			require.InDelta(t, 0.5, f.revertReporter.PrevRevertMetrics.ContractRevertMetrics["C"].FunctionRevertMetrics["f"].Pct, 0.00001)
		})
	}
}

func TestFuzzerServicesWorkerBarrier(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "coverage"), 0700))
	runFuzzerTest(t, &fuzzerSolcFileTest{
		filePath: "testdata/contracts/properties/initial_repair.sol", solcVersion: "0.8.25",
		configUpdates: func(c *config.ProjectConfig) {
			initialTestConfig(c)
			c.Fuzzing.Workers = 1
			c.Fuzzing.CoverageEnabled = true
			c.Fuzzing.PruneFrequency = 1
			c.Fuzzing.RevertReporterEnabled = true
			c.Fuzzing.CorpusDirectory = dir
			c.Fuzzing.Testing.PropertyTesting.Enabled = false
			c.Fuzzing.Testing.TestViewMethods = false
			c.Fuzzing.Testing.StopOnNoTests = false
		},
		method: func(fc *fuzzerTestContext) {
			t, f := fc.t, fc.fuzzer
			var tested atomic.Uint64
			f.Hooks.CallSequenceTestFuncs = append(f.Hooks.CallSequenceTestFuncs, func(*FuzzerWorker, calls.CallSequence) ([]ShrinkCallSequenceRequest, error) {
				if tested.Add(1) >= 30 {
					f.Stop()
				}
				return nil, nil
			})
			f.Events.WorkerDestroyed.Subscribe(func(FuzzerWorkerDestroyedEvent) error {
				// More than the queue capacity proves the consumer lives through final callbacks after Stop.
				queueServiceUpdates(f, 1001, 0)
				return nil
			})
			require.NoError(t, f.Start())
			require.Empty(t, f.revertReporter.RevertMetricsCh)
			require.EqualValues(t, 1001, f.revertReporter.RevertMetrics.ContractRevertMetrics["C"].FunctionRevertMetrics["f"].TotalCalls)
			require.Equal(t, tested.Load(), f.Metrics().CallsTested().Uint64())
			require.EqualValues(t, tested.Load(), f.revertReporter.RevertMetrics.ContractRevertMetrics["TestContract"].FunctionRevertMetrics["repair"].TotalCalls)
		},
	})
}
