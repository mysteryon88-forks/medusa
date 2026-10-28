package fuzzing

import (
	"errors"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/crytic/medusa/chain"
	"github.com/crytic/medusa/fuzzing/calls"
	"github.com/crytic/medusa/fuzzing/config"
	"github.com/crytic/medusa/fuzzing/executiontracer"
	"github.com/stretchr/testify/require"
)

func TestFuzzerMetricsDetached(t *testing.T) {
	f := &Fuzzer{metrics: newFuzzerMetrics(4, nil)}
	var writers sync.WaitGroup
	for i := 0; i < 4; i++ {
		writers.Add(1)
		go func(index int) {
			defer writers.Done()
			for j := 0; j < 1000; j++ {
				f.metrics.workerMetrics[index].recordCall(7)
			}
		}(i)
	}
	for i := 0; i < 1000; i++ {
		s := f.Metrics()
		require.Equal(t, new(big.Int).Mul(s.CallsTested(), big.NewInt(7)), s.GasUsed())
		s.CallsTested().SetInt64(-1)
	}
	writers.Wait()
	s := f.Metrics()
	require.EqualValues(t, 4000, s.CallsTested().Int64())
	s.GasUsed().SetInt64(-1)
	require.EqualValues(t, 28000, s.GasUsed().Int64())
	f.metrics.workerMetrics[0].recordCall(7)
	require.EqualValues(t, 4000, s.CallsTested().Int64())
}

func TestFuzzerMetricsLifecycle(t *testing.T) {
	f := newLifecycleFuzzer(t)
	f.config.Fuzzing.CoverageEnabled = true
	_, available := f.Metrics().CoverageMarkersHit()
	require.False(t, available)
	f.Events.FuzzerStarting.Subscribe(func(FuzzerStartingEvent) error {
		n, available := f.Metrics().CoverageMarkersHit()
		require.True(t, available)
		require.Zero(t, n)
		f.Stop()
		return nil
	})
	require.NoError(t, f.Start())
	final := f.Metrics()
	require.Zero(t, final.WorkersShrinkingCount())
	require.Equal(t, final, f.Metrics())

	// A new run publishes unavailable coverage before its setup hook.
	want := errors.New("setup failed")
	f.Hooks.ChainSetupFunc = func(*Fuzzer, *chain.TestChain) (*executiontracer.ExecutionTrace, error) {
		_, ready := f.Metrics().CoverageMarkersHit()
		require.False(t, ready)
		require.Zero(t, f.Metrics().CallsTested().Sign())
		return nil, want
	}
	require.ErrorIs(t, f.Start(), want)
	_, available = f.Metrics().CoverageMarkersHit()
	require.False(t, available)
	_, oldAvailable := final.CoverageMarkersHit()
	require.True(t, oldAvailable)
}

func TestFuzzerMetricsCoverageDisabled(t *testing.T) {
	f := newLifecycleFuzzer(t)
	f.Events.FuzzerStarting.Subscribe(func(FuzzerStartingEvent) error { f.Stop(); return nil })
	require.NoError(t, f.Start())
	n, available := f.Metrics().CoverageMarkersHit()
	require.Zero(t, n)
	require.False(t, available)
}

func TestFuzzerMetricsRunning(t *testing.T) {
	runFuzzerTest(t, &fuzzerSolcFileTest{
		filePath: "testdata/contracts/assertions/assert_immediate.sol", solcVersion: "0.8.25",
		configUpdates: func(c *config.ProjectConfig) {
			c.Logging.NoColor = true
			c.Fuzzing.Workers = 2
			c.Fuzzing.Timeout = 5
			c.Fuzzing.CallSequenceLength = 1
			c.Fuzzing.PruneFrequency = 0
			c.Fuzzing.CorpusDirectory = t.TempDir()
			c.Fuzzing.CoverageFormats = nil
			c.Fuzzing.Testing.StopOnNoTests = false
			c.Fuzzing.Testing.AssertionTesting.Enabled = false
			c.Fuzzing.Testing.PropertyTesting.Enabled = false
			c.Fuzzing.Testing.OptimizationTesting.Enabled = false
			c.Slither.UseSlither = false
		},
		method: func(fc *fuzzerTestContext) {
			f := fc.fuzzer
			var callsTested atomic.Int64
			f.Hooks.CallSequenceTestFuncs = append(f.Hooks.CallSequenceTestFuncs, func(*FuzzerWorker, calls.CallSequence) ([]ShrinkCallSequenceRequest, error) {
				if callsTested.Add(1) >= 200 {
					f.Stop()
				}
				return nil, nil
			})
			f.Events.WorkerDestroyed.Subscribe(func(FuzzerWorkerDestroyedEvent) error {
				f.Metrics()
				f.Stop()
				return nil
			})
			setup := f.Hooks.ChainSetupFunc
			failSetup := false
			want := errors.New("setup error between runs")
			f.Hooks.ChainSetupFunc = func(f *Fuzzer, c *chain.TestChain) (*executiontracer.ExecutionTrace, error) {
				_, available := f.Metrics().CoverageMarkersHit()
				require.False(t, available)
				require.Zero(t, f.Metrics().CallsTested().Sign())
				if failSetup {
					return nil, want
				}
				return setup(f, c)
			}
			done, stopped := make(chan struct{}), make(chan struct{})
			var sampledNonzero atomic.Bool
			go func() {
				defer close(stopped)
				for {
					select {
					case <-done:
						return
					default:
						s := f.Metrics()
						if s.CallsTested().Sign() > 0 {
							sampledNonzero.Store(true)
						}
						runtime.Gosched()
					}
				}
			}()
			defer func() { close(done); <-stopped }()
			require.NoError(t, f.Start())
			require.Positive(t, f.Metrics().CallsTested().Sign())
			sequences, _ := f.corpus.CallSequenceEntryCount()
			require.Positive(t, sequences)
			first := f.Metrics()
			failSetup = true
			require.ErrorIs(t, f.Start(), want)
			failSetup = false
			callsTested.Store(0)
			require.NoError(t, f.Start())
			require.Positive(t, f.corpus.ValidCallSequences())
			require.True(t, sampledNonzero.Load())
			require.Positive(t, first.CallsTested().Sign())
			require.Zero(t, f.Metrics().WorkersShrinkingCount())
		},
	})
}

func TestFuzzerMetricsEarlyErrors(t *testing.T) {
	for _, mode := range []string{"subscriber", "noTests"} {
		t.Run(mode, func(t *testing.T) {
			f := newLifecycleFuzzer(t)
			want := errors.New("starting subscriber error")
			if mode == "subscriber" {
				f.Events.FuzzerStarting.Subscribe(func(FuzzerStartingEvent) error { return want })
			} else {
				f.config.Fuzzing.Testing.StopOnNoTests = true
			}
			err := f.Start()
			if mode == "subscriber" {
				require.ErrorIs(t, err, want)
			} else {
				require.ErrorContains(t, err, "no assertion")
			}
			require.Zero(t, f.Metrics().CallsTested().Sign())
			require.Zero(t, f.Metrics().WorkersShrinkingCount())
		})
	}
}
