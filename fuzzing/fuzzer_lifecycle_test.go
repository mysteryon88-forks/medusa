package fuzzing

import (
	"context"
	"errors"
	"math/big"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crytic/medusa/chain"
	"github.com/crytic/medusa/fuzzing/calls"
	"github.com/crytic/medusa/fuzzing/config"
	"github.com/crytic/medusa/fuzzing/corpus"
	"github.com/crytic/medusa/fuzzing/executiontracer"
	"github.com/crytic/medusa/fuzzing/valuegeneration"
	"github.com/stretchr/testify/require"
)

func newLifecycleFuzzer(t *testing.T) *Fuzzer {
	t.Helper()
	c, err := config.GetDefaultProjectConfig("")
	require.NoError(t, err)
	c.Logging.NoColor = true
	c.Fuzzing.Workers = 2
	c.Fuzzing.CoverageEnabled = false
	c.Fuzzing.CoverageFormats = nil
	c.Fuzzing.PruneFrequency = 0
	c.Fuzzing.Testing.StopOnNoTests = false
	c.Fuzzing.Testing.AssertionTesting.Enabled = false
	c.Fuzzing.Testing.PropertyTesting.Enabled = false
	c.Fuzzing.Testing.OptimizationTesting.Enabled = false
	f, err := NewFuzzer(*c)
	require.NoError(t, err)
	f.Hooks.ChainSetupFunc = func(*Fuzzer, *chain.TestChain) (*executiontracer.ExecutionTrace, error) { return nil, nil }
	return f
}

func TestRaceWorkerCompletion(t *testing.T) {
	f := newLifecycleFuzzer(t)
	want := errors.New("created callback failed")
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	finished := make(chan struct{})
	f.Events.WorkerCreated.Subscribe(func(FuzzerWorkerCreatedEvent) error { return want })
	f.Events.WorkerDestroyed.Subscribe(func(FuzzerWorkerDestroyedEvent) error {
		entered <- struct{}{}
		<-release
		return nil
	})
	done := make(chan error, 1)
	go func() { defer close(finished); done <- f.Start() }()
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		f.Terminate()
		select {
		case <-finished:
		case <-time.After(10 * time.Second):
			t.Error("Start leaked")
		}
	})
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("Start returned before final callback: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("no worker callback")
	}
	select {
	case err := <-done:
		t.Fatalf("Start returned during final callback: %v", err)
	default:
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-done:
		require.ErrorIs(t, err, want)
	case <-time.After(10 * time.Second):
		f.Terminate()
		t.Fatal("workers did not finish")
	}
}

func TestRaceWorkerControl(t *testing.T) {
	for _, mode := range []string{"constructor", "destroyed", "stop", "terminate"} {
		t.Run(mode, func(t *testing.T) {
			f := newLifecycleFuzzer(t)
			want := errors.New(mode)
			switch mode {
			case "constructor":
				f.Hooks.NewCallSequenceGeneratorConfigFunc = func(*Fuzzer, *valuegeneration.ValueSet, *rand.Rand) (*CallSequenceGeneratorConfig, error) {
					return nil, want
				}
			case "destroyed":
				f.Events.WorkerCreated.Subscribe(func(FuzzerWorkerCreatedEvent) error { f.Stop(); return nil })
				f.Events.WorkerDestroyed.Subscribe(func(FuzzerWorkerDestroyedEvent) error { return want })
			case "stop", "terminate":
				f.Events.WorkerCreated.Subscribe(func(FuzzerWorkerCreatedEvent) error {
					if mode == "stop" {
						f.Stop()
					} else {
						f.Terminate()
					}
					return nil
				})
				f.Events.WorkerDestroyed.Subscribe(func(FuzzerWorkerDestroyedEvent) error { f.Stop(); return nil })
			}
			done := make(chan error, 1)
			go func() { done <- f.Start() }()
			select {
			case err := <-done:
				if mode == "constructor" || mode == "destroyed" {
					require.ErrorIs(t, err, want)
				} else {
					require.NoError(t, err)
				}
			case <-time.After(10 * time.Second):
				f.Terminate()
				t.Fatal("worker control did not return")
			}
		})
	}
}

func TestMetricsReset(t *testing.T) {
	runFuzzerTest(t, &fuzzerSolcFileTest{
		filePath:    "testdata/contracts/assertions/assert_immediate.sol",
		solcVersion: "0.8.25",
		configUpdates: func(c *config.ProjectConfig) {
			c.Fuzzing.Workers = 1
			c.Fuzzing.WorkerResetLimit = 1
			c.Fuzzing.CallSequenceLength = 1
			c.Fuzzing.CoverageEnabled = false
			c.Fuzzing.CoverageFormats = nil
			c.Fuzzing.Testing.StopOnNoTests = false
			c.Fuzzing.Testing.AssertionTesting.Enabled = false
			c.Fuzzing.Testing.PropertyTesting.Enabled = false
			c.Fuzzing.Testing.OptimizationTesting.Enabled = false
			c.Slither.UseSlither = false
		},
		method: func(fc *fuzzerTestContext) {
			var created atomic.Int32
			fc.fuzzer.Events.WorkerCreated.Subscribe(func(FuzzerWorkerCreatedEvent) error {
				if created.Add(1) == 3 {
					fc.fuzzer.Stop()
				}
				return nil
			})
			require.NoError(t, fc.fuzzer.Start())
			require.EqualValues(t, 3, fc.fuzzer.metrics.WorkerStartupCount().Int64())
			require.GreaterOrEqual(t, fc.fuzzer.metrics.SequencesTested().Int64(), int64(4))
		},
	})
}

func TestMetricsShrinkingError(t *testing.T) {
	f := newLifecycleFuzzer(t)
	f.metrics = newFuzzerMetrics(2, nil)
	f.emergencyCtx = context.Background()
	var err error
	f.corpus, err = corpus.NewCorpus("")
	require.NoError(t, err)
	w, err := newFuzzerWorker(f, 0, rand.New(rand.NewSource(2)))
	require.NoError(t, err)
	w.chain, err = f.createTestChain()
	require.NoError(t, err)
	defer w.chain.Close()
	w.randomProvider = rand.New(rand.NewSource(2))
	w.testingBaseBlockIndex = uint64(len(w.chain.CommittedBlocks()))
	to := f.senders[0]
	sequence := calls.CallSequence{}
	for i := 0; i < 2; i++ {
		sequence = append(sequence, &calls.CallSequenceElement{Call: calls.NewCallMessage(to, &to, 0, big.NewInt(0), 100000, big.NewInt(0), big.NewInt(0), big.NewInt(0), nil)})
	}
	want := errors.New("verifier failure")
	_, err = w.shrinkCallSequence(ShrinkCallSequenceRequest{
		CallSequenceToShrink: sequence,
		VerifierFunction:     func(*FuzzerWorker, calls.CallSequence) (bool, error) { return false, want },
	})
	require.ErrorIs(t, err, want)
	require.Zero(t, f.metrics.WorkersShrinkingCount())
}
