package cmd

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/crytic/medusa/chain"
	"github.com/crytic/medusa/fuzzing"
	"github.com/crytic/medusa/fuzzing/config"
	"github.com/crytic/medusa/fuzzing/executiontracer"
	"github.com/stretchr/testify/require"
)

func TestContextSignalHandshake(t *testing.T) {
	for i := 0; i < 500; i++ {
		var terminated atomic.Int32
		c := campaignCancellation{terminate: func() { terminated.Add(1) }}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); c.request() }()
		go func() { defer wg.Done(); c.markReady() }()
		wg.Wait()
		require.Positive(t, terminated.Load())
	}
	var terminated atomic.Int32
	c := campaignCancellation{terminate: func() { terminated.Add(1) }}
	c.request()
	require.Zero(t, terminated.Load())
	c.markReady()
	require.EqualValues(t, 1, terminated.Load())
}

func signalTestFuzzer(t *testing.T) *fuzzing.Fuzzer {
	t.Helper()
	c, err := config.GetDefaultProjectConfig("")
	require.NoError(t, err)
	c.Logging.NoColor = true
	c.Fuzzing.Workers = 1
	c.Fuzzing.CoverageEnabled = false
	c.Fuzzing.CoverageFormats = nil
	c.Fuzzing.PruneFrequency = 0
	c.Fuzzing.Testing.StopOnNoTests = false
	c.Fuzzing.Testing.PropertyTesting.Enabled = false
	c.Fuzzing.Testing.AssertionTesting.Enabled = false
	c.Fuzzing.Testing.OptimizationTesting.Enabled = false
	f, err := fuzzing.NewFuzzer(*c)
	require.NoError(t, err)
	f.Hooks.ChainSetupFunc = func(*fuzzing.Fuzzer, *chain.TestChain) (*executiontracer.ExecutionTrace, error) { return nil, nil }
	return f
}

func TestContextSignalStart(t *testing.T) {
	f := signalTestFuzzer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var setup atomic.Int32
	f.Hooks.ChainSetupFunc = func(*fuzzing.Fuzzer, *chain.TestChain) (*executiontracer.ExecutionTrace, error) {
		setup.Add(1)
		return nil, nil
	}
	require.ErrorIs(t, startWithSignalContext(ctx, f), context.Canceled)
	require.Zero(t, setup.Load())

	ctx, cancel = context.WithCancel(context.Background())
	f.Hooks.ChainSetupFunc = func(*fuzzing.Fuzzer, *chain.TestChain) (*executiontracer.ExecutionTrace, error) {
		setup.Add(1)
		cancel()
		return nil, nil
	}
	require.ErrorIs(t, startWithSignalContext(ctx, f), context.Canceled)
	require.EqualValues(t, 1, setup.Load())

	// Hooks and observers from that run must not capture the next campaign.
	f.Hooks.ChainSetupFunc = func(*fuzzing.Fuzzer, *chain.TestChain) (*executiontracer.ExecutionTrace, error) { return nil, nil }
	f.Events.FuzzerStarting.Subscribe(func(fuzzing.FuzzerStartingEvent) error { f.Stop(); return nil })
	require.NoError(t, startWithSignalContext(context.Background(), f))
}
