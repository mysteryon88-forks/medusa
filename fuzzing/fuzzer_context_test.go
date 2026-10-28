package fuzzing_test

import (
	"context"
	"testing"

	"github.com/crytic/medusa/chain"
	"github.com/crytic/medusa/fuzzing"
	"github.com/crytic/medusa/fuzzing/config"
	"github.com/crytic/medusa/fuzzing/executiontracer"
	"github.com/stretchr/testify/require"
)

func TestFuzzerContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f, err := fuzzing.NewFuzzerWithContext(ctx, config.ProjectConfig{})
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, f)
}

func TestFuzzerContextPreparationOnly(t *testing.T) {
	c, err := config.GetDefaultProjectConfig("")
	require.NoError(t, err)
	c.Logging.NoColor = true
	c.Fuzzing.Workers = 1
	c.Fuzzing.CoverageEnabled = false
	c.Fuzzing.CoverageFormats = nil
	c.Fuzzing.PruneFrequency = 0
	c.Fuzzing.Testing.StopOnNoTests = false
	c.Fuzzing.Testing.AssertionTesting.Enabled = false
	c.Fuzzing.Testing.PropertyTesting.Enabled = false
	c.Fuzzing.Testing.OptimizationTesting.Enabled = false
	ctx, cancel := context.WithCancel(context.Background())
	f, err := fuzzing.NewFuzzerWithContext(ctx, *c)
	require.NoError(t, err)
	cancel()
	f.Hooks.ChainSetupFunc = func(*fuzzing.Fuzzer, *chain.TestChain) (*executiontracer.ExecutionTrace, error) { return nil, nil }
	f.Events.FuzzerStarting.Subscribe(func(fuzzing.FuzzerStartingEvent) error { f.Stop(); return nil })
	require.NoError(t, f.Start())
}
