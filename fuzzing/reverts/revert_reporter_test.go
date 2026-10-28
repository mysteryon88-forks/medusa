package reverts

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/crytic/medusa-geth/core"
	"github.com/crytic/medusa-geth/core/vm"
	"github.com/crytic/medusa/logging"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func reporterForTest(t *testing.T) *RevertReporter {
	t.Helper()
	logging.GlobalLogger = logging.NewLogger(zerolog.Disabled)
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "coverage"), 0700))
	r, err := NewRevertReporter(true, dir)
	require.NoError(t, err)
	return r
}

func enqueueReverts(r *RevertReporter, count, reverts int) {
	for i := 0; i < count; i++ {
		result := &core.ExecutionResult{}
		if i < reverts {
			result.Err = vm.ErrExecutionReverted
		}
		r.RevertMetricsCh <- RevertMetricsUpdate{ContractName: "C", FunctionName: "f", ExecutionResult: result}
	}
}

func TestRevertReporterDrain(t *testing.T) {
	r := reporterForTest(t)
	enqueueReverts(r, 1000, 500)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.Start(ctx)
	require.NoError(t, r.BuildArtifacts())
	metrics := r.RevertMetrics.ContractRevertMetrics["C"].FunctionRevertMetrics["f"]
	require.EqualValues(t, 1000, metrics.TotalCalls)
	require.EqualValues(t, 500, metrics.TotalReverts)
	require.InDelta(t, 0.5, metrics.Pct, 0.00001)
	require.Empty(t, r.RevertMetricsCh)
	enqueueReverts(r, 3, 0)
	r.Start(ctx)
	require.NoError(t, r.BuildArtifacts())
	metrics = r.RevertMetrics.ContractRevertMetrics["C"].FunctionRevertMetrics["f"]
	require.EqualValues(t, 3, metrics.TotalCalls)
	require.InDelta(t, 0.5, metrics.PrevPct, 0.00001)
	require.Zero(t, metrics.TotalReverts)
	require.Empty(t, r.RevertMetricsCh)
}

func TestRevertReporterPrevious(t *testing.T) {
	r := reporterForTest(t)
	enqueueReverts(r, 3, 2)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.Start(ctx)
	r.Wait() // Model an early Fuzzer return that has no artifact generation.
	enqueueReverts(r, 2, 0)
	r.Start(ctx)
	require.NoError(t, r.BuildArtifacts())
	metrics := r.RevertMetrics.ContractRevertMetrics["C"].FunctionRevertMetrics["f"]
	require.EqualValues(t, 2, metrics.TotalCalls)
	require.InDelta(t, float64(2)/3, metrics.PrevPct, 0.00001)
}

func TestRevertReporterClosed(t *testing.T) {
	r := reporterForTest(t)
	close(r.RevertMetricsCh)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx)
	done := make(chan struct{})
	go func() { r.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("closed channel did not finish reporter")
	}
}

func TestRevertReporterLoadedPrevious(t *testing.T) {
	r := reporterForTest(t)
	previous := NewRevertMetrics()
	for i := 0; i < 4; i++ {
		result := &core.ExecutionResult{}
		if i == 0 {
			result.Err = vm.ErrExecutionReverted
		}
		previous.Update(&RevertMetricsUpdate{ContractName: "C", FunctionName: "f", ExecutionResult: result}, nil)
	}
	previous.Finalize(NewRevertMetrics())
	b, err := json.Marshal(previous)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(r.Path, "revert_report.json"), b, 0600))
	r, err = NewRevertReporter(true, filepath.Dir(r.Path))
	require.NoError(t, err)
	enqueueReverts(r, 4, 2)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.Start(ctx)
	require.NoError(t, r.BuildArtifacts())
	metrics := r.RevertMetrics.ContractRevertMetrics["C"].FunctionRevertMetrics["f"]
	require.InDelta(t, 0.5, metrics.Pct, 0.00001)
	require.InDelta(t, 0.25, metrics.PrevPct, 0.00001)
}
