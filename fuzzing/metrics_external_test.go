package fuzzing_test

import (
	"math/big"
	"testing"

	"github.com/crytic/medusa/fuzzing"
	"github.com/stretchr/testify/require"
)

func TestFuzzerMetricsZero(t *testing.T) {
	var s fuzzing.FuzzerMetricsSnapshot
	for _, getter := range []func() *big.Int{s.CallsTested, s.SequencesTested, s.FailedSequences, s.GasUsed, s.WorkerStartupCount} {
		value := getter()
		require.Zero(t, value.Sign())
		value.SetInt64(1)
		require.Zero(t, getter().Sign())
	}
	require.Zero(t, s.WorkersShrinkingCount())
	n, available := s.CoverageMarkersHit()
	require.Zero(t, n)
	require.False(t, available)
	f := &fuzzing.Fuzzer{}
	require.Zero(t, f.Metrics().CallsTested().Sign())
	var legacy fuzzing.FuzzerMetrics
	require.Zero(t, legacy.CallsTested().Sign())
}
