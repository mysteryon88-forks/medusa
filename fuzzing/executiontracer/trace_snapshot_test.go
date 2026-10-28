package executiontracer

import (
	"testing"

	"github.com/crytic/medusa-geth/common"
	"github.com/stretchr/testify/require"
)

func TestCompletedTraceLabels(t *testing.T) {
	address, hash := common.HexToAddress("0x1"), common.HexToHash("0x2")
	labels := map[common.Address]string{address: "before"}
	stored := &ExecutionTrace{labels: labels}
	tracer := &ExecutionTracer{traceMap: map[common.Hash]*ExecutionTrace{hash: stored}}
	snapshot := tracer.GetTrace(hash)
	labels[address] = "after"
	require.NotSame(t, stored, snapshot)
	require.Equal(t, "before", snapshot.labels[address])
	require.Equal(t, "after", tracer.GetTrace(hash).labels[address])
}
