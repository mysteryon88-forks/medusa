package chain

import (
	"context"
	"math/big"
	"testing"

	"github.com/crytic/medusa-geth/common"
	"github.com/crytic/medusa-geth/core"
	"github.com/crytic/medusa-geth/core/tracing"
	"github.com/crytic/medusa-geth/core/types"
	"github.com/crytic/medusa-geth/eth/tracers"
	"github.com/stretchr/testify/require"
)

func TestCallContractInfrastructureError(t *testing.T) {
	ch, err := NewTestChain(context.Background(), types.GenesisAlloc{}, nil)
	require.NoError(t, err)
	defer ch.Close()
	to, from := common.HexToAddress("0x1"), common.HexToAddress("0x1234")
	var traceErr error
	var receipt *types.Receipt
	tracer := &TestChainTracer{Tracer: &tracers.Tracer{Hooks: &tracing.Hooks{OnTxEnd: func(r *types.Receipt, err error) { receipt, traceErr = r, err }}}}
	require.NotPanics(t, func() {
		result, err := ch.CallContract(&core.Message{From: from, To: &to, GasLimit: 1, Value: new(big.Int), GasPrice: big.NewInt(1), GasFeeCap: new(big.Int), GasTipCap: new(big.Int)}, nil, tracer)
		require.Nil(t, result)
		require.ErrorIs(t, err, core.ErrIntrinsicGas)
	})
	require.ErrorIs(t, traceErr, core.ErrIntrinsicGas)
	require.Equal(t, types.ReceiptStatusFailed, receipt.Status)
	require.Zero(t, ch.State().GetBalance(from).Sign())
	copyID := ch.ChainID()
	copyID.SetInt64(999)
	require.NotEqual(t, copyID, ch.ChainID())
}
