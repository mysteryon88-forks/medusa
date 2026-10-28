package fuzzing

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/crytic/medusa-geth/accounts/abi"
	"github.com/crytic/medusa-geth/common"
	gethTypes "github.com/crytic/medusa-geth/core/types"
	"github.com/crytic/medusa/chain"
	chainTypes "github.com/crytic/medusa/chain/types"
	"github.com/crytic/medusa/fuzzing/calls"
	"github.com/crytic/medusa/fuzzing/contracts"
	"github.com/stretchr/testify/require"
)

func TestFinalizedFailureOwnsSequence(t *testing.T) {
	for _, kind := range []string{"assertion", "property"} {
		t.Run(kind, func(t *testing.T) {
			f := newLifecycleFuzzer(t)
			f.metrics = newFuzzerMetrics(1, nil)
			f.testCasesFinished = make(map[string]TestCase)
			worker := &FuzzerWorker{fuzzer: f, workerIndex: 0}
			address := common.HexToAddress("0x1234")
			labels := map[common.Address]string{address: "before"}
			sequence := optimizationSequence(100)
			sequence[0].Call.From = address
			sequence[0].ChainReference = &calls.CallSequenceElementChainReference{
				Block: &chainTypes.Block{
					Header:         &gethTypes.Header{Number: big.NewInt(7)},
					MessageResults: []*chainTypes.MessageResults{{AdditionalResults: map[string]any{"Labels": labels}}},
				},
			}

			var published TestCase
			if kind == "assertion" {
				c := &AssertionTestCase{targetContract: contracts.NewContract("C", "C.sol", nil, nil)}
				accepted, err := (&AssertionTestCaseProvider{fuzzer: f}).finalizeFailure(worker, c, &sequence)
				require.NoError(t, err)
				require.True(t, accepted)
				published = c
			} else {
				c := &PropertyTestCase{targetContract: contracts.NewContract("C", "C.sol", nil, nil)}
				accepted, err := (&PropertyTestCaseProvider{fuzzer: f}).finalizeFailure(worker, c, &sequence, nil)
				require.NoError(t, err)
				require.True(t, accepted)
				published = c
			}
			message := published.Message()
			sequence[0].Call.GasLimit = 999
			sequence[0].ChainReference.Block.Header.Number.SetInt64(99)
			labels[address] = "after"

			result := (*published.CallSequence())[0]
			require.EqualValues(t, 100, result.Call.GasLimit)
			require.EqualValues(t, 7, result.ChainReference.Block.Header.Number.Int64())
			require.Equal(t, "before", chain.GetLabels(result.ChainReference.MessageResults())[address])
			require.Equal(t, message, published.Message())
			done := make(chan struct{})
			go func() {
				defer close(done)
				for i := 0; i < 1000; i++ {
					sequence[0].Call.GasLimit++
					labels[address] = "later"
				}
			}()
			for i := 0; i < 1000; i++ {
				_ = published.Message()
			}
			<-done
			require.Equal(t, message, published.Message())
		})
	}
}

func TestFailureSnapshotErrorDoesNotPublish(t *testing.T) {
	for _, kind := range []string{"property", "assertion"} {
		t.Run(kind, func(t *testing.T) {
			f := newLifecycleFuzzer(t)
			f.metrics = newFuzzerMetrics(1, nil)
			f.testCasesFinished = make(map[string]TestCase)
			w := &FuzzerWorker{fuzzer: f}
			uintType, err := abi.NewType("uint256", "", nil)
			require.NoError(t, err)
			method := &abi.Method{Inputs: abi.Arguments{{Type: uintType}}}
			bad := optimizationSequence(1)
			bad[0].Call.DataAbiValues = &calls.CallMessageDataAbiValues{Method: method}
			good := optimizationSequence(2)
			contract := contracts.NewContract("C", "C.sol", nil, nil)
			if kind == "property" {
				c := &PropertyTestCase{targetContract: contract}
				p := &PropertyTestCaseProvider{fuzzer: f}
				accepted, err := p.finalizeFailure(w, c, &bad, nil)
				require.Error(t, err)
				require.False(t, accepted)
				require.NotEqual(t, TestCaseStatusFailed, c.Status())
				accepted, err = p.finalizeFailure(w, c, &good, nil)
				require.NoError(t, err)
				require.True(t, accepted)
			} else {
				c := &AssertionTestCase{targetContract: contract}
				p := &AssertionTestCaseProvider{fuzzer: f}
				accepted, err := p.finalizeFailure(w, c, &bad)
				require.Error(t, err)
				require.False(t, accepted)
				require.NotEqual(t, TestCaseStatusFailed, c.Status())
				accepted, err = p.finalizeFailure(w, c, &good)
				require.NoError(t, err)
				require.True(t, accepted)
			}
			require.EqualValues(t, 1, f.metrics.FailedSequences().Int64())
			require.Len(t, f.testCasesFinished, 1)
		})
	}
}

func TestFailureWaitsForInitialSave(t *testing.T) {
	f := newLifecycleFuzzer(t)
	f.emergencyCtx = context.Background()
	f.metrics = newFuzzerMetrics(1, nil)
	f.testCasesFinished = make(map[string]TestCase)
	c := &PropertyTestCase{targetContract: contracts.NewContract("C", "C.sol", nil, nil)}
	p := &PropertyTestCaseProvider{fuzzer: f}
	reservation, owner := c.beginInitialFailure()
	require.True(t, owner)
	type result struct {
		accepted bool
		err      error
	}
	done := make(chan result, 1)
	sequence := calls.CallSequence{}
	go func() {
		accepted, err := p.finalizeFailure(&FuzzerWorker{fuzzer: f}, c, &sequence, nil)
		done <- result{accepted, err}
	}()
	require.False(t, c.completeInitialFailure(reservation, &sequence, nil, errors.New("save failed")))
	got := <-done
	require.NoError(t, got.err)
	require.True(t, got.accepted)
	require.EqualValues(t, 1, f.metrics.FailedSequences().Int64())
}
