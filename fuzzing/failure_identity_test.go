package fuzzing

import (
	"context"
	"strings"
	"testing"

	"github.com/crytic/medusa-geth/accounts/abi"
	"github.com/crytic/medusa-geth/common"
	gethTypes "github.com/crytic/medusa-geth/core/types"
	"github.com/crytic/medusa/chain"
	compilationTypes "github.com/crytic/medusa/compilation/types"
	"github.com/crytic/medusa/fuzzing/calls"
	"github.com/crytic/medusa/fuzzing/contracts"
	"github.com/stretchr/testify/require"
)

func TestFailureIdentityAcrossSourcePaths(t *testing.T) {
	for _, kind := range []string{"property", "assertion"} {
		t.Run(kind, func(t *testing.T) {
			f := newLifecycleFuzzer(t)
			f.config.Fuzzing.Testing.TestAllContracts = true
			f.metrics = newFuzzerMetrics(1, nil)
			f.testCasesFinished = make(map[string]TestCase)
			method := abi.Method{Name: "test", Sig: "test()"}
			first := contracts.NewContract("Same", "A.sol", nil, nil)
			second := contracts.NewContract("Same", "B.sol", nil, nil)
			f.contractDefinitions = contracts.Contracts{first, second}
			firstID := contracts.GetContractMethodID(first, &method)
			secondID := contracts.GetContractMethodID(second, &method)
			require.NotEqual(t, firstID, secondID)
			w := &FuzzerWorker{fuzzer: f, workerIndex: 0}
			sequence := calls.CallSequence{}
			if kind == "property" {
				first.PropertyTestMethods = []abi.Method{method}
				second.PropertyTestMethods = []abi.Method{method}
				p := &PropertyTestCaseProvider{fuzzer: f}
				require.NoError(t, p.onFuzzerStarting(FuzzerStartingEvent{}))
				a, b := p.testCases[firstID], p.testCases[secondID]
				require.Equal(t, a.ID(), b.ID())
				accepted, err := p.finalizeFailure(w, a, &sequence, nil)
				require.NoError(t, err)
				require.True(t, accepted)
				accepted, err = p.finalizeFailure(w, b, &sequence, nil)
				require.NoError(t, err)
				require.False(t, accepted)
			} else {
				first.AssertionTestMethods = []abi.Method{method}
				second.AssertionTestMethods = []abi.Method{method}
				p := &AssertionTestCaseProvider{fuzzer: f}
				require.NoError(t, p.onFuzzerStarting(FuzzerStartingEvent{}))
				a, b := p.testCases[firstID], p.testCases[secondID]
				require.Equal(t, a.ID(), b.ID())
				accepted, err := p.finalizeFailure(w, a, &sequence)
				require.NoError(t, err)
				require.True(t, accepted)
				accepted, err = p.finalizeFailure(w, b, &sequence)
				require.NoError(t, err)
				require.False(t, accepted)
			}
			require.Len(t, f.TestCases(), 1)
			require.EqualValues(t, 1, f.metrics.FailedSequences().Int64())
			require.Len(t, f.testCasesFinished, 1)
		})
	}
}

func TestFailureIdentityExecutesMethodsFromBothSourcePaths(t *testing.T) {
	f := newLifecycleFuzzer(t)
	f.config.Fuzzing.Workers = 1
	f.config.Fuzzing.Testing.TestAllContracts = true
	f.metrics = newFuzzerMetrics(1, nil)
	f.testCasesFinished = make(map[string]TestCase)
	f.senders = []common.Address{common.HexToAddress("0x1234")}

	parsedABI, err := abi.JSON(strings.NewReader(`[{"type":"function","name":"property_check","stateMutability":"view","inputs":[],"outputs":[{"type":"bool"}]}]`))
	require.NoError(t, err)
	method := parsedABI.Methods["property_check"]
	trueCode := common.FromHex("0x600160005260206000f3")
	falseCode := common.FromHex("0x600060005260206000f3")
	first := contracts.NewContract("Same", "A.sol", &compilationTypes.CompiledContract{Abi: parsedABI, RuntimeBytecode: trueCode}, compilationTypes.NewCompilation())
	second := contracts.NewContract("Same", "B.sol", &compilationTypes.CompiledContract{Abi: parsedABI, RuntimeBytecode: falseCode}, compilationTypes.NewCompilation())
	first.PropertyTestMethods = []abi.Method{method}
	second.PropertyTestMethods = []abi.Method{method}
	f.contractDefinitions = contracts.Contracts{first, second}

	firstAddress, secondAddress := common.HexToAddress("0x123456"), common.HexToAddress("0x234567")
	ch, err := chain.NewTestChain(context.Background(), gethTypes.GenesisAlloc{
		firstAddress:  {Code: trueCode},
		secondAddress: {Code: falseCode},
	}, nil)
	require.NoError(t, err)
	defer ch.Close()

	provider := &PropertyTestCaseProvider{fuzzer: f}
	require.NoError(t, provider.onFuzzerStarting(FuzzerStartingEvent{}))
	worker := &FuzzerWorker{fuzzer: f, chain: ch, workerIndex: 0}
	require.NoError(t, provider.onWorkerCreated(FuzzerWorkerCreatedEvent{Worker: worker}))
	for _, deployed := range []struct {
		address  common.Address
		contract *contracts.Contract
	}{{firstAddress, first}, {secondAddress, second}} {
		require.NoError(t, provider.onWorkerDeployedContractAdded(FuzzerWorkerContractAddedEvent{
			Worker: worker, ContractAddress: deployed.address, ContractDefinition: deployed.contract,
		}))
	}

	firstID := contracts.GetContractMethodID(first, &method)
	secondID := contracts.GetContractMethodID(second, &method)
	require.NotEqual(t, firstID, secondID)
	firstTest, secondTest := provider.testCases[firstID], provider.testCases[secondID]
	require.Same(t, firstTest, secondTest)
	require.Len(t, provider.workerStates[0].propertyTestMethods, 2)

	firstMethod := provider.workerStates[0].propertyTestMethods[firstID]
	failed, _, err := provider.checkPropertyTestFailed(worker, &firstMethod, false)
	require.NoError(t, err)
	require.False(t, failed, "A.sol property implementation returns true")
	secondMethod := provider.workerStates[0].propertyTestMethods[secondID]
	failed, _, err = provider.checkPropertyTestFailed(worker, &secondMethod, false)
	require.NoError(t, err)
	require.True(t, failed, "B.sol property implementation returns false")

	accepted, err := provider.finalizeFailure(worker, secondTest, &calls.CallSequence{}, nil)
	require.NoError(t, err)
	require.True(t, accepted)
	require.Len(t, f.TestCases(), 1)
	require.EqualValues(t, 1, f.metrics.FailedSequences().Int64())
}
