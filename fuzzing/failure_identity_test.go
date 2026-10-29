package fuzzing

import (
	"context"
	"math/big"
	"strings"
	"sync"
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

func TestSourcePropertyAfterFailure(t *testing.T) {
	f, p, w, methods := newSourcePropertyFixture(t, "")
	registerSourceProperty(t, p, w, methods[0])
	requests, err := p.callSequencePostCallTest(w, calls.CallSequence{})
	require.NoError(t, err)
	require.Len(t, requests, 1)
	require.NoError(t, requests[0].FinishedCallback(w, calls.CallSequence{}, 0))
	first := f.TestCases()[0].CallSequence()

	// B is deployed after A has finalized the shared public result.
	registerSourceProperty(t, p, w, methods[1])
	requests, err = p.callSequencePostCallTest(w, calls.CallSequence{})
	require.NoError(t, err)
	require.Len(t, requests, 1, "the second source must still be evaluated and shrunk")
	require.NoError(t, requests[0].FinishedCallback(w, calls.CallSequence{}, 0))
	require.Same(t, first, f.TestCases()[0].CallSequence())
	require.EqualValues(t, 1, f.metrics.FailedSequences().Int64())
	require.Len(t, f.TestCases(), 1)

	// A worker reset must retain source completion without using the public status as its gate.
	require.NoError(t, p.onWorkerCreated(FuzzerWorkerCreatedEvent{Worker: w}))
	for _, method := range methods {
		registerSourceProperty(t, p, w, method)
	}
	requests, err = p.callSequencePostCallTest(w, calls.CallSequence{})
	require.NoError(t, err)
	require.Empty(t, requests)

	// A fresh campaign must make both source methods eligible again.
	f.testCases = nil
	require.NoError(t, p.onFuzzerStarting(FuzzerStartingEvent{}))
	require.NoError(t, p.onWorkerCreated(FuzzerWorkerCreatedEvent{Worker: w}))
	for _, method := range methods {
		registerSourceProperty(t, p, w, method)
	}
	requests, err = p.callSequencePostCallTest(w, calls.CallSequence{})
	require.NoError(t, err)
	require.Len(t, requests, 2)
}

func TestSourceInitialAfterFailure(t *testing.T) {
	for _, replay := range []bool{false, true} {
		t.Run(map[bool]string{false: "initial", true: "replay"}[replay], func(t *testing.T) {
			f, p, w, methods := newSourcePropertyFixture(t, "")
			registerSourceProperty(t, p, w, methods[0])
			require.NoError(t, p.checkInitialState(w))
			if replay {
				f.initialResults = f.corpus.InitialPropertyResults()
				require.Len(t, f.initialResults, 1)
				f.testCases = nil
				f.testCasesFinished = make(map[string]TestCase)
				f.metrics = newFuzzerMetrics(2, nil)
				require.NoError(t, p.onFuzzerStarting(FuzzerStartingEvent{}))
				require.NoError(t, p.onWorkerCreated(FuzzerWorkerCreatedEvent{Worker: w}))
				registerSourceProperty(t, p, w, methods[0])
				require.NoError(t, p.replayInitialResults(w))
			}
			first := f.TestCases()[0].CallSequence()
			registerSourceProperty(t, p, w, methods[1])
			id := contracts.GetContractMethodID(methods[1].Contract, &methods[1].Method)
			method, exists := p.workerStates[0].propertyTestMethods[id]
			require.True(t, exists, "a different failed source must not prevent registration")
			method.Method.Outputs = nil
			p.workerStates[0].propertyTestMethods[id] = method
			require.Error(t, p.checkInitialState(w), "B must actually execute and surface its invalid ABI")
			p.workerStates[0].propertyTestMethods[id] = methods[1]
			require.NoError(t, p.checkInitialState(w))
			require.Same(t, first, f.TestCases()[0].CallSequence())
			require.EqualValues(t, 1, f.metrics.FailedSequences().Int64())
			require.Len(t, f.corpus.InitialPropertyResults(), 1)
			requests, err := p.callSequencePostCallTest(w, calls.CallSequence{})
			require.NoError(t, err)
			require.Empty(t, requests, "successful nonwinning source finalization must complete that source")
		})
	}
}

func TestSourcePropertyConcurrentFailure(t *testing.T) {
	f, p, firstWorker, methods := newSourcePropertyFixture(t, "")
	secondChain, err := firstWorker.chain.Clone(nil)
	require.NoError(t, err)
	t.Cleanup(func() { secondChain.Close() })
	secondWorker := &FuzzerWorker{fuzzer: f, chain: secondChain, workerIndex: 1, deployedContracts: firstWorker.deployedContracts}
	require.NoError(t, p.onWorkerCreated(FuzzerWorkerCreatedEvent{Worker: secondWorker}))
	workers := []*FuzzerWorker{firstWorker, secondWorker}
	requests := make([]ShrinkCallSequenceRequest, 2)
	for i, w := range workers {
		registerSourceProperty(t, p, w, methods[i])
		found, err := p.callSequencePostCallTest(w, calls.CallSequence{})
		require.NoError(t, err)
		require.Len(t, found, 1)
		requests[i] = found[0]
	}
	var wg sync.WaitGroup
	errors := make(chan error, 2)
	for i, w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errors <- requests[i].FinishedCallback(w, calls.CallSequence{}, 0)
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
	require.EqualValues(t, 1, f.metrics.FailedSequences().Int64())
	require.Len(t, f.testCasesFinished, 1)
	for _, w := range workers {
		found, err := p.callSequencePostCallTest(w, calls.CallSequence{})
		require.NoError(t, err)
		require.Empty(t, found)
	}
}

func TestSourceAssertionAfterFailure(t *testing.T) {
	f := newLifecycleFuzzer(t)
	f.config.Fuzzing.Testing.TestAllContracts = true
	f.config.Fuzzing.Testing.StopOnFailedTest = false
	f.metrics = newFuzzerMetrics(1, nil)
	f.testCasesFinished = make(map[string]TestCase)
	parsed, err := abi.JSON(strings.NewReader(`[{"type":"function","name":"test","stateMutability":"nonpayable","inputs":[],"outputs":[]}]`))
	require.NoError(t, err)
	method := parsed.Methods["test"]
	// Return Solidity's Panic(0x01) payload from both source implementations.
	code := common.FromHex("0x634e487b7160e01b600052600160045260246000fd")
	from := common.HexToAddress("0x1234")
	addresses := []common.Address{common.HexToAddress("0x123456"), common.HexToAddress("0x234567")}
	ch, err := chain.NewTestChain(context.Background(), gethTypes.GenesisAlloc{
		from: {Balance: big.NewInt(1000000000)}, addresses[0]: {Code: code}, addresses[1]: {Code: code},
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { ch.Close() })
	base := uint64(len(ch.CommittedBlocks()))
	deployed := make(map[common.Address]*contracts.Contract)
	for i, source := range []string{"A.sol", "B.sol"} {
		contract := contracts.NewContract("Same", source, &compilationTypes.CompiledContract{Abi: parsed, RuntimeBytecode: code}, compilationTypes.NewCompilation())
		contract.AssertionTestMethods = []abi.Method{method}
		f.contractDefinitions = append(f.contractDefinitions, contract)
		deployed[addresses[i]] = contract
	}
	p := &AssertionTestCaseProvider{fuzzer: f}
	require.NoError(t, p.onFuzzerStarting(FuzzerStartingEvent{}))
	w := &FuzzerWorker{fuzzer: f, chain: ch, deployedContracts: deployed}
	var first *calls.CallSequence
	for i, address := range addresses {
		require.NoError(t, ch.RevertToBlockIndex(base))
		require.NoError(t, p.onWorkerDeployedContractAdded(FuzzerWorkerContractAddedEvent{Worker: w, ContractAddress: address, ContractDefinition: deployed[address]}))
		call := calls.NewCallMessageWithAbiValueData(from, &address, 0, new(big.Int), 500000, big.NewInt(1), new(big.Int), new(big.Int), &calls.CallMessageDataAbiValues{Method: &method})
		sequence, err := calls.ExecuteCallSequence(ch, calls.CallSequence{{Contract: deployed[address], Call: call}})
		require.NoError(t, err)
		requests, err := p.callSequencePostCallTest(w, sequence)
		require.NoError(t, err)
		require.Len(t, requests, 1, "each source must produce its own assertion shrink request")
		require.NoError(t, ch.RevertToBlockIndex(base))
		require.NoError(t, requests[0].FinishedCallback(w, sequence, 0))
		if i == 0 {
			first = f.TestCases()[0].CallSequence()
		} else {
			require.Same(t, first, f.TestCases()[0].CallSequence())
		}
		requests, err = p.callSequencePostCallTest(w, sequence)
		require.NoError(t, err)
		require.Empty(t, requests, "only this completed source should be skipped")
	}
	require.Len(t, f.TestCases(), 1)
	require.EqualValues(t, 1, f.metrics.FailedSequences().Int64())
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
