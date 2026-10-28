package fuzzing

import (
	"context"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/crytic/medusa-geth/accounts/abi"
	"github.com/crytic/medusa-geth/common"
	gethTypes "github.com/crytic/medusa-geth/core/types"
	"github.com/crytic/medusa/chain"
	compilationTypes "github.com/crytic/medusa/compilation/types"
	"github.com/crytic/medusa/fuzzing/calls"
	"github.com/crytic/medusa/fuzzing/config"
	"github.com/crytic/medusa/fuzzing/contracts"
	"github.com/stretchr/testify/require"
)

func optimizationCase() *OptimizationTestCase {
	minimum, _ := new(big.Int).SetString(MIN_INT, 16)
	return &OptimizationTestCase{status: TestCaseStatusRunning, value: minimum, targetContract: contracts.NewContract("C", "C.sol", nil, nil), targetMethod: abi.Method{Sig: "optimize_p()"}}
}

func optimizationSequence(marker uint64) calls.CallSequence {
	to := common.HexToAddress("0x1234")
	return calls.CallSequence{&calls.CallSequenceElement{Call: calls.NewCallMessage(common.Address{}, &to, 0, new(big.Int), marker, new(big.Int), new(big.Int), new(big.Int), nil)}}
}

func TestRaceOptimizationResult(t *testing.T) {
	c := optimizationCase()
	start, stop := make(chan struct{}), make(chan struct{})
	var readers, writers sync.WaitGroup
	readers.Add(1)
	go func() {
		defer readers.Done()
		<-start
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = c.Status()
			_ = c.CallSequence()
			_ = c.Message()
			c.Value().SetInt64(-1)
		}
	}()
	errors := make([]error, 64)
	for i := range errors {
		writers.Add(1)
		go func() {
			defer writers.Done()
			<-start
			v := big.NewInt(int64(i + 1))
			_, errors[i] = c.updateCandidate(v, optimizationSequence(uint64(i+1)), &ShrinkCallSequenceRequest{})
			v.SetInt64(-999)
		}()
	}
	close(start)
	writers.Wait()
	close(stop)
	readers.Wait()
	for _, err := range errors {
		require.NoError(t, err)
	}
	require.EqualValues(t, 64, c.Value().Int64())
	require.EqualValues(t, 64, (*c.CallSequence())[0].Call.GasLimit)
	require.Equal(t, TestCaseStatusRunning, c.Status(), "logging must not finalize a live test")
	c.finish()
	require.Equal(t, TestCaseStatusPassed, c.Status())
}

func TestOptimizationOwnership(t *testing.T) {
	c := optimizationCase()
	seq := optimizationSequence(100)
	request := &ShrinkCallSequenceRequest{}
	accepted, err := c.updateCandidate(big.NewInt(100), seq, request)
	require.NoError(t, err)
	require.True(t, accepted)
	seq[0].Call.Nonce = 5
	taken := c.takeShrinkRequest()
	require.NotNil(t, taken)
	taken.CallSequenceToShrink[0].Call.Nonce = 6
	require.Zero(t, (*c.CallSequence())[0].Call.Nonce)
	require.Nil(t, c.takeShrinkRequest())
	accepted, err = c.updateFinal(big.NewInt(99), optimizationSequence(99), nil)
	require.NoError(t, err)
	require.False(t, accepted)
	require.EqualValues(t, 100, c.Value().Int64())
	v := big.NewInt(120)
	accepted, err = c.updateFinal(v, optimizationSequence(120), nil)
	require.NoError(t, err)
	require.True(t, accepted)
	v.SetInt64(0)
	require.EqualValues(t, 120, c.Value().Int64())
	accepted, err = c.updateFinal(big.NewInt(120), calls.CallSequence{}, nil)
	require.NoError(t, err)
	require.True(t, accepted)
	require.Empty(t, *c.CallSequence())
	minimum := optimizationCase()
	minimum.finish()
	require.Equal(t, TestCaseStatusFailed, minimum.Status())
}

func TestOptimizationVerifierError(t *testing.T) {
	f := newLifecycleFuzzer(t)
	parsed, err := abi.JSON(strings.NewReader(`[{"type":"function","name":"optimize_p","stateMutability":"view","inputs":[],"outputs":[{"type":"int256"}]}]`))
	require.NoError(t, err)
	code := common.FromHex("0x600160005260206000f3")
	contract := contracts.NewContract("C", "C.sol", &compilationTypes.CompiledContract{Abi: parsed, RuntimeBytecode: code}, compilationTypes.NewCompilation())
	address := common.HexToAddress("0x123456")
	ch, err := chain.NewTestChain(context.Background(), gethTypes.GenesisAlloc{address: {Code: code}}, nil)
	require.NoError(t, err)
	defer ch.Close()
	method := contracts.DeployedContractMethod{Address: address, Contract: contract, Method: parsed.Methods["optimize_p"]}
	id := contracts.GetContractMethodID(contract, &method.Method)
	c := optimizationCase()
	p := &OptimizationTestCaseProvider{fuzzer: f, testCases: map[contracts.ContractMethodID]*OptimizationTestCase{id: c}, workerStates: []optimizationTestCaseProviderWorkerState{{optimizationTestMethods: map[contracts.ContractMethodID]contracts.DeployedContractMethod{id: method}}}}
	w := &FuzzerWorker{fuzzer: f, chain: ch, deployedContracts: map[common.Address]*contracts.Contract{address: contract}}
	_, err = p.callSequencePostCallTest(w, optimizationSequence(100))
	require.NoError(t, err)
	req := c.takeShrinkRequest()
	require.NotNil(t, req)
	ch.State().SetCode(address, common.FromHex("0x600060005360016000f3"))
	require.NotPanics(t, func() {
		valid, err := req.VerifierFunction(w, calls.CallSequence{})
		require.False(t, valid)
		require.ErrorContains(t, err, "decode optimization")
	})
}

func TestOptimizationSequential(t *testing.T) {
	runFuzzerTest(t, &fuzzerSolcFileTest{
		filePath: "testdata/contracts/optimizations/optimize.sol", solcVersion: "0.8.25",
		configUpdates: func(c *config.ProjectConfig) {
			initialTestConfig(c)
			c.Fuzzing.Workers = 1
			c.Fuzzing.ShrinkLimit = 5000
			c.Fuzzing.TestLimit = 10_000
			c.Fuzzing.Timeout = 0
			c.Fuzzing.Testing.PropertyTesting.Enabled = false
			c.Fuzzing.Testing.OptimizationTesting.Enabled = true
		},
		method: func(fc *fuzzerTestContext) {
			for i := 0; i < 2; i++ {
				require.NoError(fc.t, fc.fuzzer.Start())
				cases := fc.fuzzer.TestCasesWithStatus(TestCaseStatusPassed)
				require.Len(fc.t, cases, 1)
				c := cases[0].(*OptimizationTestCase)
				require.EqualValues(fc.t, 4241, c.Value().Int64())
				require.NotNil(fc.t, c.CallSequence())
				require.NotNil(fc.t, c.optimizationTestTrace, "each campaign must shrink and trace its winner")
			}
		},
	})
}

func TestOptimizationRuntimeSnapshot(t *testing.T) {
	from, to := common.HexToAddress("0x10000"), common.HexToAddress("0x123456")
	ch, err := chain.NewTestChain(context.Background(), gethTypes.GenesisAlloc{from: {Balance: new(big.Int).Lsh(big.NewInt(1), 100)}}, nil)
	require.NoError(t, err)
	defer ch.Close()
	block, err := ch.PendingBlockCreate()
	require.NoError(t, err)
	ch.Labels[from] = "initial-sender"
	newCall := func() *calls.CallMessage {
		m := calls.NewCallMessage(from, &to, 0, new(big.Int), 100000, big.NewInt(1), new(big.Int), new(big.Int), nil)
		m.FillFromTestChainProperties(ch)
		return m
	}
	m := newCall()
	require.NoError(t, ch.PendingBlockAddTx(m.ToCoreMessage()))
	seq := calls.CallSequence{calls.NewCallSequenceElement(nil, m, 1, 1)}
	seq[0].ChainReference = &calls.CallSequenceElementChainReference{Block: block, TransactionIndex: 0, BlockNumber: block.Header.Number.Uint64(), BlockTimestamp: block.Header.Time}
	c := optimizationCase()
	_, err = c.updateCandidate(big.NewInt(1), seq, &ShrinkCallSequenceRequest{})
	require.NoError(t, err)
	request := c.takeShrinkRequest()
	resultBlock := (*c.CallSequence())[0].ChainReference.Block
	require.NotSame(t, resultBlock, request.CallSequenceToShrink[0].ChainReference.Block)
	request.CallSequenceToShrink[0].ChainReference.Block.Header.GasUsed++
	require.NotEqual(t, resultBlock.Header.GasUsed, request.CallSequenceToShrink[0].ChainReference.Block.Header.GasUsed)
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				_ = c.Message()
			}
		}
	}()
	defer func() { close(stop); <-done }()
	for i := 0; i < 100; i++ {
		ch.Labels[from] = "next-" + strconv.Itoa(i)
		require.NoError(t, ch.PendingBlockAddTx(newCall().ToCoreMessage()))
	}
	result := (*c.CallSequence())[0].ChainReference
	require.NotSame(t, block, result.Block)
	require.Len(t, result.Block.MessageResults, 1)
	require.Len(t, block.MessageResults, 101)
	require.Contains(t, c.Message(), "initial-sender")
}
