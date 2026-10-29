package fuzzing

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/crytic/medusa-geth/accounts/abi"
	"github.com/crytic/medusa-geth/common"
	gethTypes "github.com/crytic/medusa-geth/core/types"
	"github.com/crytic/medusa/chain"
	chainTypes "github.com/crytic/medusa/chain/types"
	compilationTypes "github.com/crytic/medusa/compilation/types"
	"github.com/crytic/medusa/fuzzing/calls"
	"github.com/crytic/medusa/fuzzing/contracts"
	"github.com/crytic/medusa/logging"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type initialErrorState struct {
	chainTypes.MedusaStateDB
	err                    error
	afterRoot, reachedRoot bool
}

func (s *initialErrorState) Error() error {
	if !s.afterRoot || s.reachedRoot {
		return s.err
	}
	return nil
}
func (s *initialErrorState) IntermediateRoot(bool) common.Hash {
	s.reachedRoot = true
	return common.HexToHash("0x1")
}

func TestInitialStateError(t *testing.T) {
	want := errors.New("state read failed")
	for _, after := range []bool{false, true} {
		_, err := initialStateRoot(&initialErrorState{err: want, afterRoot: after})
		require.ErrorIs(t, err, want)
	}
}

func TestInitialFingerprintInputs(t *testing.T) {
	f := newLifecycleFuzzer(t)
	ch, err := chain.NewTestChain(context.Background(), gethTypes.GenesisAlloc{}, nil)
	require.NoError(t, err)
	defer ch.Close()
	compiled := &compilationTypes.CompiledContract{InitBytecode: []byte{0x60}, RuntimeBytecode: []byte{0x60}}
	compilation := compilationTypes.NewCompilation()
	contract := contracts.NewContract("C", "absolute/first.sol", compiled, compilation)
	f.contractDefinitions = contracts.Contracts{contract}
	w := &FuzzerWorker{fuzzer: f, chain: ch}
	method := contracts.DeployedContractMethod{Contract: contract, Method: abi.Method{Sig: "p()"}}
	first, err := f.initialPropertyResult(w, method, "PROPERTY-C-p()")
	require.NoError(t, err)
	// Operational changes and source paths must not prevent a replay.
	f.config.Fuzzing.Workers, f.config.Fuzzing.Timeout, f.config.Fuzzing.TestLimit = 7, 20, 5
	f.config.Fuzzing.CorpusDirectory = "a different path"
	f.config.Fuzzing.Testing.PropertyTesting.CheckInitialState = true
	contract = contracts.NewContract("C", "other/absolute/path.sol", compiled, compilation)
	f.contractDefinitions, method.Contract = contracts.Contracts{contract}, contract
	second, err := f.initialPropertyResult(w, method, first.TestID)
	require.NoError(t, err)
	require.True(t, sameInitialInputs(first, second))
	// Metadata-free artifacts still distinguish known compiler versions from unknown provenance.
	compilation.CompilerVersion = "0.8.25"
	second, err = f.initialPropertyResult(w, method, first.TestID)
	require.NoError(t, err)
	require.NotEqual(t, first.ArtifactFingerprint, second.ArtifactFingerprint)
	beforeHash := ch.Head().Hash
	ch.Head().Hash[0] ^= 1
	changedHash, err := f.initialPropertyResult(w, method, first.TestID)
	require.NoError(t, err)
	require.NotEqual(t, second.BlockFingerprint, changedHash.BlockFingerprint)
	ch.Head().Hash = beforeHash
	f.config.Fuzzing.TestChainConfig.ForkConfig.ForkModeEnabled = true
	_, err = f.initialPropertyResult(w, method, first.TestID)
	require.ErrorIs(t, err, errInitialUnrepresentable)
	f.config.Fuzzing.TestChainConfig.ForkConfig.ForkModeEnabled = false
	_, err = ch.PendingBlockCreate()
	require.NoError(t, err)
	_, err = f.initialPropertyResult(w, method, first.TestID)
	require.ErrorIs(t, err, errInitialUnrepresentable)
}

type initialCallbackWriter struct{ write func() }

func (w initialCallbackWriter) Write(b []byte) (int, error) { w.write(); return len(b), nil }

type initialCallbackCase struct {
	TestCase
	callback func()
}

func (c *initialCallbackCase) Status() TestCaseStatus { c.callback(); return c.TestCase.Status() }
func (c *initialCallbackCase) ID() string             { c.callback(); return c.TestCase.ID() }

func TestInitialReportingReentrant(t *testing.T) {
	f := newLifecycleFuzzer(t)
	f.testCasesFinished = make(map[string]TestCase)
	f.config.Fuzzing.Testing.StopOnFailedTest = false
	var held atomic.Bool
	probe := func() bool {
		if !f.testCasesLock.TryLock() {
			held.Store(true)
			return false
		}
		f.testCasesLock.Unlock()
		return true
	}
	f.logger = logging.NewLogger(zerolog.InfoLevel)
	f.logger.AddWriter(initialCallbackWriter{func() {
		if probe() {
			_ = f.TestCasesWithStatus(TestCaseStatusRunning)
		}
	}}, logging.STRUCTURED, false)
	base := &PropertyTestCase{targetContract: contracts.NewContract("C", "C.sol", nil, nil), targetMethod: abi.Method{Sig: "p()"}, status: TestCaseStatusRunning}
	c := &initialCallbackCase{TestCase: base, callback: func() {
		if probe() {
			_ = f.TestCases()
		}
	}}
	f.RegisterTestCase(c)
	_ = f.TestCasesWithStatus(TestCaseStatusRunning)
	sequence := calls.CallSequence{}
	accepted, pending, err := base.tryFinalizeFailure(&sequence, nil)
	require.NoError(t, err)
	require.Nil(t, pending)
	require.True(t, accepted)
	f.ReportTestCaseFinished(c)
	require.False(t, held.Load(), "logger/TestCase callbacks must not run under testCasesLock")
	snapshot := f.TestCases()
	snapshot[0] = nil
	require.NotNil(t, f.TestCases()[0])
}

func TestInitialReservation(t *testing.T) {
	c := &PropertyTestCase{status: TestCaseStatusRunning}
	reservation, owner := c.beginInitialFailure()
	require.True(t, owner)
	other, owner := c.beginInitialFailure()
	require.False(t, owner)
	require.Equal(t, reservation, other)
	sequence := calls.CallSequence{}
	accepted, pending, err := c.tryFinalizeFailure(&sequence, nil)
	require.NoError(t, err)
	require.False(t, accepted)
	require.Equal(t, (<-chan struct{})(reservation), pending)
	require.False(t, c.completeInitialFailure(reservation, &sequence, nil, errors.New("disk failed")))
	select {
	case <-other:
	default:
		t.Fatal("save failure did not release contenders")
	}
	require.Equal(t, TestCaseStatusRunning, c.Status())
	reservation, owner = c.beginInitialFailure()
	require.True(t, owner)
	require.True(t, c.completeInitialFailure(reservation, &sequence, nil, nil))
	accepted, pending, err = c.tryFinalizeFailure(&sequence, nil)
	require.NoError(t, err)
	require.False(t, accepted)
	require.Nil(t, pending)
	reservation, owner = c.beginInitialFailure()
	require.False(t, owner)
	require.Nil(t, reservation)
}

func TestInitialForkMemoryEvaluation(t *testing.T) {
	f := newLifecycleFuzzer(t)
	f.config.Fuzzing.TestChainConfig.ForkConfig.ForkModeEnabled = true
	f.emergencyCtx = context.Background()
	f.metrics = newFuzzerMetrics(1, nil)
	f.testCasesFinished = make(map[string]TestCase)
	parsedABI, err := abi.JSON(strings.NewReader(`[{"type":"function","name":"property_p","stateMutability":"view","inputs":[],"outputs":[{"type":"bool"}]}]`))
	require.NoError(t, err)
	code := common.FromHex("0x600060005260206000f3") // return false
	contract := contracts.NewContract("C", "C.sol", &compilationTypes.CompiledContract{Abi: parsedABI, RuntimeBytecode: code}, compilationTypes.NewCompilation())
	address := common.HexToAddress("0x123456")
	// Local StateDB isolates the routing test; no external RPC is contacted.
	ch, err := chain.NewTestChain(context.Background(), gethTypes.GenesisAlloc{address: {Code: code}}, nil)
	require.NoError(t, err)
	defer ch.Close()
	method := contracts.DeployedContractMethod{Address: address, Contract: contract, Method: parsedABI.Methods["property_p"]}
	id := contracts.GetContractMethodID(contract, &method.Method)
	testCase := &PropertyTestCase{targetContract: contract, targetMethod: method.Method, status: TestCaseStatusRunning}
	p := &PropertyTestCaseProvider{
		fuzzer:         f,
		testCases:      map[contracts.ContractMethodID]*PropertyTestCase{id: testCase},
		methodStatuses: map[contracts.ContractMethodID]TestCaseStatus{id: TestCaseStatusRunning},
		workerStates:   []propertyTestCaseProviderWorkerState{{propertyTestMethods: map[contracts.ContractMethodID]contracts.DeployedContractMethod{id: method}}},
	}
	require.NoError(t, p.checkInitialState(&FuzzerWorker{fuzzer: f, chain: ch}))
	require.Equal(t, TestCaseStatusFailed, testCase.Status())
	require.NotNil(t, testCase.CallSequence())
	require.Empty(t, *testCase.CallSequence())
}
