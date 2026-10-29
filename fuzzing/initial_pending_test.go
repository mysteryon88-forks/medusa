package fuzzing

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crytic/medusa-geth/accounts/abi"
	"github.com/crytic/medusa-geth/common"
	gethTypes "github.com/crytic/medusa-geth/core/types"
	"github.com/crytic/medusa/chain"
	compilationTypes "github.com/crytic/medusa/compilation/types"
	"github.com/crytic/medusa/fuzzing/calls"
	"github.com/crytic/medusa/fuzzing/contracts"
	"github.com/crytic/medusa/fuzzing/corpus"
	"github.com/stretchr/testify/require"
)

// newSourcePropertyFixture provides two source-distinct, identically named false properties without a compiler.
func newSourcePropertyFixture(t *testing.T, directory string) (*Fuzzer, *PropertyTestCaseProvider, *FuzzerWorker, []contracts.DeployedContractMethod) {
	t.Helper()
	f := newLifecycleFuzzer(t)
	f.ctx = context.Background()
	f.emergencyCtx = context.Background()
	f.config.Fuzzing.Testing.TestAllContracts = true
	f.config.Fuzzing.Testing.StopOnFailedTest = false
	f.config.Fuzzing.CorpusDirectory = directory
	f.metrics = newFuzzerMetrics(2, nil)
	f.testCasesFinished = make(map[string]TestCase)
	f.senders = []common.Address{common.HexToAddress("0x1234")}
	var err error
	f.corpus, err = corpus.NewCorpus(directory)
	require.NoError(t, err)
	parsed, err := abi.JSON(strings.NewReader(`[{"type":"function","name":"property_check","stateMutability":"view","inputs":[],"outputs":[{"type":"bool"}]}]`))
	require.NoError(t, err)
	method := parsed.Methods["property_check"]
	code := common.FromHex("0x600060005260206000f3")
	methods := make([]contracts.DeployedContractMethod, 2)
	alloc := gethTypes.GenesisAlloc{}
	deployed := make(map[common.Address]*contracts.Contract)
	for i, source := range []string{"A.sol", "B.sol"} {
		contract := contracts.NewContract("Same", source, &compilationTypes.CompiledContract{Abi: parsed, RuntimeBytecode: code}, compilationTypes.NewCompilation())
		contract.PropertyTestMethods = []abi.Method{method}
		f.contractDefinitions = append(f.contractDefinitions, contract)
		address := common.BytesToAddress([]byte{0x12, byte(i + 1)})
		alloc[address] = gethTypes.Account{Code: code}
		deployed[address] = contract
		methods[i] = contracts.DeployedContractMethod{Address: address, Contract: contract, Method: method}
	}
	ch, err := chain.NewTestChain(context.Background(), alloc, nil)
	require.NoError(t, err)
	t.Cleanup(func() { ch.Close() })
	p := &PropertyTestCaseProvider{fuzzer: f}
	require.NoError(t, p.onFuzzerStarting(FuzzerStartingEvent{}))
	w := &FuzzerWorker{fuzzer: f, chain: ch, deployedContracts: deployed}
	require.NoError(t, p.onWorkerCreated(FuzzerWorkerCreatedEvent{Worker: w}))
	return f, p, w, methods
}

// registerSourceProperty exercises the provider's deployment path, including worker resets.
func registerSourceProperty(t *testing.T, p *PropertyTestCaseProvider, w *FuzzerWorker, method contracts.DeployedContractMethod) {
	t.Helper()
	require.NoError(t, p.onWorkerDeployedContractAdded(FuzzerWorkerContractAddedEvent{
		Worker: w, ContractAddress: method.Address, ContractDefinition: method.Contract,
	}))
}

func TestInitialPendingSetup(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		for _, state := range []string{"eligible", "empty", "failed"} {
			t.Run(map[bool]string{false: "memory", true: "persistent"}[persistent]+"/"+state, func(t *testing.T) {
				directory := ""
				if persistent {
					directory = t.TempDir()
				}
				f, p, w, methods := newSourcePropertyFixture(t, directory)
				if state != "empty" {
					registerSourceProperty(t, p, w, methods[0])
				}
				if state == "failed" {
					require.NoError(t, p.checkInitialState(w))
				}
				beforeFailures := f.metrics.FailedSequences().Int64()
				pending, err := w.chain.PendingBlockCreate()
				require.NoError(t, err)
				beforeTime := pending.Header.Time
				require.ErrorContains(t, p.checkInitialState(w), "pending")
				require.Same(t, pending, w.chain.PendingBlock())
				require.Equal(t, beforeTime, pending.Header.Time)
				require.Equal(t, beforeFailures, f.metrics.FailedSequences().Int64())
				require.Zero(t, f.metrics.CallsTested().Sign())
			})
		}
	}
}

func TestSourceInitialSaveRetry(t *testing.T) {
	directory := t.TempDir()
	f, p, w, methods := newSourcePropertyFixture(t, directory)
	registerSourceProperty(t, p, w, methods[0])
	blocked := filepath.Join(directory, "initial_results")
	require.NoError(t, os.WriteFile(blocked, []byte("blocking file"), 0600))
	require.Error(t, p.checkInitialState(w))
	require.Zero(t, f.metrics.FailedSequences().Sign())
	require.NoError(t, os.Remove(blocked))
	require.NoError(t, p.checkInitialState(w))
	require.EqualValues(t, 1, f.metrics.FailedSequences().Int64())
	requests, err := p.callSequencePostCallTest(w, calls.CallSequence{})
	require.NoError(t, err)
	require.Empty(t, requests, "only the successfully finalized source should now be skipped")
}
