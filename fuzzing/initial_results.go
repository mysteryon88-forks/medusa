package fuzzing

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/crytic/medusa-geth/common"
	"github.com/crytic/medusa/chain"
	chainConfig "github.com/crytic/medusa/chain/config"
	chainTypes "github.com/crytic/medusa/chain/types"
	compilationTypes "github.com/crytic/medusa/compilation/types"
	"github.com/crytic/medusa/fuzzing/calls"
	"github.com/crytic/medusa/fuzzing/config"
	"github.com/crytic/medusa/fuzzing/contracts"
	"github.com/crytic/medusa/fuzzing/corpus"
	"github.com/crytic/medusa/fuzzing/executiontracer"
)

var errInitialUnrepresentable = errors.New("initial result unsupported")

func fingerprintJSON(value any) (common.Hash, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return common.Hash{}, err
	}
	return common.Hash(sha256.Sum256(b)), nil
}

func initialContractIdentity(contract *contracts.Contract) (common.Hash, error) {
	compiled := contract.CompiledContract()
	version := ""
	if compilation := contract.Compilation(); compilation != nil {
		version = compilation.CompilerVersion
	}
	if version == "" {
		version = "unknown"
	}
	// Crytic's solc export can omit provenance; bytecode metadata is also optional.
	var embeddedCompiler any = "unknown"
	if metadata := compilationTypes.ExtractContractMetadata(compiled.RuntimeBytecode); metadata != nil {
		if compiler, ok := (*metadata)["solc"]; ok {
			embeddedCompiler = compiler
		}
	}
	return fingerprintJSON(struct {
		Name             string
		ABI              any
		Init, Runtime    []byte
		CompilerVersion  string
		EmbeddedCompiler any
	}{contract.Name(), compiled.Abi, compiled.InitBytecode, compiled.RuntimeBytecode, version, embeddedCompiler})
}

func initialPreparedState(ch *chain.TestChain) (common.Hash, common.Hash, error) {
	if ch.PendingBlock() != nil {
		return common.Hash{}, common.Hash{}, fmt.Errorf("%w: setup has an uncommitted pending block", errInitialUnrepresentable)
	}
	root, err := initialStateRoot(ch.State())
	if err != nil {
		return common.Hash{}, common.Hash{}, err
	}
	if root != ch.Head().Header.Root {
		return common.Hash{}, common.Hash{}, fmt.Errorf("%w: setup state differs from the committed block", errInitialUnrepresentable)
	}
	// BLOCKHASH can observe earlier headers, not just the current block context.
	headers := make([]struct{ Header, ExecutionHash common.Hash }, len(ch.CommittedBlocks()))
	for i, block := range ch.CommittedBlocks() {
		headers[i].Header, headers[i].ExecutionHash = block.Header.Hash(), block.Hash
	}
	blockFingerprint, err := fingerprintJSON(headers)
	return root, blockFingerprint, err
}

func initialStateRoot(state chainTypes.MedusaStateDB) (common.Hash, error) {
	if err := state.Error(); err != nil {
		return common.Hash{}, fmt.Errorf("initial result state: %w", err)
	}
	root := state.IntermediateRoot(true)
	if err := state.Error(); err != nil {
		return common.Hash{}, fmt.Errorf("initial result state root: %w", err)
	}
	return root, nil
}

func (f *Fuzzer) initialPropertyResult(worker *FuzzerWorker, method contracts.DeployedContractMethod, testID string) (corpus.InitialPropertyResult, error) {
	result := corpus.InitialPropertyResult{SchemaVersion: 1, Kind: "initialPropertyFailure", TestID: testID,
		PropertySignature: method.Method.Sig, Address: method.Address, ContractName: method.Contract.Name(), Calls: calls.CallSequence{}}
	if f.config.Fuzzing.TestChainConfig.ForkConfig.ForkModeEnabled {
		return result, fmt.Errorf("%w: lazy RPC state cannot be fingerprinted for persistent replay", errInitialUnrepresentable)
	}
	var err error
	result.StateRoot, result.BlockFingerprint, err = initialPreparedState(worker.chain)
	if err != nil {
		return result, err
	}
	result.ContractIdentity, err = initialContractIdentity(method.Contract)
	if err != nil {
		return result, err
	}
	identities := make([]common.Hash, 0, len(f.contractDefinitions))
	for _, contract := range f.contractDefinitions {
		identity, err := initialContractIdentity(contract)
		if err != nil {
			return result, err
		}
		identities = append(identities, identity)
	}
	sort.Slice(identities, func(i, j int) bool { return identities[i].Hex() < identities[j].Hex() })
	result.ArtifactFingerprint, err = fingerprintJSON(identities)
	if err != nil {
		return result, err
	}
	cfg := f.config.Fuzzing
	chainCfg := cfg.TestChainConfig
	chainCfg.GenesisStateFile = ""
	chainCfg.ForkConfig.RpcUrl, chainCfg.ForkConfig.PoolSize = "", 0
	// This versioned projection excludes operational settings, paths and credentials.
	result.ConfigFingerprint, err = fingerprintJSON(struct {
		Chain                       chainConfig.TestChainConfig
		ChainID                     string
		BlockGasLimit, GasLimit     uint64
		Senders                     []common.Address
		Deployer                    common.Address
		Targets, PropertyPrefixes   []string
		Predeployed                 map[string]string
		Balances                    []*config.ContractBalance
		ConstructorArgs             map[string]map[string]any
		TestAllContracts            bool
		TargetFunctions, Exclusions []string
	}{chainCfg, worker.chain.ChainID().String(), worker.chain.BlockGasLimit, cfg.TransactionGasLimit,
		f.senders, f.deployer, cfg.TargetContracts, cfg.Testing.PropertyTesting.TestPrefixes,
		cfg.PredeployedContracts, cfg.TargetContractsBalances, cfg.ConstructorArgs, cfg.Testing.TestAllContracts,
		cfg.Testing.TargetFunctionSignatures, cfg.Testing.ExcludeFunctionSignatures})
	return result, err
}

func (t *PropertyTestCaseProvider) replayInitialResults(worker *FuzzerWorker) error {
	type reproduced struct {
		testCase *PropertyTestCase
		trace    *executiontracer.ExecutionTrace
		methodID contracts.ContractMethodID
	}
	failures := make([]reproduced, 0, len(t.fuzzer.initialResults))
	for _, saved := range t.fuzzer.initialResults {
		if err := t.fuzzer.emergencyCtx.Err(); err != nil {
			return err
		}
		label := fmt.Sprintf("initial replay %s test %s", saved.FileName, saved.TestID)
		contract := worker.deployedContracts[saved.Address]
		if contract == nil || contract.Name() != saved.ContractName {
			return fmt.Errorf("initial replay incompatible: %s: contract is not deployed at %s", label, saved.Address)
		}
		var method *contracts.DeployedContractMethod
		var testCase *PropertyTestCase
		for _, candidate := range contract.PropertyTestMethods {
			if candidate.Sig != saved.PropertySignature {
				continue
			}
			id := contracts.GetContractMethodID(contract, &candidate)
			t.testCasesLock.Lock()
			testCase = t.testCases[id]
			t.testCasesLock.Unlock()
			if testCase != nil && testCase.ID() == saved.TestID {
				method = &contracts.DeployedContractMethod{Address: saved.Address, Contract: contract, Method: candidate}
			}
			break
		}
		if method == nil {
			return fmt.Errorf("initial replay incompatible: %s: saved property is not enabled", label)
		}
		current, err := t.fuzzer.initialPropertyResult(worker, *method, testCase.ID())
		if err != nil {
			return fmt.Errorf("initial replay incompatible: %s: %w", label, err)
		}
		if !sameInitialInputs(saved, current) {
			return fmt.Errorf("initial replay incompatible: %s: artifacts, configuration or prepared state changed", label)
		}
		failed, trace, err := t.checkPropertyTestFailed(worker, method, true)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if err := t.fuzzer.emergencyCtx.Err(); err != nil {
			return err
		}
		if !failed {
			return fmt.Errorf("initial replay not reproduced: %s", label)
		}
		after, err := t.fuzzer.initialPropertyResult(worker, *method, testCase.ID())
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if !sameInitialInputs(current, after) {
			return fmt.Errorf("initial replay incompatible: %s: property evaluation changed prepared inputs", label)
		}
		failures = append(failures, reproduced{testCase, trace, contracts.GetContractMethodID(method.Contract, &method.Method)})
	}
	// Validate every loaded record before reporting a failure can trigger StopOnFailedTest.
	if err := t.fuzzer.emergencyCtx.Err(); err != nil {
		return err
	}
	for _, failure := range failures {
		if err := t.fuzzer.emergencyCtx.Err(); err != nil {
			return err
		}
		sequence := calls.CallSequence{}
		if _, err := t.finalizeFailure(worker, failure.testCase, &sequence, failure.trace); err != nil {
			return err
		}
		t.markMethodFailed(failure.methodID)
	}
	return nil
}

func sameInitialInputs(a, b corpus.InitialPropertyResult) bool {
	return a.TestID == b.TestID && a.PropertySignature == b.PropertySignature && a.Address == b.Address &&
		a.ContractName == b.ContractName && a.ContractIdentity == b.ContractIdentity &&
		a.ArtifactFingerprint == b.ArtifactFingerprint && a.ConfigFingerprint == b.ConfigFingerprint &&
		a.StateRoot == b.StateRoot && a.BlockFingerprint == b.BlockFingerprint
}
