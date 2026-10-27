package fuzzing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/crytic/medusa-geth/common"
	"github.com/crytic/medusa-geth/core/tracing"
	gethTypes "github.com/crytic/medusa-geth/core/types"
	"github.com/crytic/medusa-geth/eth/tracers"
	"github.com/crytic/medusa/chain"
	"github.com/crytic/medusa/fuzzing/calls"
	"github.com/crytic/medusa/fuzzing/config"
	"github.com/crytic/medusa/fuzzing/contracts"
	"github.com/crytic/medusa/fuzzing/corpus"
	"github.com/crytic/medusa/fuzzing/executiontracer"
	"github.com/stretchr/testify/require"
)

func TestFuzzerInitialGenesisDiscovery(t *testing.T) {
	runFuzzerTest(t, &fuzzerSolcFileTest{
		filePath: "testdata/contracts/assertions/assert_and_property_test.sol", solcVersion: "0.8.25",
		configUpdates: func(c *config.ProjectConfig) {
			c.Logging.NoColor = true
			c.Fuzzing.Workers = 1
			c.Fuzzing.Timeout = 2
			c.Fuzzing.TestLimit = 0
			c.Fuzzing.CallSequenceLength = 1
			c.Fuzzing.CoverageEnabled = false
			c.Fuzzing.CoverageFormats = nil
			c.Fuzzing.PruneFrequency = 0
			c.Fuzzing.TargetContracts = []string{"TestContract"}
			c.Fuzzing.Testing.AssertionTesting.Enabled = false
			c.Fuzzing.Testing.OptimizationTesting.Enabled = false
			c.Slither.UseSlither = false
		},
		method: func(fc *fuzzerTestContext) {
			t := fc.t
			f := fc.fuzzer
			address := "0x1111111111111111111111111111111111111111"
			genesis := map[string]any{address: map[string]any{
				"balance": "0x0", "nonce": "0x1",
				"code":    "0x" + hex.EncodeToString(f.contractDefinitions[0].CompiledContract().RuntimeBytecode),
				"storage": map[string]string{},
			}}
			b, err := json.Marshal(genesis)
			require.NoError(t, err)
			path := filepath.Join(t.TempDir(), "genesis.json")
			require.NoError(t, os.WriteFile(path, b, 0600))
			f.config.Fuzzing.TestChainConfig.GenesisStateFile = path
			f.config.Fuzzing.TestChainConfig.GenesisContractMappings = map[string]string{address: "TestContract"}
			f.Hooks.ChainSetupFunc = func(*Fuzzer, *chain.TestChain) (*executiontracer.ExecutionTrace, error) { return nil, nil }
			require.NoError(t, f.Start())
			require.Len(t, f.TestCasesWithStatus(TestCaseStatusFailed), 1)
			f.config.Fuzzing.Testing.PropertyTesting.CheckInitialState = true
			f.config.Fuzzing.TargetContracts = nil
			f.config.Fuzzing.Testing.StopOnNoTests = false
			f.Events.WorkerCreated.Subscribe(func(e FuzzerWorkerCreatedEvent) error {
				e.Worker.Events.FuzzerWorkerChainSetup.Subscribe(func(FuzzerWorkerChainSetupEvent) error { f.Stop(); return nil })
				return nil
			})
			require.NoError(t, f.Start())
			require.Empty(t, f.TestCasesWithStatus(TestCaseStatusFailed))
			f.config.Fuzzing.Testing.TestAllContracts = true
			require.NoError(t, f.Start())
			require.Len(t, f.TestCasesWithStatus(TestCaseStatusFailed), 1)
			require.Zero(t, f.Metrics().CallsTested().Sign())
		},
	})
}

func initialTestConfig(c *config.ProjectConfig) {
	c.Logging.NoColor = true
	c.Fuzzing.Workers = 2
	c.Fuzzing.Timeout = 3
	c.Fuzzing.TestLimit = 0
	c.Fuzzing.ShrinkLimit = 20
	c.Fuzzing.CallSequenceLength = 1
	c.Fuzzing.CoverageEnabled = false
	c.Fuzzing.CoverageFormats = nil
	c.Fuzzing.PruneFrequency = 0
	c.Fuzzing.TargetContracts = []string{"TestContract"}
	c.Fuzzing.Testing.AssertionTesting.Enabled = false
	c.Fuzzing.Testing.OptimizationTesting.Enabled = false
	c.Slither.UseSlither = false
}

func TestFuzzerInitialRepair(t *testing.T) {
	runFuzzerTest(t, &fuzzerSolcFileTest{
		filePath: "testdata/contracts/properties/initial_repair.sol", solcVersion: "0.8.25", configUpdates: initialTestConfig,
		method: func(fc *fuzzerTestContext) {
			t, f := fc.t, fc.fuzzer
			require.False(t, f.config.Fuzzing.Testing.PropertyTesting.CheckInitialState)
			var hooks atomic.Int32
			f.Hooks.CallSequenceTestFuncs = append(f.Hooks.CallSequenceTestFuncs, func(*FuzzerWorker, calls.CallSequence) ([]ShrinkCallSequenceRequest, error) {
				hooks.Add(1)
				f.Stop()
				return nil, nil
			})
			require.NoError(t, f.Start())
			require.Empty(t, f.TestCasesWithStatus(TestCaseStatusFailed))
			require.Positive(t, hooks.Load())
			f.config.Fuzzing.Testing.PropertyTesting.CheckInitialState = true
			hooks.Store(0)
			require.NoError(t, f.Start())
			failed := f.TestCasesWithStatus(TestCaseStatusFailed)
			require.Len(t, failed, 1)
			require.NotNil(t, failed[0].CallSequence())
			require.Empty(t, *failed[0].CallSequence())
			require.Contains(t, failed[0].Message(), "initial state")
			require.Zero(t, hooks.Load())
			s := f.Metrics()
			require.Zero(t, s.CallsTested().Sign())
			require.Zero(t, s.SequencesTested().Sign())
			require.Zero(t, s.GasUsed().Sign())
			require.Zero(t, s.WorkersShrinkingCount())
			require.EqualValues(t, 1, s.FailedSequences().Int64())
		},
	})
}

func TestFuzzerInitialOnly(t *testing.T) {
	runFuzzerTest(t, &fuzzerSolcFileTest{
		filePath: "testdata/contracts/properties/initial_only.sol", solcVersion: "0.8.25",
		configUpdates: func(c *config.ProjectConfig) {
			initialTestConfig(c)
			c.Fuzzing.Testing.PropertyTesting.CheckInitialState = true
		},
		method: func(fc *fuzzerTestContext) {
			t, f := fc.t, fc.fuzzer
			require.NoError(t, f.Start())
			require.Len(t, f.TestCasesWithStatus(TestCaseStatusFailed), 1)
			f.config.Fuzzing.TargetContracts = []string{"InitialTrue"}
			require.NoError(t, f.Start())
			require.Len(t, f.TestCasesWithStatus(TestCaseStatusPassed), 1)
			require.Empty(t, f.TestCasesWithStatus(TestCaseStatusFailed))
			require.Zero(t, f.Metrics().CallsTested().Sign())
		},
	})
}

func TestFuzzerInitialSetup(t *testing.T) {
	runFuzzerTest(t, &fuzzerSolcFileTest{
		filePath: "testdata/contracts/properties/initial_setup.sol", solcVersion: "0.8.25",
		configUpdates: func(c *config.ProjectConfig) {
			initialTestConfig(c)
			c.Fuzzing.Testing.PropertyTesting.CheckInitialState = true
		},
		method: func(fc *fuzzerTestContext) {
			t, f := fc.t, fc.fuzzer
			f.Events.WorkerCreated.Subscribe(func(e FuzzerWorkerCreatedEvent) error {
				// The first callback leaves the property false; the later one repairs it.
				for _, value := range []int64{0, 1} {
					value := value
					e.Worker.Events.FuzzerWorkerChainSetup.Subscribe(func(e FuzzerWorkerChainSetupEvent) error {
						if _, err := e.Chain.PendingBlockCreate(); err != nil {
							return err
						}
						for address := range e.Worker.DeployedContracts() {
							e.Chain.State().SetState(address, common.Hash{}, common.BigToHash(big.NewInt(value)))
						}
						if err := e.Chain.PendingBlockCommit(); err != nil {
							return err
						}
						if value == 1 {
							f.Stop()
						}
						return nil
					})
				}
				return nil
			})
			require.NoError(t, f.Start())
			require.Len(t, f.TestCasesWithStatus(TestCaseStatusPassed), 1)
			require.Empty(t, f.TestCasesWithStatus(TestCaseStatusFailed))
			require.Zero(t, f.Metrics().CallsTested().Sign())
		},
	})
}

func TestFuzzerInitialReplay(t *testing.T) {
	runFuzzerTest(t, &fuzzerSolcFileTest{
		filePath: "testdata/contracts/properties/initial_repair.sol", solcVersion: "0.8.25", configUpdates: initialTestConfig,
		method: func(fc *fuzzerTestContext) {
			t, f := fc.t, fc.fuzzer
			f.config.Fuzzing.CorpusDirectory = t.TempDir()
			f.config.Fuzzing.Testing.PropertyTesting.CheckInitialState = true
			require.NoError(t, f.Start())
			files, err := filepath.Glob(filepath.Join(f.config.Fuzzing.CorpusDirectory, "initial_results", "*.json"))
			require.NoError(t, err)
			require.Len(t, files, 1)
			f.config.Fuzzing.Testing.PropertyTesting.CheckInitialState = false
			baseConfig := f.config
			fresh, err := NewFuzzer(f.config)
			require.NoError(t, err)
			require.NoError(t, fresh.Start())
			require.Len(t, fresh.TestCasesWithStatus(TestCaseStatusFailed), 1)
			require.Zero(t, fresh.Metrics().CallsTested().Sign())
			require.Zero(t, fresh.Metrics().GasUsed().Sign())
			require.NotNil(t, fresh.TestCasesWithStatus(TestCaseStatusFailed)[0].CallSequence())
			// Disabling property testing must reject saved results before the no-tests guard.
			f.config.Fuzzing.Testing.PropertyTesting.Enabled = false
			disabled, err := NewFuzzer(f.config)
			require.NoError(t, err)
			require.ErrorContains(t, disabled.Start(), "initial replay unsupported")
			require.Zero(t, disabled.Metrics().CallsTested().Sign())
			f.config.Fuzzing.Testing.PropertyTesting.Enabled = true
			f.config.Fuzzing.SenderAddresses = []string{"0x20000"}
			changed, err := NewFuzzer(f.config)
			require.NoError(t, err)
			require.ErrorContains(t, changed.Start(), "initial replay incompatible")
			require.Zero(t, changed.Metrics().CallsTested().Sign())
			require.Empty(t, changed.TestCasesWithStatus(TestCaseStatusPassed))
			for _, change := range []string{"artifact", "setup"} {
				fresh, err := NewFuzzer(baseConfig)
				require.NoError(t, err)
				if change == "artifact" {
					compiled := fresh.contractDefinitions[0].CompiledContract()
					compiled.RuntimeBytecode = append([]byte(nil), compiled.RuntimeBytecode...)
					compiled.RuntimeBytecode[0] ^= 1
				} else {
					fresh.Events.WorkerCreated.Subscribe(func(e FuzzerWorkerCreatedEvent) error {
						e.Worker.Events.FuzzerWorkerChainSetup.Subscribe(func(e FuzzerWorkerChainSetupEvent) error {
							if _, err := e.Chain.PendingBlockCreate(); err != nil {
								return err
							}
							for address := range e.Worker.deployedContracts {
								e.Chain.State().SetState(address, common.Hash{}, common.HexToHash("0x1"))
							}
							return e.Chain.PendingBlockCommit()
						})
						return nil
					})
				}
				require.ErrorContains(t, fresh.Start(), "initial replay incompatible", change)
				require.Empty(t, fresh.TestCasesWithStatus(TestCaseStatusFailed))
				require.Empty(t, fresh.TestCasesWithStatus(TestCaseStatusPassed))
				require.Zero(t, fresh.Metrics().CallsTested().Sign())
			}
		},
	})
}

func TestFuzzerInitialNotReproduced(t *testing.T) {
	runFuzzerTest(t, &fuzzerSolcFileTest{
		filePath: "testdata/contracts/properties/initial_only.sol", solcVersion: "0.8.25", configUpdates: initialTestConfig,
		method: func(fc *fuzzerTestContext) {
			t, f := fc.t, fc.fuzzer
			f.config.Fuzzing.Testing.PropertyTesting.CheckInitialState = true
			f.config.Fuzzing.TargetContracts = []string{"InitialTrue"}
			var record corpus.InitialPropertyResult
			f.Events.WorkerCreated.Subscribe(func(e FuzzerWorkerCreatedEvent) error {
				e.Worker.Events.FuzzerWorkerChainSetup.Subscribe(func(e FuzzerWorkerChainSetupEvent) error {
					method := contractsMethodForTest(f.propertyTestProvider, e.Worker)
					var err error
					id := f.propertyTestProvider.testCases[contracts.GetContractMethodID(method.Contract, &method.Method)].ID()
					record, err = f.initialPropertyResult(e.Worker, method, id)
					return err
				})
				return nil
			})
			f.config.Fuzzing.Workers = 1
			require.NoError(t, f.Start())
			f.config.Fuzzing.CorpusDirectory = t.TempDir()
			c, err := corpus.NewCorpus(f.config.Fuzzing.CorpusDirectory)
			require.NoError(t, err)
			require.NoError(t, c.SaveInitialPropertyResult(record))
			f.config.Fuzzing.Testing.PropertyTesting.CheckInitialState = false
			fresh, err := NewFuzzer(f.config)
			require.NoError(t, err)
			require.ErrorContains(t, fresh.Start(), "initial replay not reproduced")
			require.Empty(t, fresh.TestCasesWithStatus(TestCaseStatusFailed))
			require.Empty(t, fresh.TestCasesWithStatus(TestCaseStatusPassed))
			require.Zero(t, fresh.Metrics().CallsTested().Sign())
		},
	})
}

func contractsMethodForTest(provider *PropertyTestCaseProvider, worker *FuzzerWorker) contracts.DeployedContractMethod {
	for _, method := range provider.workerStates[worker.WorkerIndex()].propertyTestMethods {
		return method
	}
	panic("test fixture has no deployed property")
}

func TestFuzzerInitialMany(t *testing.T) {
	runFuzzerTest(t, &fuzzerSolcFileTest{
		filePath: "testdata/contracts/properties/initial_only.sol", solcVersion: "0.8.25", configUpdates: initialTestConfig,
		method: func(fc *fuzzerTestContext) {
			t, f := fc.t, fc.fuzzer
			f.config.Fuzzing.CorpusDirectory = t.TempDir()
			f.config.Fuzzing.Testing.PropertyTesting.CheckInitialState = true
			f.config.Fuzzing.Testing.StopOnFailedTest = false
			f.config.Fuzzing.TargetContracts = []string{"InitialMany"}
			require.NoError(t, f.Start())
			require.Len(t, f.TestCasesWithStatus(TestCaseStatusFailed), 2)
			require.EqualValues(t, 2, f.Metrics().FailedSequences().Int64())
			records := f.corpus.InitialPropertyResults()
			require.Len(t, records, 2)
			f.config.Fuzzing.Testing.PropertyTesting.CheckInitialState = false
			f.config.Fuzzing.Testing.StopOnFailedTest = true
			fresh, err := NewFuzzer(f.config)
			require.NoError(t, err)
			require.NoError(t, fresh.Start())
			require.Len(t, fresh.TestCasesWithStatus(TestCaseStatusFailed), 2)
			require.Zero(t, fresh.Metrics().CallsTested().Sign())
			// Put a reproducible record first and an incompatible one second in deterministic load order.
			sort.Slice(records, func(i, j int) bool { return records[i].FileName < records[j].FileName })
			good, bad := records[0], records[1]
			for i := int64(1); ; i++ {
				bad.StateRoot = common.BigToHash(big.NewInt(i))
				data, err := json.Marshal(bad)
				require.NoError(t, err)
				digest := sha256.Sum256(data)
				if hex.EncodeToString(digest[:])+".json" > good.FileName {
					break
				}
				require.Less(t, i, int64(10000))
			}
			f.config.Fuzzing.CorpusDirectory = t.TempDir()
			c, err := corpus.NewCorpus(f.config.Fuzzing.CorpusDirectory)
			require.NoError(t, err)
			require.NoError(t, c.SaveInitialPropertyResult(good))
			require.NoError(t, c.SaveInitialPropertyResult(bad))
			fresh, err = NewFuzzer(f.config)
			require.NoError(t, err)
			require.ErrorContains(t, fresh.Start(), "initial replay incompatible")
			require.Empty(t, fresh.TestCasesWithStatus(TestCaseStatusFailed))
			require.Empty(t, fresh.TestCasesWithStatus(TestCaseStatusPassed))
			require.Zero(t, fresh.Metrics().FailedSequences().Sign())
			require.Zero(t, fresh.Metrics().CallsTested().Sign())
		},
	})
}

func TestFuzzerInitialRevertAndABI(t *testing.T) {
	runFuzzerTest(t, &fuzzerSolcFileTest{
		filePath: "testdata/contracts/properties/initial_only.sol", solcVersion: "0.8.25", configUpdates: initialTestConfig,
		method: func(fc *fuzzerTestContext) {
			t, f := fc.t, fc.fuzzer
			f.config.Fuzzing.Testing.PropertyTesting.CheckInitialState = true
			f.config.Fuzzing.TargetContracts = []string{"InitialRevert"}
			require.NoError(t, f.Start())
			require.Len(t, f.TestCasesWithStatus(TestCaseStatusFailed), 1)
			f.config.Fuzzing.TargetContracts = []string{"InitialMalformed"}
			require.ErrorContains(t, f.Start(), "decode property test method")
			require.Empty(t, f.TestCasesWithStatus(TestCaseStatusFailed))
			require.Empty(t, f.TestCasesWithStatus(TestCaseStatusPassed))
			require.Zero(t, f.Metrics().CallsTested().Sign())
		},
	})
}

func TestFuzzerInitialReset(t *testing.T) {
	runFuzzerTest(t, &fuzzerSolcFileTest{
		filePath: "testdata/contracts/properties/initial_setup.sol", solcVersion: "0.8.25", configUpdates: initialTestConfig,
		method: func(fc *fuzzerTestContext) {
			t, f := fc.t, fc.fuzzer
			f.config.Fuzzing.Workers, f.config.Fuzzing.WorkerResetLimit = 1, 0
			f.config.Fuzzing.Testing.PropertyTesting.CheckInitialState = true
			var setups, postCalls atomic.Int32
			f.Events.WorkerCreated.Subscribe(func(e FuzzerWorkerCreatedEvent) error {
				e.Worker.Events.FuzzerWorkerChainSetup.Subscribe(func(e FuzzerWorkerChainSetupEvent) error {
					value := common.Hash{}
					if setups.Add(1) == 1 {
						value = common.HexToHash("0x1")
					}
					if _, err := e.Chain.PendingBlockCreate(); err != nil {
						return err
					}
					for address := range e.Worker.deployedContracts {
						e.Chain.State().SetState(address, common.Hash{}, value)
					}
					return e.Chain.PendingBlockCommit()
				})
				return nil
			})
			f.Hooks.CallSequenceTestFuncs = append(f.Hooks.CallSequenceTestFuncs, func(*FuzzerWorker, calls.CallSequence) ([]ShrinkCallSequenceRequest, error) {
				postCalls.Add(1)
				return nil, nil
			})
			require.NoError(t, f.Start())
			require.EqualValues(t, 2, setups.Load())
			require.EqualValues(t, 1, postCalls.Load())
			require.Len(t, f.TestCasesWithStatus(TestCaseStatusFailed), 1)
			require.EqualValues(t, 1, f.Metrics().CallsTested().Int64())
		},
	})
}

func TestFuzzerInitialSaveError(t *testing.T) {
	runFuzzerTest(t, &fuzzerSolcFileTest{
		filePath: "testdata/contracts/properties/initial_only.sol", solcVersion: "0.8.25", configUpdates: initialTestConfig,
		method: func(fc *fuzzerTestContext) {
			t, f := fc.t, fc.fuzzer
			f.config.Fuzzing.Workers = 1
			f.config.Fuzzing.Testing.PropertyTesting.CheckInitialState = true
			f.config.Fuzzing.CorpusDirectory = t.TempDir()
			f.Events.WorkerCreated.Subscribe(func(e FuzzerWorkerCreatedEvent) error {
				e.Worker.Events.FuzzerWorkerChainSetup.Subscribe(func(FuzzerWorkerChainSetupEvent) error {
					return os.WriteFile(filepath.Join(f.config.Fuzzing.CorpusDirectory, "initial_results"), []byte("blocking file"), 0600)
				})
				return nil
			})
			require.ErrorContains(t, f.Start(), "save initial property")
			require.Empty(t, f.TestCasesWithStatus(TestCaseStatusFailed))
			require.Empty(t, f.TestCasesWithStatus(TestCaseStatusPassed))
			require.Empty(t, f.testCasesFinished)
			require.Zero(t, f.Metrics().FailedSequences().Sign())
		},
	})
}

func TestFuzzerInitialReplayTerminate(t *testing.T) {
	runFuzzerTest(t, &fuzzerSolcFileTest{
		filePath: "testdata/contracts/properties/initial_only.sol", solcVersion: "0.8.25", configUpdates: initialTestConfig,
		method: func(fc *fuzzerTestContext) {
			t, f := fc.t, fc.fuzzer
			f.config.Fuzzing.CorpusDirectory = t.TempDir()
			f.config.Fuzzing.Workers = 1
			f.config.Fuzzing.Testing.PropertyTesting.CheckInitialState = true
			f.config.Fuzzing.Testing.StopOnFailedTest = false
			f.config.Fuzzing.TargetContracts = []string{"InitialMany"}
			require.NoError(t, f.Start())
			require.Len(t, f.corpus.InitialPropertyResults(), 2)
			f.config.Fuzzing.Testing.PropertyTesting.CheckInitialState = false
			fresh, err := NewFuzzer(f.config)
			require.NoError(t, err)
			var evaluations atomic.Int32
			fresh.Events.WorkerCreated.Subscribe(func(e FuzzerWorkerCreatedEvent) error {
				e.Worker.Events.FuzzerWorkerChainSetup.Subscribe(func(e FuzzerWorkerChainSetupEvent) error {
					e.Chain.AddTracer(&chain.TestChainTracer{Tracer: &tracers.Tracer{Hooks: &tracing.Hooks{OnTxEnd: func(*gethTypes.Receipt, error) { evaluations.Add(1); fresh.Terminate() }}}}, false, true)
					return nil
				})
				return nil
			})
			require.ErrorIs(t, fresh.Start(), context.Canceled)
			require.EqualValues(t, 1, evaluations.Load())
			require.Empty(t, fresh.TestCasesWithStatus(TestCaseStatusFailed))
			require.Empty(t, fresh.TestCasesWithStatus(TestCaseStatusPassed))
			require.Zero(t, fresh.Metrics().FailedSequences().Sign())
			require.Empty(t, fresh.testCasesFinished)
		},
	})
}

func TestFuzzerInitialMixedError(t *testing.T) {
	runFuzzerTest(t, &fuzzerSolcFileTest{
		filePath: "testdata/contracts/properties/initial_only.sol", solcVersion: "0.8.25", configUpdates: initialTestConfig,
		method: func(fc *fuzzerTestContext) {
			t, f := fc.t, fc.fuzzer
			cfg := f.config
			cfg.Fuzzing.TargetContracts = []string{"InitialMalformed"}
			cfg.Fuzzing.Testing.PropertyTesting.CheckInitialState = true
			cfg.Fuzzing.Testing.AssertionTesting.Enabled = true
			fresh, err := NewFuzzer(cfg)
			require.NoError(t, err)
			require.ErrorContains(t, fresh.Start(), "decode property test method")
			require.GreaterOrEqual(t, len(fresh.TestCases()), 2)
			require.Empty(t, fresh.TestCasesWithStatus(TestCaseStatusPassed))
			require.Empty(t, fresh.TestCasesWithStatus(TestCaseStatusFailed))
			require.Zero(t, fresh.Metrics().CallsTested().Sign())
		},
	})
}

func TestFuzzerInitialCompetingSetup(t *testing.T) {
	runFuzzerTest(t, &fuzzerSolcFileTest{
		filePath: "testdata/contracts/properties/initial_repair.sol", solcVersion: "0.8.25", configUpdates: initialTestConfig,
		method: func(fc *fuzzerTestContext) {
			t, f := fc.t, fc.fuzzer
			f.config.Fuzzing.CorpusDirectory = t.TempDir()
			f.config.Fuzzing.Testing.PropertyTesting.CheckInitialState = true
			var finalTraces sync.WaitGroup
			finalTraces.Add(2)
			f.Events.WorkerCreated.Subscribe(func(e FuzzerWorkerCreatedEvent) error {
				e.Worker.Events.FuzzerWorkerChainSetup.Subscribe(func(e FuzzerWorkerChainSetupEvent) error {
					if _, err := e.Chain.PendingBlockCreate(); err != nil {
						return err
					}
					for address := range e.Worker.deployedContracts {
						e.Chain.State().SetState(address, common.HexToHash("0x1"), common.BigToHash(big.NewInt(int64(e.Worker.WorkerIndex()+1))))
					}
					if err := e.Chain.PendingBlockCommit(); err != nil {
						return err
					}
					attempts := 0
					e.Chain.AddTracer(&chain.TestChainTracer{Tracer: &tracers.Tracer{Hooks: &tracing.Hooks{OnTxEnd: func(*gethTypes.Receipt, error) {
						attempts++
						if attempts == 2 {
							finalTraces.Done()
							finalTraces.Wait()
						}
					}}}}, false, true)
					return nil
				})
				return nil
			})
			require.NoError(t, f.Start())
			require.Len(t, f.corpus.InitialPropertyResults(), 1, "losing worker input must not leave a manifest")
			require.Len(t, f.TestCasesWithStatus(TestCaseStatusFailed), 1)
			require.EqualValues(t, 1, f.Metrics().FailedSequences().Int64())
			require.EqualValues(t, 2, f.Metrics().WorkerStartupCount().Int64())
		},
	})
}
