package fuzzing

import (
	"errors"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crytic/medusa-geth/accounts/abi"
	"github.com/crytic/medusa-geth/common"
	compilationTypes "github.com/crytic/medusa/compilation/types"
	"github.com/crytic/medusa/events"
	"github.com/crytic/medusa/fuzzing/calls"
	"github.com/crytic/medusa/fuzzing/contracts"
	"github.com/crytic/medusa/fuzzing/valuegeneration"
	"github.com/stretchr/testify/require"
)

// newOptimizationShutdownFuzzer uses constant-return bytecode, without an external compiler.
func newOptimizationShutdownFuzzer(t *testing.T, workers int) (*Fuzzer, *OptimizationTestCaseProvider) {
	t.Helper()
	f := newLifecycleFuzzer(t)
	f.config.Fuzzing.Workers = workers
	f.config.Fuzzing.WorkerResetLimit = 1
	f.config.Fuzzing.CallSequenceLength = 1
	f.config.Fuzzing.TestLimit = 0
	f.config.Fuzzing.Timeout = 0
	f.config.Fuzzing.ShrinkLimit = 10
	f.config.Fuzzing.Testing.TestAllContracts = true
	f.config.Fuzzing.Testing.OptimizationTesting.Enabled = true
	f.config.Fuzzing.Testing.OptimizationTesting.TestPrefixes = []string{"optimize_"}
	parsed, err := abi.JSON(strings.NewReader(`[{"type":"function","name":"step","stateMutability":"nonpayable","inputs":[],"outputs":[]},{"type":"function","name":"optimize_p","stateMutability":"view","inputs":[],"outputs":[{"type":"int256"}]}]`))
	require.NoError(t, err)
	code := common.FromHex("0x600760005260206000f3")
	contract := contracts.NewContract("C", "C.sol", &compilationTypes.CompiledContract{Abi: parsed, RuntimeBytecode: code}, compilationTypes.NewCompilation())
	contract.AssertionTestMethods = []abi.Method{parsed.Methods["step"]}
	contract.OptimizationTestMethods = []abi.Method{parsed.Methods["optimize_p"]}
	f.contractDefinitions = contracts.Contracts{contract}
	genesis := filepath.Join(t.TempDir(), "genesis.json")
	require.NoError(t, os.WriteFile(genesis, []byte(`{"0x0000000000000000000000000000000000123456":{"code":"0x600760005260206000f3","balance":"0x0"},"0x0000000000000000000000000000000000234567":{"code":"0x600960005260206000f3","balance":"0x0"},"0x0000000000000000000000000000000000345678":{"code":"0x600160005260206000f3","balance":"0x0"}}`), 0600))
	f.config.Fuzzing.TestChainConfig.GenesisStateFile = genesis
	p := attachOptimizationTestCaseProvider(f)
	require.NotNil(t, p)
	f.Events.WorkerCreated.Subscribe(func(event FuzzerWorkerCreatedEvent) error {
		event.Worker.Events.FuzzerWorkerChainSetup.Subscribe(func(event FuzzerWorkerChainSetupEvent) error {
			address := common.HexToAddress("0x123456")
			if event.Worker.WorkerIndex() == 1 {
				address = common.HexToAddress("0x234567")
			}
			event.Worker.deployedContracts[address] = contract
			event.Worker.updateMethods()
			return event.Worker.Events.ContractAdded.Publish(FuzzerWorkerContractAddedEvent{Worker: event.Worker, ContractAddress: address, ContractDefinition: contract})
		})
		return nil
	})
	return f, p
}

func startOptimizationShutdown(t *testing.T, f *Fuzzer) <-chan error {
	t.Helper()
	done, finished := make(chan error, 1), make(chan struct{})
	go func() { defer close(finished); done <- f.Start() }()
	t.Cleanup(func() {
		f.Terminate()
		select {
		case <-finished:
		case <-time.After(10 * time.Second):
			t.Error("shutdown campaign leaked")
		}
	})
	return done
}

func joinOptimizationShutdown(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown campaign did not join")
		return nil
	}
}

func awaitOptimizationArrival(t *testing.T, p *OptimizationTestCaseProvider, done <-chan error) {
	t.Helper()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	for {
		p.completionLock.Lock()
		arrived := p.completedWorkers
		p.completionLock.Unlock()
		if arrived == 1 {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("campaign returned before first provider arrival: %v", err)
		case <-timer.C:
			t.Fatal("no provider terminal arrival")
		default:
			runtime.Gosched()
		}
	}
}

// prependShutdownWorkerHook installs a test seam before the provider's terminal subscription.
func prependShutdownWorkerHook(f *Fuzzer, hook func(FuzzerWorkerCreatedEvent) error) {
	existing := f.Events.WorkerCreated
	f.Events.WorkerCreated = events.EventEmitter[FuzzerWorkerCreatedEvent]{}
	f.Events.WorkerCreated.Subscribe(hook)
	f.Events.WorkerCreated.Subscribe(existing.Publish)
}

func TestOptimizationShutdownLateProducer(t *testing.T) {
	f, p := newOptimizationShutdownFuzzer(t, 2)
	var held, release chan struct{}
	f.Events.WorkerCreated.Subscribe(func(event FuzzerWorkerCreatedEvent) error {
		w := event.Worker
		if w.WorkerIndex() == 1 {
			w.Events.CallSequenceTesting.Subscribe(func(FuzzerWorkerCallSequenceTestingEvent) error {
				close(held)
				select {
				case <-release:
				case <-f.emergencyCtx.Done():
				}
				return nil
			})
		} else {
			w.Events.CallSequenceTested.Subscribe(func(FuzzerWorkerCallSequenceTestedEvent) error {
				select {
				case <-held:
				case <-f.emergencyCtx.Done():
				}
				f.Stop()
				return nil
			})
		}
		return nil
	})
	for campaign := 0; campaign < 2; campaign++ {
		held, release = make(chan struct{}), make(chan struct{})
		done := startOptimizationShutdown(t, f)
		awaitOptimizationArrival(t, p, done)
		for _, c := range p.testCases {
			c.resultLock.RLock()
			pending, trace := c.shrinkCallSequenceRequest != nil, c.optimizationTestTrace
			c.resultLock.RUnlock()
			require.True(t, pending, "first arrival must leave the candidate pending")
			require.Nil(t, trace, "first arrival must not finalize before the producer ends")
			require.EqualValues(t, 7, c.Value().Int64())
		}
		close(release)
		require.NoError(t, joinOptimizationShutdown(t, done))
		requireOptimizationShutdownResult(t, f, 9)
	}
}

func TestOptimizationShutdownAbortReleasesWaiter(t *testing.T) {
	for _, stage := range []string{"terminate", "constructor", "created", "setup", "run", "complete", "destroyed"} {
		t.Run(stage, func(t *testing.T) {
			f, p := newOptimizationShutdownFuzzer(t, 2)
			want := errors.New("shutdown sentinel " + stage)
			held, release := make(chan struct{}), make(chan struct{})
			var heldOnce sync.Once
			fail := func() error {
				heldOnce.Do(func() { close(held) })
				select {
				case <-release:
				case <-f.emergencyCtx.Done():
				}
				if stage == "terminate" {
					return nil
				}
				return want
			}
			if stage == "constructor" {
				original := f.Hooks.NewCallSequenceGeneratorConfigFunc
				var constructors atomic.Int32
				f.Hooks.NewCallSequenceGeneratorConfigFunc = func(f *Fuzzer, values *valuegeneration.ValueSet, rng *rand.Rand) (*CallSequenceGeneratorConfig, error) {
					if constructors.Add(1) == 2 {
						return nil, fail()
					}
					return original(f, values, rng)
				}
			}
			prependShutdownWorkerHook(f, func(event FuzzerWorkerCreatedEvent) error {
				w := event.Worker
				if stage == "constructor" {
					f.Stop()
					return nil
				}
				if w.WorkerIndex() == 1 {
					switch stage {
					case "terminate", "created":
						return fail()
					case "setup":
						w.Events.FuzzerWorkerChainSetup.Subscribe(func(FuzzerWorkerChainSetupEvent) error { return fail() })
					case "run":
						w.Events.CallSequenceTesting.Subscribe(func(FuzzerWorkerCallSequenceTestingEvent) error { return fail() })
					case "complete":
						w.Events.CallSequenceTested.Subscribe(func(FuzzerWorkerCallSequenceTestedEvent) error { f.Stop(); return nil })
						w.Events.TestingComplete.Subscribe(func(FuzzerWorkerTestingCompleteEvent) error { return fail() })
					}
				} else {
					w.Events.CallSequenceTested.Subscribe(func(FuzzerWorkerCallSequenceTestedEvent) error {
						select {
						case <-held:
						case <-f.emergencyCtx.Done():
						}
						f.Stop()
						return nil
					})
				}
				return nil
			})
			if stage == "destroyed" {
				f.Events.WorkerDestroyed.Subscribe(func(event FuzzerWorkerDestroyedEvent) error {
					if event.Worker.WorkerIndex() == 1 {
						return fail()
					}
					return nil
				})
			}
			done := startOptimizationShutdown(t, f)
			awaitOptimizationArrival(t, p, done)
			if stage == "terminate" {
				f.Terminate()
			} else {
				close(release)
			}
			err := joinOptimizationShutdown(t, done)
			switch stage {
			case "terminate":
				require.NoError(t, err)
			case "constructor", "created", "destroyed":
				require.ErrorIs(t, err, want)
			default:
				require.ErrorContains(t, err, want.Error())
			}
		})
	}
}

func TestOptimizationShutdownBeforeLaunch(t *testing.T) {
	for _, emergency := range []bool{false, true} {
		t.Run(map[bool]string{false: "stop", true: "terminate"}[emergency], func(t *testing.T) {
			f, p := newOptimizationShutdownFuzzer(t, 2)
			var created, complete atomic.Int32
			f.Events.WorkerCreated.Subscribe(func(event FuzzerWorkerCreatedEvent) error {
				created.Add(1)
				event.Worker.Events.TestingComplete.Subscribe(func(FuzzerWorkerTestingCompleteEvent) error { complete.Add(1); return nil })
				return nil
			})
			f.Events.FuzzerStarting.Subscribe(func(FuzzerStartingEvent) error {
				if emergency {
					f.Terminate()
				} else {
					f.Stop()
				}
				return nil
			})
			require.NoError(t, joinOptimizationShutdown(t, startOptimizationShutdown(t, f)))
			want := int32(2)
			if emergency {
				want = 0
			}
			require.Equal(t, want, created.Load())
			require.Equal(t, want, complete.Load())
			require.EqualValues(t, want, p.completedWorkers)
			require.Zero(t, f.metrics.CallsTested().Sign())
		})
	}
}

func TestOptimizationShutdownInitialNoCallable(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		t.Run(map[bool]string{false: "all", true: "mixed"}[mixed], func(t *testing.T) {
			f, p := newOptimizationShutdownFuzzer(t, 2)
			f.config.Fuzzing.Testing.PropertyTesting.Enabled = true
			f.config.Fuzzing.Testing.PropertyTesting.CheckInitialState = true
			f.config.Fuzzing.Testing.PropertyTesting.TestPrefixes = []string{"property_"}
			parsed, err := abi.JSON(strings.NewReader(`[{"type":"function","name":"property_ok","stateMutability":"view","inputs":[],"outputs":[{"type":"bool"}]}]`))
			require.NoError(t, err)
			contract := contracts.NewContract("P", "P.sol", &compilationTypes.CompiledContract{Abi: parsed, RuntimeBytecode: common.FromHex("0x600160005260206000f3")}, compilationTypes.NewCompilation())
			contract.PropertyTestMethods = []abi.Method{parsed.Methods["property_ok"]}
			f.contractDefinitions = append(f.contractDefinitions, contract)
			f.propertyTestProvider = attachPropertyTestCaseProvider(f)
			require.NotNil(t, f.propertyTestProvider)
			held, release := make(chan struct{}), make(chan struct{})
			var complete atomic.Int32
			f.Events.WorkerCreated.Subscribe(func(event FuzzerWorkerCreatedEvent) error {
				w := event.Worker
				w.Events.TestingComplete.Subscribe(func(FuzzerWorkerTestingCompleteEvent) error { complete.Add(1); return nil })
				w.Events.FuzzerWorkerChainSetup.Subscribe(func(event FuzzerWorkerChainSetupEvent) error {
					address := common.HexToAddress("0x345678")
					w.deployedContracts[address] = contract
					if err := w.Events.ContractAdded.Publish(FuzzerWorkerContractAddedEvent{Worker: w, ContractAddress: address, ContractDefinition: contract}); err != nil {
						return err
					}
					if !mixed || w.WorkerIndex() == 0 {
						w.stateChangingMethods, w.pureMethods, w.fallbackMethods = nil, nil, nil
						if mixed {
							select {
							case <-held:
							case <-f.emergencyCtx.Done():
							}
						}
					}
					return nil
				})
				if mixed && w.WorkerIndex() == 1 {
					w.Events.CallSequenceTesting.Subscribe(func(FuzzerWorkerCallSequenceTestingEvent) error {
						close(held)
						select {
						case <-release:
						case <-f.emergencyCtx.Done():
						}
						return nil
					})
				}
				return nil
			})
			done := startOptimizationShutdown(t, f)
			if mixed {
				awaitOptimizationArrival(t, p, done)
				close(release)
			}
			require.NoError(t, joinOptimizationShutdown(t, done))
			require.EqualValues(t, 2, p.completedWorkers)
			require.EqualValues(t, 2, complete.Load())
			if mixed {
				cases := f.TestCasesWithStatus(TestCaseStatusPassed)
				require.Len(t, cases, 2)
				for _, c := range cases {
					if c, ok := c.(*OptimizationTestCase); ok {
						require.EqualValues(t, 9, c.Value().Int64())
						require.NotNil(t, c.optimizationTestTrace)
					}
				}
			} else {
				require.Zero(t, f.metrics.CallsTested().Sign(), "initial checks must not generate fuzz calls")
				require.Len(t, f.TestCasesWithStatus(TestCaseStatusPassed), 1, "initial property must still pass")
			}
		})
	}
}

func requireOptimizationShutdownResult(t *testing.T, f *Fuzzer, want int64) {
	t.Helper()
	cases := f.TestCasesWithStatus(TestCaseStatusPassed)
	require.Len(t, cases, 1)
	c := cases[0].(*OptimizationTestCase)
	require.Equal(t, want, c.Value().Int64())
	require.NotNil(t, c.CallSequence())
	require.NotNil(t, c.optimizationTestTrace, "terminal completion must finish and trace the winner")
	value := c.Value()
	value.SetInt64(-1)
	require.Equal(t, want, c.Value().Int64(), "result must own its value")
}

func TestOptimizationShutdownReset(t *testing.T) {
	for _, mode := range []string{"tested", "destroyed"} {
		t.Run(mode, func(t *testing.T) {
			f, _ := newOptimizationShutdownFuzzer(t, 1)
			var tested, destroyed, complete atomic.Int32
			var source calls.CallSequence
			f.Hooks.CallSequenceTestFuncs = append(f.Hooks.CallSequenceTestFuncs, func(_ *FuzzerWorker, sequence calls.CallSequence) ([]ShrinkCallSequenceRequest, error) {
				source = sequence
				return nil, nil
			})
			f.Events.FuzzerStarting.Subscribe(func(FuzzerStartingEvent) error { tested.Store(0); destroyed.Store(0); complete.Store(0); return nil })
			f.Events.WorkerCreated.Subscribe(func(event FuzzerWorkerCreatedEvent) error {
				event.Worker.Events.TestingComplete.Subscribe(func(FuzzerWorkerTestingCompleteEvent) error { complete.Add(1); return nil })
				event.Worker.Events.CallSequenceTested.Subscribe(func(FuzzerWorkerCallSequenceTestedEvent) error {
					if tested.Add(1) == 2 && mode == "tested" {
						f.Stop()
					}
					return nil
				})
				return nil
			})
			f.Events.WorkerDestroyed.Subscribe(func(FuzzerWorkerDestroyedEvent) error {
				if destroyed.Add(1) == 1 && mode == "destroyed" {
					f.Stop()
				}
				return nil
			})
			for campaign := 0; campaign < 2; campaign++ {
				require.NoError(t, f.Start())
				require.EqualValues(t, 1, complete.Load(), "each slot must complete exactly once")
				require.EqualValues(t, 2, destroyed.Load(), "the reset generation and terminal replacement must both be destroyed")
				require.EqualValues(t, 2, tested.Load(), "the reset limit must retain its existing sequence count")
				requireOptimizationShutdownResult(t, f, 7)
				result := f.TestCasesWithStatus(TestCaseStatusPassed)[0].CallSequence()
				if len(*result) > 0 {
					require.NotSame(t, source[0], (*result)[0], "published sequence must be independent of the producer")
				}
			}
		})
	}
}
