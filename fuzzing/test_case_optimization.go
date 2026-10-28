package fuzzing

import (
	"fmt"
	"maps"
	"math/big"
	"slices"
	"strings"
	"sync"

	"github.com/crytic/medusa-geth/accounts/abi"
	"github.com/crytic/medusa-geth/common"
	gethTypes "github.com/crytic/medusa-geth/core/types"
	chainTypes "github.com/crytic/medusa/chain/types"
	"github.com/crytic/medusa/fuzzing/calls"
	"github.com/crytic/medusa/fuzzing/contracts"
	"github.com/crytic/medusa/fuzzing/executiontracer"
	"github.com/crytic/medusa/logging"
	"github.com/crytic/medusa/logging/colors"
)

// OptimizationTestCase describes a test being run by a OptimizationTestCaseProvider.
type OptimizationTestCase struct {
	resultLock sync.RWMutex
	// status describes the status of the test case
	status TestCaseStatus
	// targetContract describes the target contract where the test case was found
	targetContract *contracts.Contract
	// targetMethod describes the target method for the test case
	targetMethod abi.Method
	// callSequence describes the call sequence that maximized the value
	callSequence *calls.CallSequence
	// shrinkCallSequenceRequest is the shrink request that will be executed to identify the optimal call sequence
	// that maximizes the value
	shrinkCallSequenceRequest *ShrinkCallSequenceRequest
	// value is used to store the maximum value returned by the test method
	value *big.Int
	// optimizationTestTrace describes the execution trace when running the callSequence
	optimizationTestTrace *executiontracer.ExecutionTrace
}

// Status describes the TestCaseStatus used to define the current state of the test.
func (t *OptimizationTestCase) Status() TestCaseStatus {
	t.resultLock.RLock()
	defer t.resultLock.RUnlock()
	return t.status
}

// CallSequence describes the calls.CallSequence of calls sent to the EVM which resulted in this TestCase result.
// This should be nil if the result is not related to the CallSequence.
func (t *OptimizationTestCase) CallSequence() *calls.CallSequence {
	t.resultLock.RLock()
	defer t.resultLock.RUnlock()
	return t.callSequence
}

// Name describes the name of the test case.
func (t *OptimizationTestCase) Name() string {
	return fmt.Sprintf("Optimization Test: %s.%s", t.targetContract.Name(), t.targetMethod.Sig)
}

// LogMessage obtains a buffer that represents the result of the OptimizationTestCase. This buffer can be passed to a logger for
// console or file logging.
func (t *OptimizationTestCase) LogMessage() *logging.LogBuffer {
	t.resultLock.RLock()
	status, sequence, trace := t.status, t.callSequence, t.optimizationTestTrace
	value := new(big.Int).Set(t.value)
	t.resultLock.RUnlock()
	buffer := logging.NewLogBuffer()

	// If the test case never started, just log the status and name of the test case
	if status == TestCaseStatusNotStarted {
		buffer.Append(colors.GreenBold, fmt.Sprintf("[%s] ", status), colors.Bold, t.Name(), colors.Reset, "\n")
		return buffer
	}

	minInt, _ := new(big.Int).SetString(MIN_INT, 16)
	buffer.Append(colors.GreenBold, fmt.Sprintf("[%s] ", status), colors.Bold, t.Name(), colors.Reset, "\n")

	// Notify the user we failed to find anything
	if value.Cmp(minInt) == 0 {
		buffer.Append(fmt.Sprintf("Test for method \"%s.%s\" failed to identify a value greater than the minimum"+
			" value of an int256: ", t.targetContract.Name(), t.targetMethod.Sig))
		// We do not have a call sequence or execution trace for this test, so return early
		return buffer
	}

	// We are guaranteed to now handle only successful test cases
	buffer.Append(fmt.Sprintf("Test for method \"%s.%s\" resulted in the maximum value: ", t.targetContract.Name(), t.targetMethod.Sig))
	buffer.Append(colors.Bold, value, colors.Reset, "\n")
	buffer.Append(colors.Bold, "[Call Sequence]", colors.Reset, "\n")
	buffer.Append(sequence.Log().Elements()...)

	// If an execution trace is attached then add it to the message
	if trace != nil {
		buffer.Append(colors.Bold, "[Optimization Test Execution Trace]", colors.Reset, "\n")
		buffer.Append(trace.Log().Elements()...)
	}
	return buffer
}

// Message obtains a text-based printable message which describes the result of the OptimizationTestCase.
func (t *OptimizationTestCase) Message() string {
	// Internally, we just call log message and convert it to a string. This can be useful for 3rd party apps
	return t.LogMessage().String()
}

// ID obtains a unique identifier for a test result.
func (t *OptimizationTestCase) ID() string {
	return strings.ReplaceAll(fmt.Sprintf("OPTIMIZATION-%s-%s", t.targetContract.Name(), t.targetMethod.Sig), "_", "-")
}

// Value returns an independent copy of the maximum value found so far.
func (t *OptimizationTestCase) Value() *big.Int {
	t.resultLock.RLock()
	defer t.resultLock.RUnlock()
	return new(big.Int).Set(t.value)
}

func (t *OptimizationTestCase) markRunning() {
	t.resultLock.Lock()
	defer t.resultLock.Unlock()
	if t.status == TestCaseStatusNotStarted {
		t.status = TestCaseStatusRunning
	}
}

func (t *OptimizationTestCase) finish() {
	minimum, _ := new(big.Int).SetString(MIN_INT, 16)
	t.resultLock.Lock()
	defer t.resultLock.Unlock()
	if t.status != TestCaseStatusRunning {
		return
	}
	if t.value.Cmp(minimum) == 0 {
		t.status = TestCaseStatusFailed
	} else {
		t.status = TestCaseStatusPassed
	}
}

func (t *OptimizationTestCase) updateCandidate(value *big.Int, sequence calls.CallSequence, request *ShrinkCallSequenceRequest) (bool, error) {
	resultSequence, err := snapshotOptimizationSequence(sequence)
	if err != nil {
		return false, err
	}
	requestSequence, err := snapshotOptimizationSequence(sequence)
	if err != nil {
		return false, err
	}
	value = new(big.Int).Set(value)
	request.CallSequenceToShrink = requestSequence
	t.resultLock.Lock()
	defer t.resultLock.Unlock()
	if value.Cmp(t.value) <= 0 {
		return false, nil
	}
	t.value, t.callSequence, t.shrinkCallSequenceRequest, t.optimizationTestTrace = value, &resultSequence, request, nil
	return true, nil
}

func (t *OptimizationTestCase) takeShrinkRequest() *ShrinkCallSequenceRequest {
	t.resultLock.Lock()
	defer t.resultLock.Unlock()
	request := t.shrinkCallSequenceRequest
	t.shrinkCallSequenceRequest = nil
	return request
}

func (t *OptimizationTestCase) updateFinal(value *big.Int, sequence calls.CallSequence, trace *executiontracer.ExecutionTrace) (bool, error) {
	resultSequence, err := snapshotOptimizationSequence(sequence)
	if err != nil {
		return false, err
	}
	value = new(big.Int).Set(value)
	t.resultLock.Lock()
	defer t.resultLock.Unlock()
	if value.Cmp(t.value) < 0 {
		return false, nil
	}
	t.value, t.callSequence, t.optimizationTestTrace, t.shrinkCallSequenceRequest = value, &resultSequence, trace, nil
	return true, nil
}

func snapshotOptimizationSequence(sequence calls.CallSequence) (calls.CallSequence, error) {
	result, err := sequence.Clone()
	if err != nil {
		return nil, err
	}
	blocks := make(map[*chainTypes.Block]*chainTypes.Block)
	for _, element := range result {
		reference := element.ChainReference
		if reference == nil {
			continue
		}
		block := blocks[reference.Block]
		if block == nil {
			// The owner may extend this pending block after publication.
			copyBlock := *reference.Block
			if copyBlock.Header != nil {
				copyBlock.Header = gethTypes.CopyHeader(copyBlock.Header)
			}
			copyBlock.Messages = slices.Clone(copyBlock.Messages)
			copyBlock.MessageResults = make([]*chainTypes.MessageResults, len(reference.Block.MessageResults))
			for i, message := range reference.Block.MessageResults {
				copyMessage := *message
				copyMessage.AdditionalResults = maps.Clone(message.AdditionalResults)
				for key, value := range copyMessage.AdditionalResults {
					if labels, ok := value.(map[common.Address]string); ok {
						copyMessage.AdditionalResults[key] = maps.Clone(labels)
					}
				}
				copyBlock.MessageResults[i] = &copyMessage
			}
			block = &copyBlock
			blocks[reference.Block] = block
		}
		copyReference := *reference
		copyReference.Block = block
		element.ChainReference = &copyReference
	}
	return result, nil
}
