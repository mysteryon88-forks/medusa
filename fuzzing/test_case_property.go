package fuzzing

import (
	"fmt"
	"strings"
	"sync"

	"github.com/crytic/medusa-geth/accounts/abi"
	"github.com/crytic/medusa/fuzzing/calls"
	fuzzerTypes "github.com/crytic/medusa/fuzzing/contracts"
	"github.com/crytic/medusa/fuzzing/executiontracer"
	"github.com/crytic/medusa/logging"
	"github.com/crytic/medusa/logging/colors"
)

// PropertyTestCase describes a test being run by a PropertyTestCaseProvider.
type PropertyTestCase struct {
	resultLock sync.RWMutex
	// status describes the status of the test case
	status TestCaseStatus
	// targetContract describes the target contract where the test case was found
	targetContract *fuzzerTypes.Contract
	// targetMethod describes the target method for the test case
	targetMethod abi.Method
	// callSequence describes the call sequence that broke the property
	callSequence *calls.CallSequence
	// propertyTestTrace describes the execution trace when running the callSequence
	propertyTestTrace *executiontracer.ExecutionTrace
	// pendingInitialFailure reserves a fully evaluated candidate until its persistence completes.
	pendingInitialFailure chan struct{}
}

// Status describes the TestCaseStatus used to define the current state of the test.
func (t *PropertyTestCase) Status() TestCaseStatus {
	t.resultLock.RLock()
	defer t.resultLock.RUnlock()
	return t.status
}

// CallSequence describes the types.CallSequence of calls sent to the EVM which resulted in this TestCase result.
// This should be nil if the result is not related to the CallSequence.
func (t *PropertyTestCase) CallSequence() *calls.CallSequence {
	t.resultLock.RLock()
	defer t.resultLock.RUnlock()
	return t.callSequence
}

// Name describes the name of the test case.
func (t *PropertyTestCase) Name() string {
	return fmt.Sprintf("Property Test: %s.%s", t.targetContract.Name(), t.targetMethod.Sig)
}

// LogMessage obtains a buffer that represents the result of the PropertyTestCase. This buffer can be passed to a logger for
// console or file logging.
func (t *PropertyTestCase) LogMessage() *logging.LogBuffer {
	t.resultLock.RLock()
	status, sequence := t.status, t.callSequence
	trace := t.propertyTestTrace
	t.resultLock.RUnlock()
	// If the test failed, return a failure message.
	buffer := logging.NewLogBuffer()
	if status == TestCaseStatusFailed {
		buffer.Append(colors.RedBold, fmt.Sprintf("[%s] ", status), colors.Bold, t.Name(), colors.Reset, "\n")
		if sequence != nil && len(*sequence) == 0 {
			buffer.Append("Property failed in the initial state after setup, before fuzz calls.\n")
		} else {
			buffer.Append(fmt.Sprintf("Test for method \"%s.%s\" failed after the following call sequence:\n", t.targetContract.Name(), t.targetMethod.Sig))
		}
		buffer.Append(colors.Bold, "[Call Sequence]", colors.Reset, "\n")
		buffer.Append(sequence.Log().Elements()...)

		// If an execution trace is attached then add it to the message
		if trace != nil {
			buffer.Append(colors.Bold, "[Property Test Execution Trace]", colors.Reset, "\n")
			buffer.Append(trace.Log().Elements()...)
		}
		return buffer
	}

	buffer.Append(colors.GreenBold, fmt.Sprintf("[%s] ", status), colors.Bold, t.Name(), colors.Reset)
	return buffer
}

// Message obtains a text-based printable message which describes the result of the PropertyTestCase.
func (t *PropertyTestCase) Message() string {
	// Internally, we just call log message and convert it to a string. This can be useful for 3rd party apps
	return t.LogMessage().String()
}

// ID obtains a unique identifier for a test result.
func (t *PropertyTestCase) ID() string {
	return strings.ReplaceAll(fmt.Sprintf("PROPERTY-%s-%s", t.targetContract.Name(), t.targetMethod.Sig), "_", "-")
}

func (t *PropertyTestCase) markRunning() {
	t.resultLock.Lock()
	defer t.resultLock.Unlock()
	if t.status == TestCaseStatusNotStarted {
		t.status = TestCaseStatusRunning
	}
}
func (t *PropertyTestCase) markPassed() {
	t.resultLock.Lock()
	defer t.resultLock.Unlock()
	if t.status == TestCaseStatusRunning {
		t.status = TestCaseStatusPassed
	}
}

func (t *PropertyTestCase) tryFinalizeFailure(sequence *calls.CallSequence, trace *executiontracer.ExecutionTrace) bool {
	t.resultLock.Lock()
	defer t.resultLock.Unlock()
	if t.status == TestCaseStatusFailed || t.pendingInitialFailure != nil {
		return false
	}
	t.callSequence = sequence
	t.propertyTestTrace = trace
	t.status = TestCaseStatusFailed
	return true
}

func (t *PropertyTestCase) beginInitialFailure() (chan struct{}, bool) {
	t.resultLock.Lock()
	defer t.resultLock.Unlock()
	if t.status == TestCaseStatusFailed {
		return nil, false
	}
	if t.pendingInitialFailure != nil {
		return t.pendingInitialFailure, false
	}
	t.pendingInitialFailure = make(chan struct{})
	return t.pendingInitialFailure, true
}

func (t *PropertyTestCase) completeInitialFailure(reservation chan struct{}, sequence *calls.CallSequence, trace *executiontracer.ExecutionTrace, err error) bool {
	t.resultLock.Lock()
	defer t.resultLock.Unlock()
	if t.pendingInitialFailure != reservation {
		return false
	}
	accepted := err == nil && t.status != TestCaseStatusFailed
	if accepted {
		t.callSequence, t.propertyTestTrace, t.status = sequence, trace, TestCaseStatusFailed
	}
	t.pendingInitialFailure = nil
	close(reservation)
	return accepted
}
