package fuzzing

import (
	"sync"
	"testing"

	"github.com/crytic/medusa/fuzzing/calls"
	"github.com/crytic/medusa/fuzzing/contracts"
	"github.com/crytic/medusa/fuzzing/executiontracer"
	"github.com/stretchr/testify/require"
)

func TestRacePropertyResult(t *testing.T) {
	f := newLifecycleFuzzer(t)
	f.metrics = newFuzzerMetrics(2, nil)
	f.testCasesFinished = make(map[string]TestCase)
	c := &PropertyTestCase{targetContract: contracts.NewContract("C", "C.sol", nil, nil)}
	p := &PropertyTestCaseProvider{fuzzer: f}
	sequences := []calls.CallSequence{{}, {}}
	traces := []*executiontracer.ExecutionTrace{{}, {}}
	accepted := make(chan int, 2)
	start, stop := make(chan struct{}), make(chan struct{})
	var writers, readers sync.WaitGroup
	readers.Add(1)
	go func() {
		defer readers.Done()
		close(start)
		for {
			select {
			case <-stop:
				return
			default:
			}
			c.markRunning()
			c.markPassed()
			_ = c.Status()
			_ = c.CallSequence()
			c.resultLock.RLock()
			if c.status == TestCaseStatusFailed && (c.callSequence == nil || c.propertyTestTrace == nil) {
				t.Error("partially published property failure")
			}
			c.resultLock.RUnlock()
		}
	}()
	for i := range sequences {
		writers.Add(1)
		go func(i int) {
			defer writers.Done()
			<-start
			w := &FuzzerWorker{fuzzer: f, workerIndex: i}
			ok, err := p.finalizeFailure(w, c, &sequences[i], traces[i])
			if err != nil {
				t.Errorf("finalize property: %v", err)
				return
			}
			if ok {
				accepted <- i
			}
		}(i)
	}
	writers.Wait()
	close(stop)
	readers.Wait()
	close(accepted)
	require.Len(t, accepted, 1)
	winner := <-accepted
	require.NotSame(t, &sequences[winner], c.CallSequence())
	require.Equal(t, sequences[winner], *c.CallSequence())
	require.Same(t, traces[winner], c.propertyTestTrace)
	require.Equal(t, TestCaseStatusFailed, c.Status())
	require.EqualValues(t, 1, f.metrics.FailedSequences().Int64())
	require.Len(t, f.testCasesFinished, 1)
}

func TestRaceAssertionResult(t *testing.T) {
	f := newLifecycleFuzzer(t)
	f.metrics = newFuzzerMetrics(2, nil)
	f.testCasesFinished = make(map[string]TestCase)
	c := &AssertionTestCase{targetContract: contracts.NewContract("C", "C.sol", nil, nil)}
	p := &AssertionTestCaseProvider{fuzzer: f}
	sequences := []calls.CallSequence{{}, {}}
	accepted := make(chan int, 2)
	start, stop := make(chan struct{}), make(chan struct{})
	var writers, readers sync.WaitGroup
	readers.Add(1)
	go func() {
		defer readers.Done()
		close(start)
		for {
			select {
			case <-stop:
				return
			default:
			}
			c.markRunning()
			c.markPassed()
			_ = c.Status()
			_ = c.CallSequence()
			_ = c.Message()
		}
	}()
	for i := range sequences {
		writers.Add(1)
		go func(i int) {
			defer writers.Done()
			<-start
			ok, err := p.finalizeFailure(&FuzzerWorker{fuzzer: f, workerIndex: i}, c, &sequences[i])
			if err != nil {
				t.Errorf("finalize assertion: %v", err)
				return
			}
			if ok {
				accepted <- i
			}
		}(i)
	}
	writers.Wait()
	close(stop)
	readers.Wait()
	close(accepted)
	require.Len(t, accepted, 1)
	winner := <-accepted
	require.NotSame(t, &sequences[winner], c.CallSequence())
	require.Equal(t, sequences[winner], *c.CallSequence())
	require.Equal(t, TestCaseStatusFailed, c.Status())
	require.EqualValues(t, 1, f.metrics.FailedSequences().Int64())
	require.Len(t, f.testCasesFinished, 1)
}
