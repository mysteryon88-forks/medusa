package fuzzing

import (
	"math/big"
	"sync"

	"github.com/crytic/medusa/fuzzing/calls"
	"github.com/crytic/medusa/fuzzing/reverts"
)

// FuzzerMetrics represents a struct tracking metrics for a Fuzzer run.
type FuzzerMetrics struct {
	// workerMetrics describes the metrics for each individual worker. This expands as needed and some slots may be nil
	// while workers are initializing, as it corresponds to the indexes in Fuzzer.workers.
	workerMetrics []fuzzerWorkerMetrics
}

// fuzzerWorkerMetrics represents metrics for a single FuzzerWorker instance.
type fuzzerWorkerMetrics struct {
	lock sync.Mutex
	// sequencesTested is the amount of sequences of transactions which tests were run against.
	sequencesTested *big.Int

	// failedSequences is the amount of sequences of transactions which tests failed.
	failedSequences *big.Int

	// callsTested is the amount of transactions/calls the fuzzer executed and ran tests against.
	callsTested *big.Int

	// revertMetricsChan is the channel for sending revert metrics updates to the revert reporter.
	// Note that the channel can be nil here if revert metrics are not enabled
	revertMetricsChan chan reverts.RevertMetricsUpdate

	// gasUsed is the amount of gas the fuzzer executed and ran tests against.
	gasUsed *big.Int

	// workerStartupCount is the amount of times the worker was generated, or re-generated for this index.
	workerStartupCount *big.Int

	// shrinking indicates whether the fuzzer worker is currently shrinking.
	shrinking bool
}

// newFuzzerMetrics obtains a new FuzzerMetrics struct for a given number of workers specified by workerCount.
// An optional channel for sending revert metrics updates to the revert reporter is also provided.
// Returns the new FuzzerMetrics object.
func newFuzzerMetrics(workerCount int, revertMetricsCh chan reverts.RevertMetricsUpdate) *FuzzerMetrics {
	// Create a new metrics struct and return it with as many slots as required.
	metrics := FuzzerMetrics{
		workerMetrics: make([]fuzzerWorkerMetrics, workerCount),
	}
	for i := 0; i < len(metrics.workerMetrics); i++ {
		metrics.workerMetrics[i].sequencesTested = big.NewInt(0)
		metrics.workerMetrics[i].failedSequences = big.NewInt(0)
		metrics.workerMetrics[i].callsTested = big.NewInt(0)
		metrics.workerMetrics[i].workerStartupCount = big.NewInt(0)
		metrics.workerMetrics[i].gasUsed = big.NewInt(0)
		metrics.workerMetrics[i].revertMetricsChan = revertMetricsCh

	}
	return &metrics
}

// FailedSequences returns the number of sequences that led to failures across all workers
func (m *FuzzerMetrics) FailedSequences() *big.Int {
	failedSequences := big.NewInt(0)
	for i := range m.workerMetrics {
		w := &m.workerMetrics[i]
		w.lock.Lock()
		failedSequences.Add(failedSequences, w.failedSequences)
		w.lock.Unlock()
	}
	return failedSequences
}

// SequencesTested returns the amount of sequences of transactions the fuzzer executed and ran tests against.
func (m *FuzzerMetrics) SequencesTested() *big.Int {
	sequencesTested := big.NewInt(0)
	for i := range m.workerMetrics {
		w := &m.workerMetrics[i]
		w.lock.Lock()
		sequencesTested.Add(sequencesTested, w.sequencesTested)
		w.lock.Unlock()
	}
	return sequencesTested
}

// CallsTested returns the amount of transactions/calls the fuzzer executed and ran tests against.
func (m *FuzzerMetrics) CallsTested() *big.Int {
	transactionsTested := big.NewInt(0)
	for i := range m.workerMetrics {
		w := &m.workerMetrics[i]
		w.lock.Lock()
		transactionsTested.Add(transactionsTested, w.callsTested)
		w.lock.Unlock()
	}
	return transactionsTested
}

func (m *FuzzerMetrics) GasUsed() *big.Int {
	gasUsed := big.NewInt(0)
	for i := range m.workerMetrics {
		w := &m.workerMetrics[i]
		w.lock.Lock()
		gasUsed.Add(gasUsed, w.gasUsed)
		w.lock.Unlock()
	}
	return gasUsed
}

// WorkerStartupCount describes the amount of times the worker was spawned for this index. Workers are periodically
// reset.
func (m *FuzzerMetrics) WorkerStartupCount() *big.Int {
	workerStartupCount := big.NewInt(0)
	for i := range m.workerMetrics {
		w := &m.workerMetrics[i]
		w.lock.Lock()
		workerStartupCount.Add(workerStartupCount, w.workerStartupCount)
		w.lock.Unlock()
	}
	return workerStartupCount
}

// WorkersShrinkingCount returns the amount of workers currently performing shrinking operations.
func (m *FuzzerMetrics) WorkersShrinkingCount() uint64 {
	shrinkingCount := uint64(0)
	for i := range m.workerMetrics {
		w := &m.workerMetrics[i]
		w.lock.Lock()
		if w.shrinking {
			shrinkingCount++
		}
		w.lock.Unlock()
	}
	return shrinkingCount
}

// updateRevertMetrics updates the revert metrics for the fuzzer worker based on the call sequence element.
func (m *fuzzerWorkerMetrics) updateRevertMetrics(callSequenceElement *calls.CallSequenceElement) {
	// The channel will be nil if revert metrics are not enabled
	if callSequenceElement == nil || m.revertMetricsChan == nil {
		return
	}

	// Send the revert metrics update to the revert reporter
	m.revertMetricsChan <- reverts.RevertMetricsUpdate{
		ContractName:    callSequenceElement.Contract.Name(),
		FunctionName:    callSequenceElement.Call.DataAbiValues.Method.Name,
		ExecutionResult: callSequenceElement.ChainReference.MessageResults().ExecutionResult,
	}
}

// Counter updates and snapshots share each slot's lock.
func (m *fuzzerWorkerMetrics) recordCall(gas uint64) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.callsTested.Add(m.callsTested, big.NewInt(1))
	m.gasUsed.Add(m.gasUsed, new(big.Int).SetUint64(gas))
}
func (m *fuzzerWorkerMetrics) recordSequence() {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.sequencesTested.Add(m.sequencesTested, big.NewInt(1))
}
func (m *fuzzerWorkerMetrics) recordFailure() {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.failedSequences.Add(m.failedSequences, big.NewInt(1))
}
func (m *fuzzerWorkerMetrics) recordStartup() {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.workerStartupCount.Add(m.workerStartupCount, big.NewInt(1))
}
func (m *fuzzerWorkerMetrics) setShrinking(shrinking bool) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.shrinking = shrinking
}
func (m *fuzzerWorkerMetrics) sequenceWeight() *big.Int {
	m.lock.Lock()
	defer m.lock.Unlock()
	return new(big.Int).Add(m.sequencesTested, big.NewInt(1))
}
