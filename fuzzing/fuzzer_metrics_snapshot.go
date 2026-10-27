package fuzzing

import "math/big"

// FuzzerMetricsSnapshot is a detached sample of one campaign. Workers are sampled
// sequentially, so a running sample is not a global transaction. Its zero value is usable.
type FuzzerMetricsSnapshot struct {
	calls, sequences, failures, gas, startups *big.Int
	shrinking, coverageMarkers                uint64
	coverageAvailable                         bool
}

func copyCounter(value *big.Int) *big.Int {
	if value == nil {
		return new(big.Int)
	}
	return new(big.Int).Set(value)
}

// CallsTested returns calls executed on the main testing path.
func (s FuzzerMetricsSnapshot) CallsTested() *big.Int { return copyCounter(s.calls) }

// SequencesTested returns sequences executed on the main testing path.
func (s FuzzerMetricsSnapshot) SequencesTested() *big.Int { return copyCounter(s.sequences) }

// FailedSequences returns accepted finalized failures, rather than unique vulnerabilities.
func (s FuzzerMetricsSnapshot) FailedSequences() *big.Int { return copyCounter(s.failures) }

// GasUsed returns gas consumed on the main testing path.
func (s FuzzerMetricsSnapshot) GasUsed() *big.Int { return copyCounter(s.gas) }

// WorkerStartupCount includes worker resets during this campaign.
func (s FuzzerMetricsSnapshot) WorkerStartupCount() *big.Int { return copyCounter(s.startups) }

// WorkersShrinkingCount returns the number of workers currently shrinking.
func (s FuzzerMetricsSnapshot) WorkersShrinkingCount() uint64 { return s.shrinking }

// CoverageMarkersHit returns reached branch markers and whether coverage is ready
// and enabled. This is a count, not a percentage of Solidity source coverage.
func (s FuzzerMetricsSnapshot) CoverageMarkersHit() (uint64, bool) {
	return s.coverageMarkers, s.coverageAvailable
}

// Metrics safely samples this campaign while Start runs. After Start returns the
// final sample is stable until the next sequential Start. Stop is not a barrier.
func (f *Fuzzer) Metrics() FuzzerMetricsSnapshot {
	f.metricsLock.Lock()
	defer f.metricsLock.Unlock()
	if f.metricsFinal != nil {
		return *f.metricsFinal
	}
	return f.snapshotMetricsLocked()
}

func (f *Fuzzer) snapshotMetricsLocked() FuzzerMetricsSnapshot {
	s := FuzzerMetricsSnapshot{
		calls: new(big.Int), sequences: new(big.Int), failures: new(big.Int),
		gas: new(big.Int), startups: new(big.Int),
	}
	if f.metrics != nil {
		for i := range f.metrics.workerMetrics {
			w := &f.metrics.workerMetrics[i]
			w.lock.Lock()
			s.calls.Add(s.calls, w.callsTested)
			s.sequences.Add(s.sequences, w.sequencesTested)
			s.failures.Add(s.failures, w.failedSequences)
			s.gas.Add(s.gas, w.gasUsed)
			s.startups.Add(s.startups, w.workerStartupCount)
			if w.shrinking {
				s.shrinking++
			}
			w.lock.Unlock()
		}
	}
	// Slot locks are released before taking the coverage lock.
	if f.metricsCoverage != nil {
		s.coverageAvailable = true
		s.coverageMarkers = f.metricsCoverage.BranchesHit()
	}
	return s
}

func (f *Fuzzer) freezeMetrics() {
	f.metricsLock.Lock()
	defer f.metricsLock.Unlock()
	final := f.snapshotMetricsLocked()
	f.metricsFinal = &final
}
