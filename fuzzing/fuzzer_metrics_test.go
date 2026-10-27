package fuzzing

import (
	"math/big"
	"sync"
	"testing"
)

func TestRaceMetrics(t *testing.T) {
	m := newFuzzerMetrics(4, nil)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range m.workerMetrics {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			for j := 0; j < 1000; j++ {
				m.workerMetrics[i].recordCall(7)
				m.workerMetrics[i].recordSequence()
			}
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 1000; i++ {
			_ = m.CallsTested()
			_ = m.GasUsed()
			_ = m.SequencesTested()
			_ = m.WorkersShrinkingCount()
		}
	}()
	close(start)
	wg.Wait()
	if m.CallsTested().Int64() != 4000 || m.GasUsed().Int64() != 28000 || m.SequencesTested().Int64() != 4000 {
		t.Fatal("unexpected totals", m.CallsTested(), m.GasUsed(), m.SequencesTested())
	}
	m.CallsTested().SetInt64(-1)
	if m.CallsTested().Int64() != 4000 {
		t.Fatal("reader changed engine counter")
	}
}

func TestMetricsOverflow(t *testing.T) {
	m := newFuzzerMetrics(1, nil)
	w := &m.workerMetrics[0]
	w.recordCall(^uint64(0))
	w.recordCall(^uint64(0))
	want := new(big.Int).Lsh(big.NewInt(1), 65)
	want.Sub(want, big.NewInt(2))
	if m.GasUsed().Cmp(want) != 0 {
		t.Fatalf("gas = %s, want %s", m.GasUsed(), want)
	}
}
