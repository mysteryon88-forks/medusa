package corpus

import (
	"math/big"
	"sync"
	"testing"

	"github.com/crytic/medusa/fuzzing/calls"
	"github.com/stretchr/testify/require"
)

func TestRaceCorpusMonitoring(t *testing.T) {
	c, err := NewCorpus("")
	require.NoError(t, err)
	c.unexecutedCallSequences = make([]calls.CallSequence, 1000)
	for i := range c.unexecutedCallSequences {
		c.unexecutedCallSequences[i] = getMockCallSequence(1)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for c.UnexecutedCallSequence() != nil {
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 200; i++ {
			if err := c.AddTestResultCallSequence(getMockCallSequence(1), big.NewInt(1), false); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	close(start)
	for i := 0; i < 10000; i++ {
		c.InitializingCorpus()
		c.CallSequenceEntryCount()
	}
	wg.Wait()
	require.False(t, c.InitializingCorpus())
	_, results := c.CallSequenceEntryCount()
	require.Equal(t, 200, results)
}
