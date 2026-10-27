package randomutils

import (
	"math/big"
	"sync"
	"testing"
)

func TestRaceWeightedChooser(t *testing.T) {
	c := NewWeightedRandomChooser[int]()
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 1000; i++ {
			c.AddChoices(NewWeightedRandomChoice(i, big.NewInt(1)))
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 1000; i++ {
			_ = c.ChoiceCount()
			value, err := c.Choose()
			if err == nil && (value == nil || *value < 0 || *value >= 1000) {
				t.Error("invalid selected value", value)
			}
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 1000; i++ {
			c.RemoveChoices(map[int]bool{0: true})
		}
	}()
	close(start)
	wg.Wait()
	if got := c.ChoiceCount(); got < 0 || got > 1000 {
		t.Fatalf("invalid remaining count %d", got)
	}
	remove := make(map[int]bool)
	for i := 0; i < c.ChoiceCount(); i++ {
		remove[i] = true
	}
	c.RemoveChoices(remove)
	if value, err := c.Choose(); value != nil || err == nil {
		t.Fatal("empty chooser must return an error")
	}
	c.AddChoices(NewWeightedRandomChoice(1, big.NewInt(0)))
	if value, err := c.Choose(); value != nil || err == nil {
		t.Fatal("zero-weight chooser must return an error")
	}
}
