package corpus

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"

	gethTypes "github.com/crytic/medusa-geth/core/types"
	"github.com/crytic/medusa/chain"
	"github.com/crytic/medusa/logging"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type prunerContext struct {
	context.Context
	observed chan struct{}
	once     sync.Once
}

func (c *prunerContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.observed) })
	return c.Context.Done()
}

func TestCorpusPrunerRunOwnership(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	logger := logging.NewLogger(zerolog.Disabled)
	ch, err := chain.NewTestChain(context.Background(), gethTypes.GenesisAlloc{}, nil)
	require.NoError(t, err)
	defer ch.Close()
	c, err := NewCorpus("")
	require.NoError(t, err)
	p := NewCorpusPruner(true, 1, logger)
	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer func() { cancel1(); cancel2(); p.Wait() }()
	one := &prunerContext{Context: ctx1, observed: make(chan struct{})}
	two := &prunerContext{Context: ctx2, observed: make(chan struct{})}
	require.NoError(t, p.Start(one, c, ch))
	require.NoError(t, p.Start(two, c, ch))
	for _, observed := range []chan struct{}{one.observed, two.observed} {
		select {
		case <-observed:
		case <-time.After(3 * time.Second):
			t.Fatal("pruner did not retain its run context")
		}
	}
	cancel1()
	cancel2()
	p.Wait()
}
