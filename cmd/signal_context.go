package cmd

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/crytic/medusa/chain"
	"github.com/crytic/medusa/fuzzing"
	"github.com/crytic/medusa/fuzzing/executiontracer"
)

type campaignCancellation struct {
	ready, requested atomic.Bool
	terminate        func()
}

func (c *campaignCancellation) request() {
	c.requested.Store(true)
	if c.ready.Load() {
		c.terminate()
	}
}

func (c *campaignCancellation) markReady() {
	c.ready.Store(true)
	if c.requested.Load() {
		c.terminate()
	}
}

func startWithSignalContext(ctx context.Context, f *fuzzing.Fuzzer) error {
	return runWithSignalContext(ctx, f, f.Start)
}

func runWithSignalContext(ctx context.Context, f *fuzzing.Fuzzer, run func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cancellation := campaignCancellation{terminate: f.Terminate}
	setup := f.Hooks.ChainSetupFunc
	f.Hooks.ChainSetupFunc = func(f *fuzzing.Fuzzer, c *chain.TestChain) (*executiontracer.ExecutionTrace, error) {
		// Start has initialized all cancellation functions before invoking setup.
		cancellation.markReady()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return setup(f, c)
	}
	stop, finished := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(finished)
		select {
		case <-ctx.Done():
			cancellation.request()
		case <-stop:
		}
	}()
	defer func() {
		close(stop)
		<-finished
		f.Hooks.ChainSetupFunc = setup
	}()
	err := run()
	return errors.Join(err, ctx.Err())
}
