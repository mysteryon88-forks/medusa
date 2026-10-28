// Command metrics polls a campaign once per second and prints its final sample.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/crytic/medusa/chain"
	"github.com/crytic/medusa/fuzzing"
	"github.com/crytic/medusa/fuzzing/config"
	"github.com/crytic/medusa/fuzzing/executiontracer"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 2 {
		return errors.New("usage: metrics path/to/medusa.json")
	}
	path, err := filepath.Abs(os.Args[1])
	if err != nil {
		return err
	}
	c, err := config.ReadProjectConfigFromFile(path, "crytic-compile")
	if err != nil {
		return err
	}
	if err := os.Chdir(filepath.Dir(path)); err != nil {
		return err
	}
	f, err := fuzzing.NewFuzzer(*c)
	if err != nil {
		return err
	}
	ready := make(chan struct{})
	setup := f.Hooks.ChainSetupFunc
	f.Hooks.ChainSetupFunc = func(f *fuzzing.Fuzzer, c *chain.TestChain) (*executiontracer.ExecutionTrace, error) {
		close(ready)
		return setup(f, c)
	}
	done := make(chan error, 1)
	go func() { done <- f.Start() }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	output := json.NewEncoder(os.Stdout)
	emit := func(final bool) error {
		s := f.Metrics()
		markers, available := s.CoverageMarkersHit()
		return output.Encode(map[string]any{
			"calls": s.CallsTested().String(), "sequences": s.SequencesTested().String(),
			"failures": s.FailedSequences().String(), "gas": s.GasUsed().String(),
			"workerStartups": s.WorkerStartupCount().String(), "shrinking": s.WorkersShrinkingCount(),
			"coverageMarkers": markers, "coverageAvailable": available, "final": final,
		})
	}
	for {
		select {
		case err := <-done:
			return errors.Join(err, emit(true))
		case <-ticker.C:
			if err := emit(false); err != nil {
				select {
				case <-ready:
					f.Terminate()
					<-done
				case <-done:
				}
				return err
			}
		}
	}
}
