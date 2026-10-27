# Campaign metrics

`fuzzer.Metrics()` safely samples a campaign while `Start()` runs. The returned
`FuzzerMetricsSnapshot` is detached: every counter getter returns an independent
`*big.Int`. Its zero value and a sample taken before `Start()` contain zero counters.

```go
sample := fuzzer.Metrics()
calls := sample.CallsTested()
gas := sample.GasUsed()
markers, available := sample.CoverageMarkersHit()
```

The other getters are `SequencesTested()`, `FailedSequences()`,
`WorkerStartupCount()` and `WorkersShrinkingCount()`. Worker startups include resets;
totals survive those resets. Calls and gas cover the existing main testing path,
not every deployment, property evaluation or shrinking execution. Failures count
accepted finalized results, not unique transaction sequences or vulnerabilities.

Coverage is unavailable until corpus initialization completes, and whenever
coverage is disabled. `(0, true)` means enabled, ready coverage with no reached
markers; `(0, false)` means unavailable. Markers are branch events, not a percentage
of Solidity source coverage.

Workers are sampled sequentially. Each worker's counters are coherent, but a
running sample does not stop all workers at one instant. Poll once per second for
progress. Wait for `Start()` to return before taking the final sample; `Stop()`
alone is not a completion barrier. The final sample remains stable until the next
sequential `Start()`, which resets telemetry and coverage readiness. Concurrent
calls to `Start()` on the same fuzzer are unsupported.

The buildable example in `examples/metrics/main.go`
uses a ticker, a buffered completion channel and a final sample. Run it with
`go run ./examples/metrics path/to/medusa.json`. Counter values in its JSON samples
are decimal strings to retain integers larger than 64 bits. Normal Medusa logs
are also printed; this example does not change a consumer's report format.

Corpus-health arithmetic and guard tests reuse gophersg's
[PR #848](https://github.com/crytic/medusa/pull/848), commit
`69af87a2960a7d6135ba51387d416011cc3e4b8e`. That patch fixes health totals and monitoring
of a corpus containing only one kind of entry. Campaign monitor cancellation and
joining are separate lifecycle changes in this fork.
