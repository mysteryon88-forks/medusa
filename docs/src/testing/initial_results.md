# Initial property results

Set `fuzzing.testing.propertyTesting.checkInitialState` to `true` to test registered properties after deployment and all
`FuzzerWorkerChainSetup` subscribers, before corpus replay and fuzz calls. It defaults to `false`. Property testing must
be enabled. Genesis-mapped contracts use the same discovery and target filters as deployed contracts.

A false return or an EVM revert produces a property failure with a property execution trace and a non-nil, empty
`CallSequence`. ABI decoding and infrastructure errors return an error from `Start`. Initial checks do not run post-call
hooks, shrink sequences, or increment fuzz call, sequence or gas counters. The first finalized failure for a test ID wins.
The check repeats after worker reset; already finalized failures are retained. With no callable methods, a completed
initial check ends the campaign explicitly.

## Storage

With `corpusDirectory` configured, a failure is saved immediately, even with coverage disabled, as
`initial_results/<sha256>.json`. Version 1 uses `schemaVersion: 1`, `kind: "initialPropertyFailure"`, a test ID, contract
name and identity, property signature and address, `calls: []`, and fingerprints of artifacts, configuration, prepared
state and block history. Filenames include the identity and inputs, so different properties with empty sequences stay
distinct. Writes use a temporary file and atomic rename; read and write errors stop the run. JSON records are limited to
64 KiB and checked for unsupported versions, unknown fields, invalid fingerprints and filename digest mismatches.
The winning candidate is saved before its failure status, counter and report are published. A save error releases
waiting contenders and returns an error without finalizing that candidate.

The existing arrays in `call_sequences/` and `test_results/` keep their format and replay path. Initial results are not
mutation seeds. With no corpus directory, the failure remains available through the test cases in memory; representable
local inputs also retain a manifest through `Corpus.InitialPropertyResults()`.

## Replay compatibility

On a later run, Medusa loads initial manifests and calls each saved property at its saved address after worker setup,
even with `checkInitialState: false`. All loaded records are validated before reporting failures can trigger a stop.

- Matching inputs and a failing property reproduce the failure with an empty sequence and a fresh trace.
- Changed artifacts, configuration, prepared state or block history return an `initial replay incompatible` error.
- Matching inputs and a property that now passes return an `initial replay not reproduced` error.
- Disabled property testing returns an `initial replay unsupported` error before the general no-tests guard.
- Emergency cancellation during validation aborts replay with `context.Canceled` before publishing its collected failures.

Errors identify the filename and test ID and do not mark unresolved properties as passed or failed. Keep the same setup
callbacks and actual inputs. Callbacks themselves are not serialized.

The artifact fingerprint includes sorted contract identities, ABIs and linked init/runtime bytecode, plus compiler
version and embedded compiler metadata where available. Missing compiler provenance is explicitly `unknown`; matching
artifacts do not prove identical compiler executables. Absolute source paths are excluded. The configuration projection
includes chain ID, funded account/deployment inputs, senders, property selection and EVM flags and gas limits. It excludes
worker count, timeout, test limit, logging, corpus path, `checkInitialState`, and RPC credentials.

The prepared state must match a committed state root and have no pending block. Block fingerprints include committed
headers and their cached execution hashes, covering the current EVM header fields and prior `BLOCKHASH` inputs. Uncommitted or otherwise unrepresentable
setup cannot produce a replayable manifest. Version 1 also rejects persistent replay of lazy RPC fork state because its
local root does not bind all remote reads. Initial checks without persistence can still evaluate such states in memory.
Mutable external inputs and worker-specific external setup are outside the reproducibility guarantee.
The corpus filesystem must remain stable during loading; this format does not protect against another process replacing
paths while they are read.

`medusa corpus clean` validates and preserves these manifests, reporting deferred property verification. It does not call
the saved properties; their evaluation occurs in worker setup.
