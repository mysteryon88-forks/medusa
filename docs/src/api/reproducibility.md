# RFC: seeded campaigns

Status: deferred proposal. This series adds no seed configuration or deterministic
campaign mode. The earlier discussion is [issue #201](https://github.com/crytic/medusa/issues/201).

## Current behavior

Each `Fuzzer.Start()` seeds its main PRNG from the clock and derives worker PRNGs
from that source. Corpus mutation selection creates a separate clock-seeded
chooser, and pruning uses the package-level `rand.Perm`. A future seed must reach
all these paths, including worker resets, generation and shrinking.

Worker scheduling, unordered map iteration, corpus publication and pruning,
wall-clock cancellation, setup callbacks and RPC responses also influence a run.
For a test ID, the first finalized failure wins; another schedule can select a
different counterexample. A shared seed alone cannot promise the same campaign.

Saved call sequences and versioned initial-property manifests already have their
own replay paths. Initial replay validates the prepared inputs and evaluates the
named property again; it does not recreate a previous campaign's scheduling.

## Possible guarantees

| Level                             | Proposed guarantee                                                                                                 | Required work and cost                                                                                                                                                                                                                                                  |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Seeded PRNG                       | The same algorithm and seed produce the same random stream for the same ordered requests.                          | Route every RNG through an explicit campaign-owned source; define child seeds and reset semantics. Audit remaining global or clock-seeded sources. This does not guarantee the same generated campaign.                                                                 |
| Repeatable single-worker campaign | The same supported inputs and exact work budget reproduce generation, shrinking and final results with one worker. | Also stabilize ordering, corpus inputs, pruning and setup; pin artifacts, toolchain and EVM inputs. Add an exact work budget rather than relying on wall-clock timeout or the current periodically checked limit. Restrict uncontrolled callbacks, FFI and mutable RPC. |
| Repeatable multi-worker campaign  | The same supported inputs reproduce results across parallel runs.                                                  | Also order work assignment, shared corpus updates, pruning and failure publication. A deterministic coordinator or recorded scheduling protocol adds synchronization, storage or replay costs; ordinary OS scheduling is insufficient.                                  |

## Acceptance before implementation

Choose and name the promised level before adding a public option. Record the seed,
PRNG algorithm/version, worker/reset policy and identities of the relevant
artifacts, configuration, starting corpus and prepared state. Define which
external inputs are supported and how unsupported inputs are rejected.

Test fresh independent processes and repeated `Start()` calls. For a PRNG-only
option, compare streams and child derivation. For deterministic campaigns, compare
ordered generated calls, corpus decisions, shrunk counterexamples and final test
results under an exact work budget. Measure throughput and memory cost against
the ordinary mode. A multi-worker claim also needs varied scheduling and worker
reset tests.

The smallest next feature would be the explicitly limited PRNG level after its
audit. Single-worker and multi-worker guarantees require separate decisions and
implementation work. Seed implementation remains outside this series.
