# VeRedact

Evaluation framework for **ZK-Redact** — a privacy-preserving scheme for
scalable redaction and provenance auditing in permissioned blockchains.

Three re-implemented baselines run against the same dataset, config, workload
and Hyperledger Fabric network, so a difference in the numbers is a difference
between designs and not between harnesses.

## What it measures

Each experiment is named after the operation **every** system performs, with
ZK-Redact's mechanism as the swept variable.

| Exp | Question | Swept | Real competitor |
|---|---|---|---|
| 1 Verification Throughput | authorizations/sec under concurrent load | shards `N` 1→64 | Ref[10] |
| 2 Redaction Throughput | cost batching amortises, and its staleness price | batch `B_R` 1→64 | all three |
| 3 Provenance Audit Cost | does audit cost track history depth, not ledger size | ledger `L` 100, 1,000 | Ref[13] |

Full spec: [`docs/experiments.md`](docs/experiments.md).

## The four systems

| Name | What it is | State |
|---|---|---|
| `zkredact` | Groth16 over BLS12-381, sharded proof verification | all six phases run; all three experiments |
| `ref10_emt` | committee vote, real chaincode on a real Fabric network | complete |
| `ref22_shen` | trapdoorless universal RSA accumulator | complete |
| `ref13_vrbc` | q-ary BAT over Pointproofs vector commitments | complete |

All three experiments run against all four systems from
`config/experiment.yaml`'s `systems:` lists; nothing is currently excluded.

## Quick start

```bash
make validate-config   # the gate every experiment target depends on
make all               # build every component in dependency order
make test              # vet + full suite, no Docker required
make build-zk          # compile the circuit and check it against the config
make pilot             # short run to resolve sweep bounds, before spending real time
```

Then, with the network up (below):

```bash
make experiments   # all three experiments
# or one at a time:
make experiment-verification-throughput
make experiment-redaction-throughput
make experiment-provenance-audit

make plots         # regenerate the figures from the results directory
```

A full sweep is large enough to shard across several hosts unattended:
[`scripts/launch-run.sh`](scripts/launch-run.sh) provisions up to 20 real EC2
instances (`c6i.8xlarge`, ~$1.4/hour each), each running one assigned slice
and publishing its own results, and terminates them when done. It is
documented in its own header, not elsewhere — read that before running it.
[`scripts/setup-ec2.sh`](scripts/setup-ec2.sh) provisions a single host by
hand for anything smaller.

Live network work needs Docker:

```bash
./network/scripts/network.sh up minimal   # 1 org — correctness only
./network/scripts/network.sh up full      # 4 orgs x 2 peers — measurement topology
./network/scripts/network.sh deploy && ./network/scripts/smoke.sh
make test-live                            # build-tagged, cannot pass quietly
```

## Where numbers are valid

The reference environment is Ubuntu 22.04 on `c6i.8xlarge` (32 vCPU, 64 GB).
Anything else runs the code but does not measure it: the runner checks clock
resolution at startup and **refuses a real run on a host whose clock is too
coarse**, and the minimal topology is a correctness check that produces no
measurements.

Every experiment target depends on `validate-config`. Validation you have to
remember is validation that gets skipped.

## The rules

Three constraints shape most of this codebase, and most of the guards exist to
enforce them rather than trust them:

1. **No fake, no simulation.** Every number comes from real code against a real
   network — no analytical models, no extrapolation, no placeholder timings.
2. **No hardcoded parameters.** Everything lives in `config/experiment.yaml`.
3. **No magic numbers.** A value from a reference paper is invalid until its
   rationale is recorded beside it. The derivation transfers, never the digit.

The failure mode this guards against is silent: a baseline handed a cheaper
primitive than its paper specifies does not crash, fails no test, and looks
fine in a plot. If a guard fires, it is telling you something true — do not
remove it to make something pass.

Full text, and the target environment: [`SKILL.md`](SKILL.md).

## Where to look next

| File | For |
|---|---|
| [`SKILL.md`](SKILL.md) | the rules and the target environment — read before changing anything |
| [`TASK.md`](TASK.md) | current state, what is done, what is next, and findings not to re-derive |
| [`config/experiment.yaml`](config/experiment.yaml) | every parameter, each tagged DERIVED / METHOD / PROPOSED / CONFIRM |
| [`docs/paper-conformance.md`](docs/paper-conformance.md) | every claim against its paper citation |
| [`docs/baselines/`](docs/baselines/) | per-baseline scope, timing boundaries, and deviation lists |
