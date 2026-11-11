# ZK-Redact

**An evaluation framework for ZK-Redact** — a privacy-preserving scheme for
scalable redaction and provenance auditing in permissioned blockchains.

> **Accepted at IEEE KST 2027.**

## What this is

Permissioned blockchains sometimes have to forget. A record enters the ledger
and later has to come out — a legal erasure order, a key leak, content that was
never supposed to be written down. Immutability, the property the ledger was
built for, becomes the obstacle.

Redaction schemes answer this, and each one answers it differently: who may
authorize a redaction, what they learn in the process, how the change is
recorded, and how an auditor later proves what was removed and by whom.

VeRedact is the harness that compares those answers.

## The problem it exists to solve

Redaction schemes are published in different languages, on different hardware,
against different platforms, with different measurement boundaries. Their
figures cannot honestly share a table. Citing them side by side compares
environments, not designs.

So VeRedact does not cite baselines — it **re-implements** them. ZK-Redact and
three reference schemes run on one shared harness: the same dataset, the same
config file, the same request trace, the same permissioned network, the same
timers. A difference in the numbers is then a difference between designs, and
not between harnesses.

## The four systems

| Name | Mechanism |
|---|---|
| `zkredact` | Groth16 over BLS12-381, sharded proof verification, batched redaction, hash-linked provenance index |
| `ref10_emt` | Committee vote with aggregated Schnorr verification over an extended Merkle tree |
| `ref13_vrbc` | Manager trapdoor check, q-ary blockchain authentication tree over Pointproofs vector commitments |
| `ref22_shen` | Regulator key check, double-trapdoor chameleon hash, trapdoorless universal RSA accumulator |

Each baseline implements the authorization, redaction and audit path its own
paper specifies — not a convenient sketch of it. Every deviation is written down
rather than left silent.

## What it compares

Three questions, each named after the operation **every** system performs, with
ZK-Redact's mechanism as the swept variable. Naming an experiment after our own
mechanism would exclude the baselines by definition.

| Experiment | Question |
|---|---|
| **Verification Throughput** | How many authorizations per second survive concurrent load, and does sharding the proof verification actually buy scale? |
| **Redaction Throughput** | What does batching amortize, what stays a per-request floor, and what does the resulting staleness cost? |
| **Provenance Audit Cost** | Does the cost of auditing a transaction's redaction history track the depth of that history, or the size of the whole ledger? |

## How it keeps the comparison honest

**Cryptographic cost and consensus cost are never summed.** Off-chain
cryptographic work and ledger/consensus work are timed separately and reported
separately. A single blended number hides which half a design actually moved.

**Every performance table is published beside a capability matrix.** A system
can be fast for the uninteresting reason that it does less work — no
privacy-preserving authorization, no per-transaction provenance, no freshness
revalidation. One row in particular is the row a latency column cannot be read
without: whether a scheme's authorization requires consensus at all. Otherwise a
networked protocol and a function call appear in the same column, with nothing
saying so.

**Nothing is simulated.** No analytical cost models, no extrapolation, no
placeholder timings.

**Nothing is hardcoded.** Shard counts, batch sizes, committee sizes, key
lengths, tree arity, workload rates — all read from one shared config at
runtime. A literal in code is a defect.

**No magic numbers.** A value taken from a reference paper is invalid until its
rationale is recorded beside it. The derivation transfers, never the digit.

**Reproducible or it does not count.** Same config plus same seed yields the
same results; every run records its resolved config, seed, dataset, code
revision and environment fingerprint. A result that cannot be regenerated from
those does not go into the paper.

Most of the guards in this codebase exist to *enforce* these rules rather than
trust them, because the failure mode is silent: a baseline handed a cheaper
primitive than its paper specifies does not crash, fails no test, and looks
perfectly fine in a plot.

## Where to look

| File | For |
|---|---|
| [`SKILL.md`](SKILL.md) | the rules and the target environment |
| [`docs/experiments.md`](docs/experiments.md) | what is measured, against what, under which conditions |
| [`docs/baselines/`](docs/baselines/) | per-baseline scope, timing boundaries, deviation lists |
| [`docs/paper-conformance.md`](docs/paper-conformance.md) | every claim against its paper citation |
| [`config/experiment.yaml`](config/experiment.yaml) | every parameter, with its rationale |

## License

TBD
