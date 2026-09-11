# VeRedact

Evaluation framework for **ZK-Redact** — a privacy-preserving scheme for scalable redaction and provenance auditing in permissioned blockchains.

## Evaluation Principles

- **Fair comparison.** All experiments run against a **consistent database, configuration, and workload**.
- **No hardcoded values or bias.** Every parameter (batch sizes, shard counts, key lengths, workload profiles) is loaded from a shared config file — never embedded in code.
- **No magic numbers.** Parameters from other papers are not blindly reused. All values must be justified in the config or documented with rationale.
- **Reproducibility.** Identical configs produce identical results across runs.

## Target Environment

| Item | Spec |
|---|---|
| **OS** | Ubuntu 22.04 LTS (AWS EC2) |
| **Instance** | `c6i.8xlarge` — 32 vCPU, 64 GB, 200 GB gp3 |
| **Runtime** | Go >= 1.25 (single language across all components) |
| **ZK** | `gnark` / `gnark-crypto` — Groth16 over BLS12-381 |
| **Blockchain** | Docker & Docker Compose, Hyperledger Fabric 2.5 |
| **Build tools** | Make, `protoc` >= 3.21 |

> [!NOTE]
> **Go only — no Rust or Node.js.** `gnark-crypto` supplies both the Groth16
> prover/verifier and the BLS12-381 pairings that the Ref[13] baseline needs,
> so one dependency covers the scheme and a baseline. Keeping the stack in one
> language also removes any FFI boundary from the measured path, where its cost
> would be attributable to neither design.

> [!IMPORTANT]
> Instance sizing follows a **CPU budget**, not a headline core count. Fabric
> peers, orderers, and the load generator leave roughly 20 of the 32 vCPUs to
> the system under test. A 16-vCPU host would leave about 4, so Exp 1 would
> saturate at 4 and look like a scaling limit of sharding when it is really CPU
> contention — clean, plausible, and wrong.

> [!IMPORTANT]
> If any component requires an additional library or system dependency beyond the list above, it **must** be documented in that component's README and flagged during review.

## Components

| # | Component | Role |
|---|---|---|
| 1 | **Proto** | Shared protobuf message definitions |
| 2 | **CH Library** | Chameleon hash `KeyGen` / `Hash` / `Adapt` |
| 3 | **ZK Circuits & PVL** | ZK circuit compilation, proof generation/verification, shard management |
| 4 | **Redaction Gateway** | Request auth, dedup, identity minimization |
| 5 | **Provenance Audit Index** | Hash-linked histories, Merkle auth, blockchain anchoring |
| 6 | **Blockchain Network** | Permissioned network + chaincode deployment |

## Building

> [!CAUTION]
> **Build every component before running any experiment.** Components have inter-dependencies; experiments against stale or missing builds produce invalid results.

Build in dependency order:

```bash
# 1. Shared protobuf definitions
make proto

# 2. Chameleon hash library
make build-ch

# 3. ZK circuits and proof verification layer
make build-zk          # circuit compilation may take several minutes

# 4. Redaction gateway
make build-gateway

# 5. Provenance audit index
make build-pai

# 6. Blockchain network and chaincode
make build-network
make deploy-chaincode
```

Or build everything at once (respects dependency order):

```bash
make all
make test   # run full test suite
```

## Running Experiments

All experiments read from the shared config (`config/experiment.yaml`).

```bash
make validate-config   # check config before running anything
make pilot             # resolve sweep bounds by measurement
make experiments       # run all three experiments

make experiment-verification-throughput  # Exp 1 — sharding N is the variable
make experiment-redaction-throughput     # Exp 2 — batching B_R is the variable
make experiment-provenance-audit         # Exp 3 — targeted retrieval
make experiment-e2e                      # full pipeline under concurrent load
```

> [!NOTE]
> Experiments are named after the operation **every** system performs, with
> ZK-Redact's mechanism as the swept variable. Naming them after our own
> mechanism (`zkp-throughput`, `batch-latency`) would exclude the baselines by
> definition. See [`docs/experiments.md`](docs/experiments.md).

Every experiment target depends on `validate-config`. Several config errors do
not crash anything — they silently void the comparison — so validation is a
prerequisite, not a habit.

Results are written to `results/` (CSV + JSON) with plots in `results/plots/`.

## Project Structure

```
VeRedact/
├── Reference/             # Scheme specification + baseline papers
├── docs/
│   ├── experiments.md     # Experiment specification + fairness contract
│   └── baselines/         # Per-baseline implementation specs
├── cmd/                   # Component entrypoints (incl. validate-config)
├── pkg/                   # Shared libraries (proto, ch, zk, crypto, merkle)
├── internal/              # Component internals (gateway, pvl, redactor, pai)
│   └── schemes/           # Registry + all four systems (zkredact, ref10, ref13, ref22)
├── network/               # Blockchain network config + chaincode
├── config/                # Shared experiment and scheme configurations
├── experiments/           # Experiment scripts
├── results/               # Output (generated)
├── build/                 # Build artifacts (generated)
├── Makefile
└── README.md
```

Baselines are **re-implemented** on this shared harness rather than cited. The
three reference papers use different languages, hardware, and platforms, so
their published figures cannot share a table with ours — the fair-comparison
rule above requires one environment for all systems.

## References

See [`ZK-Redact Scheme/ZK-Redact.pdf`](ZK-Redact%20Scheme/ZK-Redact.pdf) for the full formal specification.

## License

TBD