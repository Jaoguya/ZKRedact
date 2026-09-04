# VeRedact

Evaluation framework for **ZK-Redact** — a privacy-preserving scheme for scalable redaction and provenance auditing in permissioned blockchains. This codebase benchmarks ZK-Redact against baseline redactable blockchain schemes under fair, unified conditions.

## Evaluation Principles

- **Fair comparison.** All schemes (ZK-Redact and baselines) run against the **same database, configuration, and workload**. No scheme receives preferential tuning.
- **No hardcoded values or bias.** Every parameter (batch sizes, shard counts, key lengths, workload profiles) is loaded from a shared config file — never embedded in code.
- **No magic numbers.** Parameters from other papers are not blindly reused. All values must be justified in the config or documented with rationale.
- **Reproducibility.** Identical configs produce identical results across runs.

## Target Environment

| Item | Spec |
|---|---|
| **OS** | Ubuntu 22.04 LTS (AWS EC2) |
| **Runtime** | Go >= 1.21, Rust >= 1.75 (ZK circuits), Node.js >= 18 (gateway) |
| **Blockchain** | Docker & Docker Compose (permissioned network) |
| **Build tools** | Make, `protoc` >= 3.21 |

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

All experiments read from the shared config (`config/experiment.yaml`). Each scheme — ZK-Redact and every baseline — uses the **same database snapshot and parameters**.

```bash
make experiments       # run all benchmarks
make experiment-zkp-throughput   # sharded ZKP verification throughput
make experiment-batch-latency    # batch redaction latency
make experiment-audit            # provenance audit efficiency
make experiment-e2e              # full pipeline under concurrent load
```

Results are written to `results/` (CSV + JSON) with plots in `results/plots/`.

## Project Structure

```
VeRedact/
├── ZK-Redact Scheme/     # Formal scheme specification (paper)
├── cmd/                   # Component entrypoints
├── pkg/                   # Shared libraries (proto, ch, zk, crypto, merkle)
├── internal/              # Component internals (gateway, pvl, redactor, pai)
├── network/               # Blockchain network config + chaincode
├── baselines/             # Baseline scheme implementations
├── config/                # Shared experiment and scheme configurations
├── experiments/           # Experiment scripts
├── results/               # Output (generated)
├── build/                 # Build artifacts (generated)
├── Makefile
└── README.md
```

## References

See [`ZK-Redact Scheme/ZK-Redact.pdf`](ZK-Redact%20Scheme/ZK-Redact.pdf) for the full formal specification.

## License

TBD