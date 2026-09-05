# TASK — handoff

Evaluation framework for **ZK-Redact**, comparing it against three
re-implemented baselines on one shared Hyperledger Fabric harness.

**Branch:** `docs/experiment-design` (7 commits, not merged to `main`)
**Code:** ~6,700 lines Go across 24 files
**Compiled:** ❌ never — the authoring machine had no Go toolchain

---

## ⚠️ Read this first

Three rules come from [`SKILL.md`](SKILL.md) and are not negotiable. Most of the
code exists to enforce them.

1. **No fake, no simulation.** Every number comes from real code running against
   a real network. No analytical models, no extrapolation, no placeholder
   timings.
2. **No hardcoded parameters.** Everything lives in
   [`config/experiment.yaml`](config/experiment.yaml). A numeric literal in code
   is a defect.
3. **No magic numbers.** A value copied from a reference paper is invalid until
   its rationale is recorded beside it. The *derivation* transfers, never the
   digit.

**The failure mode this project guards against is silent.** A baseline given a
cheaper primitive than its paper specifies does not crash, does not fail a test,
and does not look wrong in a plot. It just runs faster than its own design
permits, and the comparison becomes worthless with nothing indicating why.

Several guards already exist for exactly this. **Do not remove them to make
something pass.** If a guard fires, it is telling you something true.

---

## Start here

```bash
# On the target host (Ubuntu 22.04, c6i.8xlarge)
./scripts/setup-ec2.sh          # installs Go, Docker, Fabric 2.5.9, protoc
source ~/.bashrc

go mod tidy
make build                      # FIRST REAL COMPILE — expect fixes here
make test                       # pkg/ch and pkg/merkle have real tests
make validate-config            # first real run of the config gate
```

> **Task 0 is `make build`.** Nothing in this repo has ever been through a
> compiler. Expect import ordering, unused variables, and similar. The structure
> was checked by hand — delimiter balance, interface conformance across all four
> schemes, every cross-package struct literal against its declaration — but that
> is not a compiler.

---

## What the evaluation is

Three experiments, each named after **the operation every system performs**,
with ZK-Redact's mechanism as the swept variable. Naming them after our own
mechanism (`batch-redaction`, `sharded-zkp`) would exclude the baselines by
definition — they do not batch and have no shards.

| Exp | Question | Swept | Real competitor |
|---|---|---|---|
| 1 Verification Throughput | authorizations/sec under concurrent load | shards `N` 1→64 | **Ref[10]** |
| 2 Redaction Throughput | how much blockchain cost batching amortises, and its staleness price | batch `B_R` 1→64 | all three |
| 3 Provenance Audit Cost | does audit cost track history depth, not ledger size | ledger 1k→10k | **Ref[13]** |

Full spec: [`docs/experiments.md`](docs/experiments.md).

**Exp 1 will show Ref[13] and Ref[22] beating ZK-Redact at low concurrency.**
That is correct and expected — their "authorization" is a single key-possession
check, because neither paper defines a per-request authorization protocol. Do
not invent one for them; that would be fabricating a result. The capability
matrix (generated from code, see `Capabilities()`) carries the interpretation,
and the crossover under load is the actual finding.

---

## Done ✅

| Package | What it is |
|---|---|
| `pkg/scheme` | The interface all four systems implement — the fairness contract |
| `pkg/config` | Single config schema, shared by validator and runtime |
| `pkg/crypto` | Security-level tables (curves, RSA, proof systems) |
| `pkg/metrics` | Exact percentiles, throughput |
| `pkg/workload` | Deterministic dataset + trace generation |
| `pkg/results` | Output with reproducibility metadata |
| `pkg/ch` | **3 chameleon hash constructions, tested** |
| `pkg/merkle` | Merkle tree + proofs, tested |
| `experiments/exp1,2,3` | All three runners |
| `cmd/validate-config` | Config gate |
| `cmd/run-experiment` | Entry point |

Scheme files in `internal/schemes/*` have real structure and real parameter
validation, but the cryptography returns `ErrNotImplemented`.

---

## Remaining tasks, in order

### 0. Compile ⬅️ **start here**
`make build`, then `make test`. Fix whatever the compiler says. Nothing else is
verifiable until this passes.

### 1. Schnorr signatures → `pkg/crypto`
Needed by Ref[10] voting (Algorithm 4). Curve comes from
`security.signature_curve` (P-256). Follow the style of `pkg/ch`: real code,
table tests, and a negative test proving verification actually rejects.

### 2. Ref[10] EMT — the first real numbers 🎯
Spec: [`docs/baselines/ref10-emt.md`](docs/baselines/ref10-emt.md)

Uses **no chameleon hash** — only Merkle (done) plus Schnorr. Highest value per
unit of effort: it is the Exp 1 competitor, already on Fabric, and finishing it
proves the whole harness works end to end even while the other three are stubs.

| Algorithm | What |
|---|---|
| 1 | EMT verification, `H_tx = H(H_c ‖ H_w)` |
| 2 | CA validation, policy `P_C` |
| 3 | Committee selection `RS_SHA256`, voting |
| 4 | Schnorr vote signatures |
| 5 | Local redaction |

Measurement boundary is pinned in the spec §2 — read it before timing anything.

### 3. Fabric network + chaincode → `network/`
4 orgs × 2 peers + 3 Raft orderers, per config. Votes must travel over the real
network; short-circuiting them to in-process calls removes the cost that
distinguishes Ref[10] from a trapdoor check.

### 4. ZK circuits → `pkg/zk`
Groth16 over BLS12-381 via **gnark**. Circuit encodes the Phase 2 statement:
requester satisfies the policy, state version matches, without revealing
attributes.

After building, record `constraint_count` and `public_input_count` into
`config/experiment.yaml` — they are the only remaining nulls, and they are
measurements, not choices.

### 5. ZK-Redact internals
| Package | Phase |
|---|---|
| `internal/pvl` | 3 — sharding + batching. **Core of Exp 1** |
| `internal/redactor` | 4 — batch execution. **Core of Exp 2** |
| `internal/pai` | 5, 6 — provenance + audit. **Core of Exp 3** |
| `internal/gateway` | 2 — request auth, dedup |

### 6. Ref[22] Shen
Double-trapdoor CH is **done** (`pkg/ch/doubletrapdoor.go`). Remaining: the
trapdoorless universal accumulator (RSA-3072) and Algorithms 1–9.

`ValChain` must genuinely traverse every block — its linear cost is what Exp 3
compares against. Do not add a cache.

### 7. Ref[13] VRBC — hardest remaining
Ephemeral-trapdoor CH is **done** (`pkg/ch/ephemeral.go`). Remaining: the q-ary
BAT with Pointproofs-style vector commitments.

> **Highest-risk component in the project.** No standard Go implementation
> exists; it must be written over BLS12-381 and audited against §3.2.2. Budget
> accordingly.

### 8. `cmd/plot`
Reads `results/*.json`. Headline plots:
- Exp 1: throughput vs concurrency, all four, showing the crossover
- Exp 2: cost per request vs `B_R`, split into crypto floor and amortised part
- Exp 3: cost vs ledger size at fixed history depth — ZK-Redact flat, others climbing

### 9. Pilot run
`make pilot` builds the dataset and trace without executing. Then use a short
real run to resolve the values that cannot be guessed:
- `meta.repetitions` from measured variance
- upper bounds of the batch and concurrency sweeps — where the curve flattens
  **is** the result

### 10. Full runs + write-up

---

## Findings already made — do not re-derive

### The three schemes use three different chameleon hashes
This was nearly a silent error. All three are now implemented and enforced by
`ch.Required` / `ch.CheckRequired`.

| Scheme | Construction | Why it matters |
|---|---|---|
| ZK-Redact | classic (spec is generic) | — |
| Ref[10] | **none** | uses pruning + voting |
| Ref[13] | ephemeral trapdoor, Eq. 5 | derives a fresh key component per redaction |
| Ref[22] | double trapdoor, §II-A | key-exposure free; Ref[22] names the classic scheme as what it replaces |

Exp 2 reports `CryptoTime` as a headline metric, so a cheaper construction =
an invisible advantage.

### BN254 is not 128-bit
Kim–Barbulescu exTNFS (2016) reduced it to ~100–110 bits. Much ZK tooling still
defaults to it. `crypto.RequirePairingCurve` rejects it against the 128-bit
target. **BLS12-381** is mandated.

### Ref[10] includes consensus its paper excluded
The paper states redaction consensus was omitted
([Ref[10].md:466](Reference/Ref%5B10%5D/Ref%5B10%5D.md#L466)). We include it, because
that cost is exactly what ZK-Redact's batching amortises. Consequence: our
Ref[10] numbers are **not comparable** to the paper's published figures.

### Published numbers must never share a table with ours
Different languages, hardware, platforms. Ref[22] especially — it disabled PoW
and excluded communication on a 2 GB VM. Enforced by
`output.allow_published_numbers_in_tables: false`.

### Instance sized from a CPU budget, not a core count
Fabric peers, orderers and the load generator take ~12 of 32 vCPUs, leaving ~20
for the system under test. On 16 vCPUs only ~4 would remain, so Exp 1 would
saturate at 4 and read as a scaling limit of sharding when it is really CPU
contention.

Full audit with paper citations: [`docs/paper-conformance.md`](docs/paper-conformance.md)

---

## Guards in the code — leave them in

| Guard | Where | Catches |
|---|---|---|
| Scheme granting every request, denying none → fail | `exp1` | a stub that always approves, which benchmarks beautifully |
| `CryptoTime == 0` with successful redactions → fail | `exp2` | cost decomposition not instrumented |
| Claims `LedgerIndependentAudit` but traverses the ledger → fail | `exp3` | a scheme contradicting its own capability declaration |
| Non-batching scheme swept over batch sizes → refused | `exp2` | fabricating a curve the scheme cannot produce |
| Ref[10] threshold not a real majority → `Setup` fails | `ref10` | an undersized committee making the main competitor look fast |
| Ref[13] corruption rate ≠ 0.01 → `Setup` fails | `ref13` | `challenged_blocks` silently losing its 95%/99% meaning |
| Ref[22] accumulator < 3072 bits → `Setup` fails | `ref22` | a baseline benchmarked below the shared security level |
| Curve below `target_bits` → validation error | `validate-config` | the BN254 trap |
| `delete_set_sizes` ≠ `redaction_batch.sizes` → error | `validate-config` | two Exp 2 curves on incomparable axes |
| Shard sweep not exceeding vCPUs → error | `validate-config` | saturation knee outside the plot |

Sweeps that find no saturation point or no optimal batch size return **0**,
meaning *extend the sweep* — not *no optimum exists*.

---

## Open questions

| # | Question | Notes |
|---|---|---|
| 1 | Dataset: synthetic or calibrated to real data? | Currently synthetic, fixed 256B/512B payloads. Content does not affect any measured cost — only size does. Real sizes have a distribution; ours does not. Discussed but not decided. |
| 2 | Network size fixed or swept? | 4 orgs × 2 peers assumes network scaling is not a claimed result. |
| 3 | Payload sizes | Deliberately not Ref[13]'s 660 B, which measured public Ethereum, not a permissioned ledger. If the target application has known sizes, use and cite those. |

Three `[CONFIRM]` markers in the config track these: `grep -n CONFIRM config/experiment.yaml`

---

## Layout

```
config/experiment.yaml   all parameters, each marked DERIVED/METHOD/PROPOSED/CONFIRM
docs/
  experiments.md         experiment spec + fairness contract
  paper-conformance.md   every claim vs its paper citation
  baselines/*.md         per-baseline scope, timing boundaries, deviations
pkg/                     shared libraries
internal/schemes/        the four systems under test
experiments/             one runner per experiment
cmd/                     validate-config, run-experiment
scripts/setup-ec2.sh     host provisioning (install | verify)
```

## Commands

```bash
make build                                  # compile everything
make test                                   # vet + tests
make validate-config                        # config gate
make pilot                                  # dataset + trace, no execution
make experiment-verification-throughput     # Exp 1
make experiment-redaction-throughput        # Exp 2
make experiment-provenance-audit            # Exp 3
make experiments                            # all three
```

Every experiment target depends on `validate-config`. That is deliberate:
validation you have to remember is validation that gets skipped.

---

## If you change something

- New component → add its row to `docs/paper-conformance.md` with the paper
  citation and its test.
- Departure from a paper → record it in that baseline's deviation list, with the
  reason **and which system it favours**.
- Parameter that changes a scheme's cost profile → add a `Setup` check that
  refuses the wrong value. A comment is not enough.

Deviations are fine and sometimes necessary. Undocumented ones are not.
