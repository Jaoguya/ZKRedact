# Experiment Specification

Evaluation plan for **ZK-Redact** against three re-implemented baselines.

This document defines *what* is measured, *against what*, and *under which shared
conditions*. Parameter **values** live in `config/experiment.yaml` — never here,
never in code.

---

## 0. Non-negotiable rules

These derive from [`SKILL.md`](../SKILL.md) and apply to every experiment and every
system under test, including the baselines.

| Rule | Meaning in practice |
|---|---|
| **Real execution only** | No simulated timings, no analytical cost models, no extrapolation. Every number is produced by running real code against a real permissioned network. |
| **No hardcoded parameters** | Shard counts, batch sizes, committee sizes, key lengths, tree arity, workload rates — all read from `config/experiment.yaml` at runtime. A literal in code is a defect. |
| **No magic numbers** | A value copied from a reference paper is invalid until its rationale is recorded in the config next to it. |
| **One dataset, one config** | All four systems consume the identical source dataset and the identical request trace, in the identical order. |
| **Reproducible** | Same config + same seed → same results. Every run records the resolved config and the seed into its output. |
| **Baselines are not strawmen** | Each baseline implements the authorization, redaction, and audit path its paper actually specifies. Every omission is recorded in that baseline's doc under *Deviations*. |

> A reported result that cannot be regenerated from `config/experiment.yaml` plus a
> seed does not go into the paper.

---

## 1. Shared experimental substrate

### 1.1 Source dataset

A single generated corpus, produced once from a seeded generator and reused by all
four systems:

- A set of transactions, each carrying a **core payload** (must remain immutable)
  and a **redactable payload** (the redaction target).
- A set of registered identities with attributes.
- A set of redaction policies.
- A **redaction request trace**: an ordered list of `(requester, target_tx, new_content, timestamp)`.

Sizes, distributions, and the seed come from config. The generator is deterministic.

### 1.2 Per-system materialization

The four systems do **not** share an on-chain format — they cannot, because each
scheme defines its own block/transaction structure:

| System | On-chain structure |
|---|---|
| ZK-Redact | CH per transaction + version counters + PAI commitments |
| Ref[10] EMT | Extended Merkle Tree: core branch + inserted branch |
| Ref[13] VRBC | CH per block + q-ary BAT vector commitments |
| Ref[22] Shen | Double-trapdoor CH + universal accumulator state and witnesses |

**Fairness contract:** each system ingests the *same source dataset* into its own
native representation before measurement begins. Ingestion is **not** timed.
Measurement starts only once every system holds an equivalent ledger derived from
identical source data.

### 1.3 Shared environment

Network topology (orgs, peers, consensus), hardware, and container resource limits
are fixed across all runs and recorded in config. Any run whose environment differs
is reported separately, never merged into a comparison table.

### 1.4 Request trace

All systems replay the **same trace in the same order**. The trace controls:

- arrival rate / concurrency level
- target distribution across transactions
- **conflict ratio** — the fraction of requests targeting an already-targeted transaction

Conflict ratio matters because ZK-Redact serializes same-transaction requests
(Phase 4, Step 1) while independent transactions proceed in parallel.

---

## 2. Experiment 1 — Verification Throughput

**Question.** How many redaction requests per second can each system *authorize*
before execution, and how does that scale with concurrent load?

### 2.1 Why it is named this way

Named after the operation **every** system performs — checking whether a request is
permitted — not after ZK-Redact's mechanism. Sharding is the swept variable, not the
experiment's identity. Naming it "Sharded ZKP Verification" would exclude every
baseline by definition.

### 2.2 What "verification" means per system

| System | Authorization work performed |
|---|---|
| **ZK-Redact** | Verify ZK proof `π_i`; shard assignment; intra-shard batching |
| **Ref[10]** | Distribute request to committee, collect Schnorr votes, verify aggregate `Σ` against threshold |
| **Ref[13]** | Verify trapdoor possession by the system manager |
| **Ref[22]** | Verify regulator key possession |

Ref[13] and Ref[22] perform substantially less work here. This is a **property of
those schemes**, not a handicap we impose — neither paper defines a per-request
authorization protocol. Recorded honestly, and paired with the capability matrix
(§5) so the reader can see what the speed is bought with.

### 2.3 Swept variables

- **Concurrent offered load** — primary axis
- **Shard count `N`** — ZK-Redact only; `N=1` is the sharding-disabled ablation
- **Verification batch `(B, Δ)`** — ZK-Redact only
- **Native batch verification** on/off — tests the Phase 3 claim that sharding
  provides parallelism *independently* of native batch-verification support

### 2.4 Metrics

| Metric | Notes |
|---|---|
| Authorized requests/sec | Primary |
| Latency p50 / p95 / p99 | Per request, end to end through authorization |
| Scaling efficiency | speedup ÷ `N` — measures how far from ideal parallelism |
| Saturation point | Load at which throughput stops rising |

### 2.5 Measurement boundary

Start: request admitted to the authorization component.
Stop: authorization decision final (accept or reject).

Excludes redaction execution and ledger commitment — those belong to Experiment 2.
Each baseline doc pins this boundary to specific algorithm steps in its own paper.

### 2.6 Expected shape

At low concurrency the trapdoor-based baselines lead — a key check is cheaper than a
proof verification. As concurrency rises, their single authorizing entity becomes a
serialization point while ZK-Redact distributes across shards. The curves are
expected to cross. **Reporting both regimes is mandatory**; reporting only the
high-load regime would be selection.

### 2.7 Required ablations

| Configuration | Isolates |
|---|---|
| `N=1`, batching off | Baseline cost of a single verification |
| `N>1`, batching off | Effect of sharding alone |
| `N=1`, batching on | Effect of batching alone |
| `N>1`, batching on | Combined |

---

## 3. Experiment 2 — Redaction Throughput

**Question.** How much per-request blockchain cost does batch-oriented processing
amortize, where does the benefit stop, and what does it cost in request staleness?

### 3.1 Why it is not named "Batch Redaction"

No baseline batches. Naming the experiment after batching would make it a
measurement of ZK-Redact's own feature with no participants. Named after the shared
operation instead, the baselines become the natural `B_R = 1` point on the same
axis.

### 3.2 What is and is not amortized

Phase 4 is explicit ([ZK-Redact.md:645-647](../Reference/ZK-Redact%20Scheme/ZK-Redact.md#L645-L647)):
CH adaptation is per-request; batching amortizes chaincode, validation, commitment,
and ledger processing.

| Component | Scales how | Batching helps? |
|---|---|---|
| `CH.Adapt` per request | Linear in batch size | **No** — this is the floor |
| Chaincode invocation | ~Constant per batch | Yes |
| `Fresh_i` revalidation | Per request, one round | Partially |
| Batch commitment `C_B^(e)` | One per batch | Yes |
| Ledger write / consensus | ~Constant per batch | Yes |

**These must be measured separately.** A single aggregate timing cannot answer
"which part improved," and would allow the paper to imply batching accelerates the
redaction cryptography. It does not, and the scheme never claims it does.

### 3.3 Swept variables

- **Redaction batch size `B_R`**, including `B_R = 1`
- **Batch wait bound `Δ_R`**
- **Conflict ratio** — same-transaction requests must serialize
- **Concurrent offered load**

### 3.4 Metrics

| # | Metric | Expected shape |
|---|---|---|
| 1 | `CH.Adapt` total time | Linear in `B_R` — the irreducible floor |
| 2 | Blockchain-side time per batch | Roughly flat in `B_R` |
| 3 | **Cost per request** = (1+2) ÷ successful requests | Steep drop, then flattens toward floor |
| 4 | Redactions/sec | Rises, then saturates |
| 5 | **Stale-exclusion rate** (`Fresh_i = 0`) | Rises with `B_R` and `Δ_R` |

Metric 5 is the honest cost of batching: longer waits mean more requests fail
freshness revalidation and must be re-authorized.

### 3.5 Measurement boundary

Start: request enters the redaction execution stage already authorized.
Stop: state transition committed and provenance record generated.

Authorization is excluded — that was Experiment 1. Double-counting it would
overstate the batching benefit.

### 3.6 Target result

An **optimal `B_R`**: the point where marginal amortization gain equals marginal
staleness loss. This is a concrete engineering recommendation. Ref[13] proposes
batched redaction ("delayed redaction",
[Ref[13].md:378](../Reference/Ref%5B13%5D/Ref%5B13%5D.md#L378)) but never measures
it, so this fills a genuine gap in the literature.

---

## 4. Experiment 3 — Provenance Retrieval and Audit Cost

**Question.** Does audit cost scale with the target transaction's redaction history
rather than with total ledger size?

### 4.1 Swept variables

- **Ledger size**, with history depth held fixed — the primary plot
- **History depth** (redactions per transaction), with ledger size held fixed
- **Number of anchored PAI states**

### 4.2 Metrics

| Metric | Notes |
|---|---|
| Retrieval latency | Fetching the provenance history and evidence |
| Verification time | Auditor-side independent verification |
| Proof / evidence size | Bytes transferred |
| Auditor authorization cost | Signature verify + freshness + `AuditAuth`, reported **separately** as a constant adder |

Auditor authorization is isolated because no prior scheme includes it — folding it
into the total would make ZK-Redact look worse for providing a capability the
baselines lack entirely.

### 4.3 What each baseline does

| System | Audit path |
|---|---|
| **ZK-Redact** | Authenticated retrieval of one transaction's history + Merkle verification against anchored state |
| **Ref[13]** | BAT challenge-response audit — the real competitor |
| **Ref[10]** | Block query + EMT recomputation to locate and validate redaction transactions |
| **Ref[22]** | `ValChain` — collect current versions of all blocks and compare against accumulator state |

### 4.4 Expected shape

The headline plot holds history depth constant and grows the ledger. ZK-Redact
should be **flat**. Ref[13] should be sublinear. Ref[10] and Ref[22] should climb
roughly linearly, since both must traverse the chain.

---

## 5. Capability matrix

Numeric tables alone would misrepresent Experiment 1, where two baselines are fast
because they perform less work. Every performance table is published alongside this
matrix. Both Ref[10] (Table I) and Ref[13] (Table 1) use the same convention.

| Capability | ZK-Redact | Ref[10] | Ref[13] | Ref[22] |
|---|---|---|---|---|
| Privacy-preserving authorization | ✓ | ✗ | ✗ | ✗ |
| Policy-bound redaction | ✓ | partial | ✗ | ✗ |
| Decentralized authorization | ✓ | ✓ | ✗ | ✗ |
| Parallel verification | ✓ | ✗ | ✗ | ✗ |
| Batch-oriented redaction | ✓ | ✗ | proposed, unmeasured | delete-set only |
| Per-transaction provenance history | ✓ | ✗ | ✗ | ✗ |
| Audit independent of ledger size | ✓ | ✗ | sublinear | ✗ |
| State-freshness revalidation | ✓ | ✗ | ✗ | ✗ |

**PCH** (Derler et al., NDSS 2019 — cited as [22] in Ref[10], [17] in Ref[13], [13]
in Ref[22]) is qualitatively compared in this matrix only. It is not implemented:
its CP-ABE authorization targets a different trust model, and none of the three
reference papers implement or measure it either. Recorded here so the omission is
explicit rather than silent.

---

## 6. Output

Per `SKILL.md`, results are written to `results/` as CSV and JSON, with plots in
`results/plots/`.

Every result file records:

- the fully resolved config (all parameters, post-defaults)
- the RNG seed
- the source dataset identifier
- git commit of the code that produced it
- environment fingerprint (OS, CPU, container limits, network topology)

A result missing any of these is not publishable under the reproducibility rule.

---

## 7. Baseline specifications

Implementation scope, measurement boundaries, parameters, and deviations for each
baseline:

- [`baselines/ref10-emt.md`](baselines/ref10-emt.md)
- [`baselines/ref13-vrbc.md`](baselines/ref13-vrbc.md)
- [`baselines/ref22-shen.md`](baselines/ref22-shen.md)
