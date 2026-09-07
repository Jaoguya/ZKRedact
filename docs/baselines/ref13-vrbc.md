# Baseline: Ref[13] — VRBC

**Paper.** G. Tian, J. Wei, M. Kutyłowski, W. Susilo, X. Huang, X. Chen, *"VRBC: A
Verifiable Redactable Blockchain With Efficient Query and Integrity Auditing,"*
IEEE Transactions on Computers, vol. 72, no. 7, 2023. DOI 10.1109/TC.2022.3230900
Source: [`Reference/Ref[13]/`](../../Reference/Ref%5B13%5D/)

**Role in evaluation.**

| Experiment | Role |
|---|---|
| 1 — Verification Throughput | Lower bound only — no per-request authorization protocol exists |
| 2 — Redaction Throughput | Fully comparable, per-request |
| 3 — Provenance Audit | ⭐ **Primary competitor.** The only baseline with a real audit protocol. |

---

## 1. What we implement

### 1.1 Block structure (§2.2)

`B_i = (h_{i-1}, ch_i, m_i, Y_i, r_i, ctr_i)` where:

- `ch_i = CH(h_{i-1}, m_i, Y_i, r_i)` (Eq. 1)
- `m_i` is the Merkle root over the block's transactions
- `h_i = H(ch_i, ctr_i)`

### 1.2 Blockchain Authentication Tree (BAT)

A `q`-ary spanning tree binding appended blocks via aggregatable vector commitments
(an adapted Pointproofs construction):

`C_i = Commit(m_i, C_{child…}; γ_i)` (Eq. 2)

The verification value `γ_i` permits appending a block without recomputing the whole
tree.

### 1.3 Block Append (§3.2.2)

Generate the chameleon hash, compute the node commitment, publish family-node
commitments, verify correctness and validity of the new block.

### 1.4 Block Redaction (§3.2.3)

Compute a CH collision for the target block, then update node commitments along the
path from the redacted node to the root. Paper cost: `2H + (ℓ+1)(H + Exp)`.

### 1.5 Block Query (§3.2.4) — Experiment 3

Three-move protocol:

- **Chal** — verifier requests block `s` with a validity proof
- **Proof** — prover runs Algorithm 2, returns `(π_s, μ_s)` plus verification metadata
- **Verify** — pairing check (Eq. 11), then chameleon-hash correctness check (Eq. 12)

### 1.6 Blockchain Auditing (§3.2.5) — Experiment 3

- **Chal** — auditor issues `Chal = (z, φ₁, φ₂)`
- **Proof** — prover runs Algorithm 3, produces `(π̂, μ̂)`
- **Verify** — aggregate pairing check, then Eq. 12 over all challenged blocks

### 1.7 Optimized auditing (§4.1)

PRF `f₁` selects `z` leaf nodes so challenged blocks fall in a minimal path union,
minimising the number of path nodes. **Implemented** — it is the configuration under
which the paper reports its results, so omitting it would understate the baseline.

---

## 2. Measurement boundaries

### Experiment 1 — Verification Throughput

| | |
|---|---|
| **Start** | Redaction request admitted |
| **Stop** | Trapdoor possession verified, redaction permitted |

> **This scheme has no per-request authorization protocol.** Redaction authority rests
> with the system manager, who holds the trapdoor. There is no policy evaluation, no
> requester privacy, no per-request permission decision to measure — only a key-possession
> check.
>
> We measure exactly what the scheme specifies and **do not** synthesise an
> authorization protocol on its behalf. Inventing one would be fabricating a result.
> The scheme will therefore appear very fast in Experiment 1 at low load; the
> capability matrix in `experiments.md` §5 carries the interpretation.
>
> Under concurrent load, the single trapdoor holder is a genuine serialization point,
> and that **is** a real, measurable property of the scheme — not an artefact.

### Experiment 2 — Redaction Throughput

| | |
|---|---|
| **Start** | Authorized redaction enters execution |
| **Stop** | CH collision computed and all path commitments from redacted node to root updated |

Per-request by construction — contributes the `B_R = 1` point.

> **Delayed redaction (§4.1) is deliberately NOT implemented.** The paper proposes
> batching redactions within a BAT sub-region but never measures it, and specifies no
> batch-formation policy, no wait bound, and no conflict handling. Implementing it
> would require us to invent those, and we would then be benchmarking our own design
> while attributing it to Ref[13]. Recorded in `experiments.md` §5 as
> *"proposed, unmeasured"* — which is exactly the gap Experiment 2 fills.

### Experiment 3 — Provenance Audit

Two separate measurements, since the scheme provides two distinct protocols:

**Block query:**

| | |
|---|---|
| **Start** | Auditor issues Chal |
| **Stop** | Both Eq. 11 and Eq. 12 verified |
| **Reported** | Prover time, verifier time, transferred bytes |

**Blockchain audit:**

| | |
|---|---|
| **Start** | Auditor issues `Chal = (z, φ₁, φ₂)` |
| **Stop** | Aggregate pairing check and Eq. 12 complete over all challenged blocks |
| **Reported** | Prover time, verifier time, transferred bytes |

> **Semantic gap to record in the paper.** VRBC audits *ledger integrity* — that
> blocks have not been tampered with. ZK-Redact retrieves *a transaction's redaction
> history* — who changed what, when, under which authorization. These are related but
> not identical questions. VRBC has no per-transaction provenance history to retrieve.
>
> The comparison is therefore on **cost scaling behaviour with respect to ledger
> size**, which both schemes answer, and must be stated as such. Presenting it as
> feature-for-feature equivalence would be misleading.

---

## 3. Parameters

All from `config/experiment.yaml`. **None hardcoded.**

| Parameter | Meaning | Rationale requirement |
|---|---|---|
| `bat_arity_q` | BAT fan-out | Paper uses 2, 5, 10. Redaction and audit costs *decrease* with `q` while append costs *increase* — the choice must be justified, and ideally swept, since a single value can flatter or penalise the baseline |
| `vector_dimension_N` | Commitment dimension | Paper uses 3, 6, 11. Affects setup and proof-generation cost |
| `challenged_blocks_z` | Audit sample size | See note below |
| `pairing_curve` | Pairing-friendly curve | Must match the security level of all other systems |

> **On `challenged_blocks_z`.** The paper's 300 and 460 derive from Ateniese et al.'s
> PDP analysis: at 1% block corruption, 300 challenged blocks give 95% detection
> precision and 460 give 99% ([Ref[13].md:639](../../Reference/Ref%5B13%5D/Ref%5B13%5D.md#L639)).
> That derivation is sound and **may be reused — provided the derivation itself is
> recorded in the config, not just the number**. Under the no-magic-numbers rule, the
> reasoning is what transfers, not the digit.

> **On `optimized_auditing`, and what it does not buy.** §4.1's mechanism is f1's
> range, `(q(1-q^{l-1})/(1-q), q(1-q^l)/(1-q)]`, which for `q=5, l=4` is `(155, 780]`
> — exactly the leaf-level indices. So the optimisation restricts challenges to
> **leaves**. It does **not** produce a smaller path union than uniform sampling:
> measured at `q=5` over 400 blocks, optimised gives a union of 56 against uniform's
> 55, because the deepest level already holds 245 of 400 blocks and a uniform sample
> draws some shallow ones whose paths are shorter. What it buys is full-depth
> coverage per challenge and a union bounded by depth. **Presenting the optimised arm
> as the cheaper configuration would be wrong** — it is enabled because it is the
> configuration the paper measures. Pinned by
> `TestOptimizedSelectionChallengesLeavesOnly`.

> **On `bat_arity_q`.** Because `q` trades append cost against redaction and audit
> cost in opposite directions, fixing one value would let the choice determine the
> outcome. Sweep it, or justify a single value explicitly.

---

## 4. Dependencies

| Dependency | Purpose | Notes |
|---|---|---|
| Pairing-friendly elliptic curve library | Eq. 11 / audit pairing checks | **Beyond base toolchain — flagged per SKILL.md** |
| Vector commitment (Pointproofs-style) | BAT node commitments | No standard library implementation; must be built |
| Chameleon hash | Block-level redaction | Shared with the project's CH library where security levels match |

> The pairing library and vector commitment are the **main implementation cost** of
> this baseline. Both must be recorded in the component README and flagged in review.

---

## 5. What we do NOT implement, and why

| Omitted | Reason |
|---|---|
| Transaction-level VRBC (§4.2) | The paper describes it but omits proof generation/verification details *"due to space limitations"*. Implementing it would require inventing the missing construction. The block-level scheme is the one the paper actually measures. |
| Permissionless VRBC (§4.3) | Our setting is permissioned. The MPC-based committee variant is out of scope. |
| Delayed redaction (§4.1) | See §2. Proposed but unspecified and unmeasured. |
| Ethereum gas measurements | Their on-chain costs were measured on Ropsten (now deprecated). We measure on our shared Fabric network. |
| Comparison against Ethereum / AMVA17 | Ref[13]'s own internal baselines, not ours. |

**Optimized auditing (§4.1) IS implemented** — it is the configuration under which
the paper reports results, and omitting it would weaken the baseline unfairly.

---

## 6. Deviations from the original

| Deviation | Justification | Effect on results |
|---|---|---|
| Fabric instead of Python + Ropsten | One shared environment for all systems (`SKILL.md` fair-comparison rule) | Absolute numbers differ substantially from published; relative comparison valid |
| Go/Rust instead of Python + GMP/PBC | Matches project toolchain; Python timings are not comparable to compiled code | **Favours Ref[13]** — likely faster than its published figures |
| **Measured OFF-CHAIN, in-process. No network I/O.** Ref[13] opens no gRPC connection and touches no Fabric peer; `internal/schemes/ref13` imports no transport library | **This matches the paper's own measurement boundary, and is not a shortcut.** Ref[13] reports two separate quantities and never one aggregate: on-chain cost as Ethereum gas on Ropsten, and *"the off-chain computation costs of all compared schemes on CentOS 8.3.2011"* ([Ref[13].md:574](../../Reference/Ref%5B13%5D/Ref%5B13%5D.md#L574)). Figs. 5, 7 and 8 are each captioned "off-chain computation costs". The protocol is off-chain by construction at exactly these points: query and audit metadata reach the verifier *"via a secure off-chain channel"*, with only the proof published on-chain ([Ref[13].md:339](../../Reference/Ref%5B13%5D/Ref%5B13%5D.md#L339), [:358](../../Reference/Ref%5B13%5D/Ref%5B13%5D.md#L358)). Charging Ref[13] a Fabric round trip for BAT path recomputation would price an operation its design performs at the verifier | **Neutral between schemes, and now stated rather than implied.** `CryptoTime` is off-chain for all four systems, so no scheme's cryptography is inflated by transport. `LedgerTime` is in-process for Ref[13], Ref[22] and ZK-Redact, and real only for Ref[10]'s voting round — see the shared measurement boundary below |
| **The SRS omits `g1^{a^{N+1}}`.** Eq. 3 as printed gives the second parameter vector as `(g1^{a^{N+1}}, …, g1^{a^{2N}})`; `pkg/vc` publishes `[N+2, 2N]` instead | The paper's own soundness proof requires the omission. Eq. 20 reduces a forgery to computing `g1^{a^{N+1}(mu' - mu)}` and calls that an `l`-wBDHE solution — if `pp` contained that element the reduction would be vacuous, since a forger could shift any valid opening to any claimed value by scaling it directly. Pointproofs (Gorbunov et al., CCS 2020) omits it for the same reason. Read as a transcription slip in Eq. 3, not a design choice | **None on cost** — the prover never needs it (for `j != i` the exponent `N+1-i+j` equals `N+1` only when `j = i`), so no operation gets cheaper or dearer. It is a **soundness** correction: following Eq. 3 literally yields a commitment that passes every round-trip test and is trivially forgeable. Pinned by `TestForgeryNeedsTheOmittedParameter`, which performs the forgery with the withheld element and then asserts the element is absent from `pp` |
| **The ephemeral component is derived from the message at HASH time, not only at adapt time.** `pkg/ch` computes `y_s = H2(x ‖ m_s)` and `Y_s = y_s·P` when a block is hashed, stores `Y_s` with the block, and recomputes it from `m_s` when adapting; `EphemeralAdapt` no longer advances any key-wide component | The paper is explicit for redaction and ambiguous for block creation, and the two readings are not compatible. §3.2.3 stores the point per block — `B_s = (ch_s, m_s, Y_s, r_s)` — Eq. 8 computes the block's trapdoor from `y_s`, and Eq. 9 derives the replacement as `y'_s = H2(x, m'_s)`, all indexed by the block `s`. Block generation is described only as done "with (X, Y)" ([Ref[13].md:402](../../Reference/Ref%5B13%5D/Ref%5B13%5D.md#L402), in the multi-party variant), which reads as one key-wide `Y`. Taken literally that is self-inconsistent: after any redaction the block's component IS `H2(x, m_s)` by Eq. 9, so deriving it the same way at creation is the only rule that makes Eq. 8 hold for a block redacted zero times and once alike. Implemented per-message throughout | **Corrects a defect, no cost claim.** The previous key-wide reading let exactly ONE redaction succeed per Setup: the first adapt moved the key's `Y`, and every other block still carried the old point, so `EphemeralAdapt` refused it. Measured before the fix — Exp 2 recorded `succeeded: 1, failed: 19` on 20 redactions and reported a full results file built from one real redaction; Exp 3 could not build a history at all and aborted. After: 0 failed of 360. Cost per hash rises by one hash-to-scalar and one scalar multiplication, which is work the construction's own rule requires. Pinned by `TestRedactTwoDifferentBlocks`, `TestEphemeralAdaptIndependentBlocks` and `TestEphemeralAdaptRotatesY` |
| Trapdoor `alpha` is sampled by `vc.Setup` and discarded, rather than produced by a ceremony | Same argument as `accumulator.GenerateUntrusted` for Ref[22]'s RSA modulus: the evaluation measures COST, and every operation's cost depends on `N` and the group, not on who knew `alpha` | **None on cost.** The security argument would not survive this shortcut; the timing measurement is unchanged by it |

> **Shared measurement boundary.** `CryptoTime` is measured off-chain and
> in-process for every system; `LedgerTime` is reported separately and is real
> Fabric cost only for Ref[10]'s voting round. Stated in full, with each paper's
> own methodology citation, in
> [`docs/experiments.md` §1.3.1](../experiments.md#131-on-chain--off-chain-measurement-boundary).

> Our Ref[13] numbers are **not** comparable to the paper's published figures and
> must never be presented as such. Language reimplementation alone can shift timings
> by an order of magnitude — which is precisely why `SKILL.md` requires one shared
> environment rather than citing across papers.

---

## 7. Fidelity checklist

- [x] Vector commitments are real cryptographic commitments, not hash placeholders — `pkg/vc`, checked against directly evaluated exponents rather than against itself
- [x] Pairing checks (Eq. 11) are actually computed and can actually fail — `AggregateVerify`, with the forgery tests behind it
- [x] Eq. 12 chameleon-hash correctness check is performed — `verify.go`, and `TestEq12CatchesWhatEq11Cannot` shows Eq. 11 alone accepts what Eq. 12 rejects
- [x] BAT path updates touch every node from redacted block to root — `refreshPath`, pinned by `TestRedactionChangesTheRoot`
- [x] Audit challenge is genuinely randomised per round via the specified PRF — `TestAuditIsADifferentChallengeEachRound`
- [x] Optimized path-union selection (§4.1) is active — and see the note above on what it does and does not buy
- [x] A tampered block is actually **detected** — `TestAuditDetectsATamperedBlock`
- [x] Trapdoor authorization check is real, not stubbed to `return true` — `HasTrapdoor`, and `TestAuthorizeDeniesAnUnknownTarget` shows it can deny
- [x] No parameter appears as a literal anywhere in the implementation — audited; the evidence-size accounting measures encodings from the types in use rather than writing 48 and 32 down, since both curves are config fields

> The negative test matters most. A commitment scheme that never rejects anything
> would look extremely fast and be entirely worthless. Every verification path needs a
> test proving it fails on invalid input.
