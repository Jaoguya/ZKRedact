# Baseline: Ref[10] — EMT

**Paper.** Z. Wu, L. Wang, X. Zhang, X. Feng, *"EMT: Extended Merkle Tree Structure
for Inserted Data Redaction in Permissioned Blockchain,"* IEEE TNSE, 2025.
DOI 10.1109/TNSE.2025.3555979
Source: [`Reference/Ref[10]/`](../../Reference/Ref%5B10%5D/)

**Role in evaluation.**

| Experiment | Role |
|---|---|
| 1 — Verification Throughput | ⭐ **Primary competitor.** The only baseline with a real per-request authorization protocol. |
| 2 — Redaction Throughput | Fully comparable, per-request |
| 3 — Provenance Audit | Fully comparable |

**Why this is the most important baseline.** It runs on Hyperledger Fabric with Raft
— the same platform as ZK-Redact. Platform-induced differences are therefore
minimal, making it the fairest numeric comparison available.

---

## 1. What we implement

### 1.1 EMT structure (§IV-B)

Two independent Merkle branches per transaction:

- Core transaction data → `H_c`
- Inserted (redactable) data → `H_w`
- Transaction hash `H_tx = H(H_c ‖ H_w)`
- Tree: `EMT(⟨tx₁.H_c, tx₁.H_w, …, tx_m.H_c, tx_m.H_w⟩)` (Eq. 4)

Maps onto our shared dataset directly: the source corpus already separates core
payload from redactable payload (see `experiments.md` §1.1).

### 1.2 Algorithm 1 — EMT Verification

Recompute `H_c`, `H_w`, `H_tx`; compare against the block-recorded value. For
redacted transactions, confirm `H_c` unchanged, recompute `H_tx'` with the new
`H_w'`, then validate against the redaction transaction.

Used in Experiment 3.

### 1.3 Algorithm 2 — Redaction Request

CA verifies requester validity `V(n_i, C)`, then returns signed policy
`msg = {P_C, σ}` where:

- `P_C = {tx_id ∈ T_rdbl, n_i ⊨ A_r}` (Eq. 5)
- `T_rdbl = T_all \ (T_gen ∪ T_rdt ∪ T_con)` (Eq. 6)
- `A_r` over attribute set `{S, R, V}` (sender / receiver / validator)

### 1.4 Algorithm 3 — Redaction Smart Contract

- `init()` — select the authorized committee
  `RS_SHA256(addr(con_k), N_all, A_r) → N_auth` (Eq. 7)
- `query()` — expose `{req, σ}` to committee members
- `vote()` — collect votes within time window `t`, verify each signature, count
  approvals, compare against threshold, emit `tx_rdt = {req, Σ}`

### 1.5 Algorithm 4 — Redaction Voting

Each authorized node validates `{req, σ}` against `P_C`, decides, produces a
**Schnorr signature** `ξ_j`, submits to `con_k`.

### 1.6 Algorithm 5 — Local Redaction

Verify `tx_rdt` against `Σ`, confirm committee consensus, locate the block
containing `tx_id`, replace `tx_n.d_w` with a reference to `tx_rdt`, update the
local ledger.

---

## 2. Measurement boundaries

Timing points are pinned to specific algorithm steps so that all four systems are
timed over semantically equivalent work.

### Experiment 1 — Verification Throughput

| | |
|---|---|
| **Start** | Redaction request admitted (Algorithm 2, entry) |
| **Stop** | Threshold reached and aggregate `Σ` verified (Algorithm 3, `vote()` exit) |
| **Includes** | CA validation, committee selection, vote distribution, signature verification, aggregation |
| **Excludes** | Local redaction execution (that is Experiment 2) |

> **Note on the voting window.** `t` bounds how long `vote()` waits. If a fixed wall-clock
> window is used, Experiment 1 measures the window rather than the protocol. We therefore
> close the round as soon as the threshold is reached, and treat `t` strictly as a timeout.
> This is the *most favourable* correct reading for Ref[10] — the alternative would inflate
> its latency by a constant we chose. Recorded here because it materially affects the
> comparison.

### Experiment 2 — Redaction Throughput

| | |
|---|---|
| **Start** | `tx_rdt` broadcast to the network |
| **Stop** | Local redaction applied and ledger updated (Algorithm 5 complete) |

No batching exists in this scheme — it contributes the `B_R = 1` point.

### Experiment 3 — Provenance Audit

| | |
|---|---|
| **Start** | Query issued for a target transaction's redaction history |
| **Stop** | All located redaction transactions verified via Algorithm 1 |

Reconstructing a transaction's full history requires locating every `tx_rdt`
referencing it — there is no per-transaction provenance index. Cost is expected to
grow with ledger size.

---

## 3. Parameters

All read from `config/experiment.yaml`. **None may be hardcoded.**

| Parameter | Meaning | Rationale requirement |
|---|---|---|
| `committee_size` | \|`N_auth`\| | Must be justified relative to network size, not copied from the paper |
| `vote_threshold` | Approvals required | Must state the fault assumption it encodes |
| `vote_window_t` | Timeout bound | Must state how it was chosen; see the note above |
| `attribute_policy` | `A_r` expression | Paper's typical value is `{S ∨ R ∨ V}` — justify if adopted |
| `signature_curve` | Schnorr curve | Must match the security level used by the other systems |

> **Fairness requirement.** `signature_curve` must provide the same security level as
> the primitives used by ZK-Redact and the other baselines. Comparing a 128-bit
> baseline against a 256-bit ZK-Redact would invalidate every number.

---

## 4. Dependencies

Per `SKILL.md`, anything beyond the declared toolchain is recorded here.

| Dependency | Purpose | Notes |
|---|---|---|
| Schnorr signature over an elliptic curve | Committee voting (Algorithm 4) | Curve selected in config |
| Hyperledger Fabric chaincode runtime | Redaction smart contract | Already required by the project |
| SHA-256 | Committee selection `RS_SHA256` | Standard library |

No dependency beyond the base toolchain is anticipated. If the chosen Schnorr
implementation requires an external library, it is added here and flagged in review.

---

## 5. What we do NOT implement, and why

| Omitted | Reason |
|---|---|
| The paper's full UTXO transaction protocol (§VII-A) | We use the shared source dataset for all systems. Reimplementing their UTXO layer would make Ref[10] run a *different workload*, breaking the one-dataset rule. |
| Comparison against Pruning[5] / 2HashChain[8] / ChameleonHash[9] | Those are Ref[10]'s own internal baselines, not ours. Out of scope. |
| Their Caliper-based harness | We use our own harness so all four systems are driven identically. Their workload design informs ours; their tooling is not reused. |

**None of these omissions touch the authorization, redaction, or audit path being
measured.** Each omitted item is either a workload-generation concern (replaced by
the shared dataset) or an unrelated comparison.

---

## 6. Deviations from the original

| Deviation | Justification | Effect on results |
|---|---|---|
| Voting round closes on threshold, not on full window `t` | See §2 note | **Favours Ref[10]** — reduces its measured latency |
| Redaction consensus **is** included | The paper explicitly excluded it ([Ref[10].md:466](../../Reference/Ref%5B10%5D/Ref%5B10%5D.md#L466)): *"the consensus mechanism for redaction operations was not included"* | **Raises** Ref[10]'s measured cost vs. its published figures — but is required, since ZK-Redact's batching amortizes exactly this cost. Excluding it would hide the effect we are measuring. |
| Our network topology, not theirs | One shared environment across all systems | Absolute numbers differ from published; relative comparison is valid |
| Redaction PRUNES: `d_w` is replaced with a reference to `tx_rdt`, and `d_new` lives in the redaction transaction | Not a deviation — this is Algorithm 5 line 9 and §V-C ("we use the pruning technology to delete target data"). Recorded because the shared harness hands every scheme a `NewContent`, and writing that into the block would silently turn Ref[10] into a content-replacement scheme | **Neutral on cost** (a short reference is hashed instead of a 512-byte payload), but it is a real *capability* difference: Ref[10] deletes where ZK-Redact replaces. Pinned by `TestRedactAppliesAndReportsCostSplit` |
| Schnorr challenge binds the public key: `e = H(R ‖ P ‖ m)` | Schnorr's 1989 formulation ([Ref[10].md:492](../../Reference/Ref%5B10%5D/Ref%5B10%5D.md#L492), ref. [43]) hashes only `(R, m)`. Key prefixing is the modern standard (RFC 8032, BIP-340) and closes related-key attacks in the multi-key setting — which is Ref[10]'s setting exactly, since `vote()` verifies many keys against one message. | **Marginally against Ref[10]** — one extra point hashed per sign and per verify. Negligible beside the two scalar multiplications, and it errs in the safe direction. Pinned by `TestChallengeBindsPublicKey`. |

> Because of the second row, **our Ref[10] numbers are not comparable to the numbers
> printed in the paper**, and must never be presented as such. They are comparable
> only to the other systems in this evaluation, which is the point.

---

## 7. Fidelity checklist

Verify before any Experiment 1 result is recorded:

- [x] Committee selection is genuinely hash-based over the full node set, not a fixed list
      — `TestCommitteeIsHashBasedOverFullNodeSet`, `TestCommitteeMembersAllSatisfyPolicy`
- [x] Every vote carries a real signature that is actually verified
      — `TestVoteRoundVerifiesBeforeCounting` drives forged ballots through a stub
      transport and requires the tally to exclude them
- [x] Threshold logic matches Algorithm 3, including rejection below threshold
      — `TestVerifySigmaRejectsForgedSets` (below threshold, duplicate-padded,
      replayed onto another request, replayed onto another contract)
- [x] `T_rdbl` exclusions (genesis, prior redactions, contract transactions) are enforced
      — `TestAuthorizeDenials`, `TestRedactionTransactionsAreNotRedactable`
- [x] Attribute policy `A_r` is genuinely evaluated per requester
      — `TestEvalPolicy`, `TestEvalPolicyRejectsMalformed`,
      `TestCommitteeMemberRederivesTheDecision`
- [ ] **Votes travel over the real network, not in-process function calls**
      — NOT YET. `vote_transport: in_process` is the only implementation; the
      `fabric` transport is refused rather than silently downgraded, and
      `validate-config` warns while this stands. Exp 1 and Exp 2 numbers for
      Ref[10] are a lower bound until this box is ticked.
- [x] Audit verifies every located redaction transaction, not just the target
      — `TestAuditVerifiesEveryLocatedRedaction`,
      `TestAuditRejectsTamperedRedactionRecord`,
      `TestAuditRejectsDuplicatePaddedRecord`. Verification cost measured at
      285µs / 567µs / 1134µs / 2268µs / 4611µs for depths 1/2/4/8/16, i.e.
      linear in history depth as `Σ` re-verification requires. Verifying only
      the target would report depth-independent verification, which nothing in
      Ref[10]'s design provides.
- [x] Algorithm 1 validates a redacted transaction AGAINST its redaction
      transaction, not merely by recomputing hashes
      — `TestAuditRejectsPrunedContentReplacedByArbitraryData`,
      `TestAuditRejectsReferenceToWrongTarget`,
      `TestAuditRejectsDanglingReference`,
      `TestAuditRejectsUnredactedTransactionCarryingAReference`. Recomputed
      hashes always agree with whatever a node wrote, so hash checks alone
      cannot distinguish an authorised redaction from an arbitrary edit.
- [x] `H_c` immutability is enforced — a redaction altering core data must fail
      — `TestAuditDetectsCoreDataTampering`, `TestRedactionChangesOnlyTheInsertedBranch`
- [x] No parameter appears as a literal anywhere in the implementation
      — every value arrives through `SetupParams.Params`; `TestSetupGuards`
      covers each missing or invalid one

> **Mutation-checked.** Each box above was verified by breaking the property in
> a scratch copy and confirming the suite fails: an always-granting policy, an
> always-true `evalPolicy`, an always-true `verifySigma`, a `verifyEMT` without
> the `H_c` check, address-independent committee selection, an indexed audit, a
> vote round that counts without verifying, a member that rubber-stamps, a
> member that skips the CA signature check, and a `fabric` transport that falls
> back to in-process. All ten fail the suite.
