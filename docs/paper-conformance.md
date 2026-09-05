# Paper Conformance Audit

Every implementation claim, checked against the paper that specifies it.

This file exists because the failure mode it guards against is silent. A
baseline given a cheaper primitive than its paper specifies does not crash, does
not fail a test, and does not look wrong in a plot — it simply runs faster than
its own design permits, and the comparison becomes worthless without anything
indicating why.

**Status legend**

| | |
|---|---|
| ✅ | Implemented and checked against the cited equation or algorithm |
| 🔶 | Structure in place, cryptography not yet written (`ErrNotImplemented`) |
| ⬜ | Not started |
| ⚠️ | Conformance risk — read the note |

Last audited against: `pkg/ch`, `pkg/merkle`, `internal/schemes/*`.

---

## 1. Chameleon hash — construction per scheme

The finding that prompted this file: the three systems using a chameleon hash
use **three different constructions**, and they differ in per-redaction cost —
which is exactly what Exp 2 reports as `CryptoTime`.

| System | Required construction | Source | Status |
|---|---|---|---|
| ZK-Redact | unspecified; classic admissible | [ZK-Redact.md:293](../Reference/ZK-Redact%20Scheme/ZK-Redact.md#L293), [:628](../Reference/ZK-Redact%20Scheme/ZK-Redact.md#L628) — generic `CH.KeyGen` / `CH.Hash` / `CH.Adapt` | ✅ `chameleon.go` |
| Ref[10] EMT | **none** — pruning plus voting | no chameleon hash anywhere in the scheme | — |
| Ref[13] VRBC | ephemeral trapdoor, two-component key | [Ref[13].md:177](../Reference/Ref%5B13%5D/Ref%5B13%5D.md#L177) Eq. 5 | ✅ `ephemeral.go` |
| Ref[22] Shen | double trapdoor (Chen et al.) | [Ref[22].md:69-77](../Reference/Ref%5B22%5D/Ref%5B22%5D.md#L69) §II-A | ✅ `doubletrapdoor.go` |

Enforced by `ch.Required` and `ch.CheckRequired`, with `TestRequiredConstructionMapping`
failing if a future edit points a baseline at the classic construction.

### 1.1 Classic — Krawczyk–Rabin

| Paper property | Implementation | Test |
|---|---|---|
| `CH(m,r) = e·G + r·Y` | `PublicKey.Hash` | `TestHashIsDeterministic` |
| Adapt yields a collision | `PrivateKey.Adapt` | `TestAdaptProducesCollision` |
| **Key exposure** — one collision leaks the trapdoor | `RecoverTrapdoor` | `TestKeyExposure` |

> Ref[22] cites this weakness as its reason for moving to a double trapdoor
> ([Ref[22].md:69](../Reference/Ref%5B22%5D/Ref%5B22%5D.md#L69)). The test asserts the
> weakness rather than describing it, so replacing this construction with a
> resistant one fails loudly instead of passing unnoticed.

### 1.2 Ephemeral trapdoor — Ref[13] Eq. 5

Paper: `ch_i = (X·Y)^{H1(h_{i-1}‖m_i, Y)} · g^{r_i} = g^{H1(...)·(x+y)+r_i}`

| Paper property | Implementation | Test |
|---|---|---|
| Two-component key `(x, y)` | `EphemeralKey` | `TestEphemeralHashMatchesPaperEquation` |
| Exponent form `H1(...)·(x+y)+r` | `EphemeralHash` | same — recomputed independently |
| `Y` rotates per adaptation | `EphemeralAdapt` | `TestEphemeralAdaptRotatesY` |
| `Y` bound into the challenge | `ephemeralChallenge` | `TestEphemeralVerifyNeedsCorrectY` |
| Chain position `h_{i-1}` bound in | `ctx` parameter | `TestEphemeralContextBinding` |

⚠️ **Deviation, recorded.** The paper's §4.3 derives the new ephemeral component
as `y' = H2(x_i, m'_s)` in a multi-party MPC setting. This implementation uses
the same derivation for the single-party permissioned case, which is the setting
under test. The multi-party aggregation of §4.3 is not implemented, and is out
of scope per [`baselines/ref13-vrbc.md`](baselines/ref13-vrbc.md) §5.

### 1.3 Double trapdoor — Ref[22] §II-A

Transcribed algorithm by algorithm:

| Paper algorithm | Implementation | Test |
|---|---|---|
| `KGen → tk=(x,t), hk=Y=xP` | `DoubleTrapdoorKeyGen` + per-hash `t` in `HGen` | `TestDoubleTrapdoorDistinctTPerHash` |
| `HGen → h=tP, ξ=(r,K)`, `r = t − H(m,K)(k+x)` | `HGen` | `TestDoubleTrapdoorHGenEqualsTP` |
| `RHGen → h = H(m,K)(K+hk) + rP` | `RHGen` | `TestDoubleTrapdoorRHGenReproducesHash` |
| `Verify` | `Verify` | `TestDoubleTrapdoorVerifyRejectsTampering` |
| `Adapt → ξ'=(r',K')`, fresh `k'` | `Adapt` | `TestDoubleTrapdoorAdaptProducesCollision` |
| **Key-exposure freeness** (Definition 2) | fresh `k'` per adaptation | `TestDoubleTrapdoorKeyExposureFreeness` |

> `t` is modelled as per-hash rather than per-key, following the paper's note
> that *"different t's correspond to different hash values, which relieves the
> storage burden of trapdoor holder"* ([Ref[22].md:77](../Reference/Ref%5B22%5D/Ref%5B22%5D.md#L77)).
> `DoubleTrapdoorHandle` keeps `t` separate from the public checking string so
> the type system distinguishes what may be published from what may not.

---

## 2. Merkle tree

Shared by three systems, so it lives in `pkg`.

| Consumer | Use | Source |
|---|---|---|
| ZK-Redact PAI | provenance authentication, batch root `R_B` | [ZK-Redact.md:607](../Reference/ZK-Redact%20Scheme/ZK-Redact.md#L607) |
| Ref[10] EMT | two branches per transaction | [Ref[10].md:182](../Reference/Ref%5B10%5D/Ref%5B10%5D.md#L182) Eq. 4 |
| Ref[13] | block transaction root `m_i` | [Ref[13].md:99](../Reference/Ref%5B13%5D/Ref%5B13%5D.md#L99) |

⚠️ **Deviation from all three papers, deliberate.** None of them specifies
domain separation or an odd-node rule. This implementation adds RFC 6962
prefixes and promotes unpaired nodes rather than duplicating them.

Without the prefixes, an internal node's hash is indistinguishable from a
leaf's, allowing inclusion proofs for data never committed. Duplicating an
unpaired node reproduces the Bitcoin bug CVE-2012-2459, where two distinct leaf
sets share a root.

Both choices apply **identically to every system**, so no scheme gains an
advantage. Tests: `TestSecondPreimageResistance`, `TestOddNodeNotDuplicated`.

---

## 3. ZK-Redact

| Phase | Requirement | Status |
|---|---|---|
| 1 Setup | keys, circuit, shards, PAI init | 🔶 |
| 2 Authorization | statement `x_i`, proof `π_i` | 🔶 |
| 3 Sharded verification | assign `H(req) mod N`, batch `(B,Δ)` | 🔶 |
| 4 Batch redaction | `Fresh_i`, `CH.Adapt`, batch commit `C_B` | 🔶 |
| 5 Provenance | chain `c_i = H(c_i ‖ H(PR))` | 🔶 |
| 6 Audit | auditor auth, targeted retrieval | 🔶 |

Already enforced in code:

| Claim | Where | Note |
|---|---|---|
| Cost split: `CH.Adapt` per request, ledger work amortised | `RedactionResult.CryptoTime` / `.LedgerTime` | [ZK-Redact.md:645-647](../Reference/ZK-Redact%20Scheme/ZK-Redact.md#L645) |
| Same-target requests serialise, others parallel | `Redact` contract | [ZK-Redact.md:583-585](../Reference/ZK-Redact%20Scheme/ZK-Redact.md#L583) |
| Stale requests excluded, not retried | `RedactionResult.StaleExcluded` | [ZK-Redact.md:588-596](../Reference/ZK-Redact%20Scheme/ZK-Redact.md#L588) |
| Sharding independent of native batch verification | `native_batch_verify: [false, true]` | [ZK-Redact.md:508-509](../Reference/ZK-Redact%20Scheme/ZK-Redact.md#L508) |
| Audit independent of ledger size | `exp3` fails a scheme that claims it and traverses the ledger | [ZK-Redact.md:813-814](../Reference/ZK-Redact%20Scheme/ZK-Redact.md#L813) |

---

## 4. Ref[10] EMT

| Algorithm | Requirement | Status |
|---|---|---|
| 1 EMT Verification | `H_tx = H(H_c ‖ H_w)`; `H_c` unchanged after redaction | 🔶 |
| 2 Redaction Request | CA validation, `T_rdbl = T_all \ (T_gen ∪ T_rdt ∪ T_con)` | 🔶 |
| 3 Smart Contract | `RS_SHA256(addr, N_all, A_r) → N_auth`, voting | 🔶 |
| 4 Redaction Voting | Schnorr signature per vote | 🔶 |
| 5 Local Redaction | verify `Σ`, replace `d_w` with a reference | 🔶 |

Already enforced:

| Claim | Where |
|---|---|
| Threshold must be a real majority | `Setup` rejects `thr ≤ size/2` |
| Committee sized from a fault assumption | validator checks `3f+1` / `2f+1` |
| Committee must fit available peers | validator |
| Policy `{S ∨ R ∨ V}` is the paper's own default | `config`, `attribute_policy` |

⚠️ **Deviation, recorded.** Redaction consensus **is** included; the paper
excluded it ([Ref[10].md:466](../Reference/Ref%5B10%5D/Ref%5B10%5D.md#L466)). That cost is
what ZK-Redact's batching amortises, so excluding it would hide the effect Exp 2
measures. Consequence: our Ref[10] numbers are **not comparable** to the
paper's published figures and must never be presented as such.

---

## 5. Ref[13] VRBC

| Component | Requirement | Status |
|---|---|---|
| Block structure | `B_i = (h_{i-1}, ch_i, m_i, Y_i, r_i, ctr_i)` | 🔶 |
| Chameleon hash | Eq. 5 | ✅ `ephemeral.go` |
| BAT | q-ary tree, Pointproofs-style vector commitments | ⬜ |
| Block query | Eq. 11 pairing check, Eq. 12 CH check | ⬜ |
| Auditing | `Chal=(z,φ₁,φ₂)`, aggregate pairing check | ⬜ |
| Optimized auditing §4.1 | path-union selection | ⬜ |

Already enforced:

| Claim | Where |
|---|---|
| `N = q + 1`, not independent | `Setup` derives it; config records the formula |
| `challenged_blocks` valid only at 1% corruption | `Setup` rejects any other rate |
| Optimized auditing on — the paper's own reporting configuration | config |
| Delayed redaction **not** implemented | config, `delayed_redaction: false` |

⚠️ **Pairing curve.** Ref[13] does not name a curve. This evaluation mandates
BLS12-381: BN254 is ~100-bit after Kim–Barbulescu exTNFS, which would put this
baseline below the uniform 128-bit target and hand it unearned speed. Enforced
by `crypto.RequirePairingCurve`.

---

## 6. Ref[22] Shen

| Algorithm | Requirement | Status |
|---|---|---|
| Block structure | `B = ⟨p,m,i,A,w,ctr,ξ⟩` | 🔶 |
| Double-trapdoor CH | §II-A | ✅ `doubletrapdoor.go` |
| Universal accumulator | trapdoorless, RSA-3072 | ⬜ |
| 1 Append / 2 ValApp | | ⬜ |
| 5 Modify / 6 ValMod | `UA.Del` then `UA.Add`, both witnesses | ⬜ |
| 7 Delete / 8 ValDel | set `L`, consecutive vs inconsecutive | ⬜ |
| 9 ValChain | full traversal | ⬜ |

Already enforced:

| Claim | Where |
|---|---|
| Accumulator ≥ 3072 bits at 128-bit target | `Setup` rejects smaller |
| `Insert` not implemented (no counterpart elsewhere) | `Setup` rejects `implement_insert: true` |
| Delete-set sizes aligned with ZK-Redact's batch sizes | validator |

⚠️ **Deviations, recorded.** PoW difficulty is not zeroed (the paper set `D=0`;
our network is Raft, with no puzzle to neutralise) and communication **is**
included (the paper excluded it). Both apply uniformly to all systems.
Consequence: this baseline has the widest gap to its published numbers, which
must never share a table with ours.

---

## 7. Open conformance risks

| # | Risk | Mitigation |
|---|---|---|
| 1 | Scheme cryptography is unimplemented, so conformance beyond `pkg/ch` and `pkg/merkle` is unverified | This file is re-audited as each component lands |
| 2 | Nothing has been compiled or executed — no Go toolchain on the authoring machine | `make build && make test` on the target host before any result is recorded |
| 3 | ZK-Redact's spec does not fix a CH construction, so the classic choice is an assumption | Recorded in `ch.Required`; revisit if the paper is revised |
| 4 | Ref[13]'s BAT needs a Pointproofs-style vector commitment with no standard Go implementation | Highest-risk remaining component; conformance to §3.2.2 must be audited when written |

---

## How to keep this current

1. When a component lands, add its row with the paper location and its test.
2. Anything that departs from a paper goes in that scheme's deviation list with
   the reason **and the direction of bias** — which system it favours.
3. Any parameter whose value changes a scheme's cost profile gets a `Setup`
   check that refuses the wrong value, not just a comment.

Deviations are acceptable and sometimes necessary. Undocumented ones are not.
