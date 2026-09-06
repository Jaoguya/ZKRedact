# Baseline: Ref[22] — Shen et al.

**Paper.** J. Shen, X. Chen, Z. Liu, W. Susilo, *"Verifiable and Redactable
Blockchains With Fully Editing Operations,"* IEEE Transactions on Information
Forensics and Security, vol. 18, 2023. DOI 10.1109/TIFS.2023.3288429
Source: [`Reference/Ref[22]/`](../../Reference/Ref%5B22%5D/)

**Role in evaluation.**

| Experiment | Role |
|---|---|
| 1 — Verification Throughput | Lower bound only — no per-request authorization protocol |
| 2 — Redaction Throughput | Fully comparable; **the only baseline with a multi-item cost curve** |
| 3 — Provenance Audit | Fully comparable — the linear-scan reference point |

**Why it earns a place.** Its `Delete` operation takes a *set* `L` and reports cost
separately for consecutive and inconsecutive positions. That is the only
multi-item-per-operation scaling curve in the three references, and it maps directly
onto ZK-Redact's distinction between independent transactions (parallel) and
same-transaction requests (serialized).

---

## 1. What we implement

### 1.1 Block structure (§III-A)

`B = ⟨p, m, i, A, w, ctr, ξ⟩` where:

- `p` — hash of the preceding block
- `m` — Merkle root of transactions
- `i` — globally unique sequence number
- `A` — accumulator state of the chain up to `B`
- `w` — witness for `A`
- `ξ` — checking string for the chameleon hash over `cont = p‖m‖i‖A‖w`

Validity: `validblock(B) := H₁(ctr, CH.RHGen(cont, ξ, hk)) < D`

### 1.2 Primitives

- **Double trapdoor chameleon hash family** — key-exposure resistant, history-independent
- **Trapdoorless universal accumulator** — commitment over all blocks, supporting
  membership and non-membership witnesses
- **Largest sequence number principle** — replaces longest-chain, forcing adoption of
  the latest version

### 1.3 Algorithms implemented

| Algorithm | Operation | Used in |
|---|---|---|
| 1 | `Append` | Ledger construction |
| 2 | `ValApp` | Exp 3 |
| 5 | `Modify` | Exp 2 |
| 6 | `ValMod` | Exp 3 |
| 7 | `Delete` | Exp 2 |
| 8 | `ValDel` | Exp 3 |
| 9 | `ValChain` | Exp 3 — the linear-scan baseline |

`Modify` runs `UA.Del` to invalidate the prior version, `UA.Add` for the new one,
then `UA.MWit` / `UA.N-MWit` to produce membership and non-membership witnesses.

`Delete` over a set `L` computes `H_prime(·)` for every deleted block and multiplies
them, plus one `CH.Adapt` behind each consecutive subset.

---

## 2. Measurement boundaries

### Experiment 1 — Verification Throughput

| | |
|---|---|
| **Start** | Redaction request admitted |
| **Stop** | Regulator key possession verified |

> **No per-request authorization protocol exists.** Editing authority rests with the
> regulator `R`, who holds the trapdoor keys and issues per-block key pairs via
> `KGenB`. There is no policy evaluation and no requester privacy.
>
> As with Ref[13], we measure what the scheme specifies and do **not** invent an
> authorization protocol for it. Under concurrent load the single regulator is a real
> serialization point — a genuine property of the design, not an artefact of our
> harness.

### Experiment 2 — Redaction Throughput

| | |
|---|---|
| **Start** | Authorized edit enters execution |
| **Stop** | `CH.Adapt` complete, accumulator updated, witnesses regenerated |

**Two sub-measurements, mirroring the paper's own split:**

| Case | Corresponds to |
|---|---|
| `Modify` on a single block | The `B_R = 1` point |
| `Delete` over set `L` | Multi-item cost, **consecutive** vs **inconsecutive** |

> The consecutive/inconsecutive split maps onto ZK-Redact's Phase 4 Step 1 rule that
> requests on different transactions execute independently while same-transaction
> requests serialize ([ZK-Redact.md:583-585](../../Reference/ZK-Redact%20Scheme/ZK-Redact.md#L583-L585)).
>
> **Do not present `Delete(L)` as equivalent to ZK-Redact batching.** It is a single
> operation over multiple blocks, not amortization of blockchain-side cost across
> independently authorized requests. It shares the *shape* of a batch-size curve, and
> is compared on that basis only.

### Experiment 3 — Provenance Audit

| | |
|---|---|
| **Start** | `ValChain` invoked |
| **Stop** | All current block versions collected and compared against accumulator state |

`ValChain` requires collecting the current version of every existing block to compare
against the latest accumulator state. Cost grows with ledger length — this is the
**linear-scan reference point** against which ZK-Redact's ledger-size independence is
demonstrated.

Per-operation validations (`ValApp`, `ValMod`, `ValDel`) are measured separately; the
paper reports these as flat in chain length.

---

## 3. Parameters

All from `config/experiment.yaml`. **None hardcoded.**

| Parameter | Meaning | Rationale requirement |
|---|---|---|
| `accumulator_key_bits` | Universal accumulator modulus | Paper uses 3072 (128-bit security). Must match the security level of every other system — justify in config |
| `ch_curve` | Double-trapdoor CH curve | Paper uses P-256 (128-bit). Same requirement |
| `delete_set_size` | \|`L`\| | Sweep range must be justified, and aligned with Experiment 2's `B_R` range so the curves are comparable |
| `delete_set_structure` | Consecutive / inconsecutive / mixed | Should mirror Experiment 2's conflict-ratio settings |
| `pow_difficulty` | Difficulty target | See deviation note below |

> **Security-level alignment is mandatory.** The paper pairs P-256 with a 3072-bit
> accumulator, both at 128-bit security. Whatever level the evaluation adopts, all
> four systems must use it. A baseline at a different level makes every comparison
> void.

---

## 4. Dependencies

| Dependency | Purpose | Notes |
|---|---|---|
| RSA-style universal accumulator | Chain-state commitment, membership / non-membership witnesses | **Beyond base toolchain — flagged per SKILL.md** |
| Double trapdoor chameleon hash | Key-exposure-resistant editing | May share the project CH library if the double-trapdoor variant is supported; otherwise separate |
| Big-integer arithmetic | Accumulator operations | Go standard library `math/big` is expected to suffice |

---

## 5. What we do NOT implement, and why

| Omitted | Reason |
|---|---|
| `Insert` (Algorithms 3, 4) | Block insertion is this paper's distinctive contribution but has no counterpart in ZK-Redact, Ref[10], or Ref[13]. Nothing to compare it against. |
| Bitcoin-specific PoW mechanics | Our setting is permissioned. See deviation below. |
| Non-interactive succinct proofs (§II-B) | ⚠️ **This justification is wrong and the omission is still open.** NI-PoE and NI-PoKE are on the measured path: Algorithm 7 builds four of them inside `Delete` (lines 17, 19, 22, 23) and Algorithm 8's entire return value is their verification. `UA.MWit` and `UA.N-MWit` also return proofs rather than bare witnesses. Omitting them makes `Delete` cheaper than the paper specifies, on the metric Exp 2 reports for this baseline. Tracked as a known gap. |
| Comparison against AMVA17 / Bitcoin | Their internal baselines, not ours. |

> **`Insert` is omitted for scope, not convenience.** It is a genuine capability the
> other three schemes lack. If the paper's related-work section discusses editing
> expressiveness, this should be acknowledged there rather than silently dropped.

---

## 6. Deviations from the original

| Deviation | Justification | Effect on results |
|---|---|---|
| **PoW difficulty not set to 0** | The paper sets `D = 0` to isolate operation cost ([Ref[22].md:769-771](../../Reference/Ref%5B22%5D/Ref%5B22%5D.md#L769-L771)). Our permissioned network uses Raft, so there is no PoW puzzle to neutralise. | Not comparable to their published numbers; comparable to our other systems |
| **Communication IS included** | The paper states *"the impact of communication is not considered in the test of each functionality"*. Network cost is central to what we measure, and is included for all four systems identically. | Raises measured cost vs. published figures; applied uniformly |
| Fabric instead of Bitcoin | One shared environment | Absolute numbers differ; relative comparison valid |
| Go instead of Python 3.8 | Project toolchain | **Favours Ref[22]** — likely faster than published |
| Their hardware was a 2 GB VM | We use the shared environment for all systems | Not comparable to published figures |
| The modulus is generated locally, so its factors are briefly known | A real deployment uses an RSA UFO or a multi-party ceremony. Cost depends on modulus size, not on who knows the factors — **except for deletion**, which is why the regulator is given `phi(N)` (see below) | Neutral on cost; the security argument does not survive this shortcut and no security claim is made from it |
| The regulator holds `phi(N)` and deletes in one exponentiation | **Not a deviation — this is what the paper specifies.** §II-C: *"since the deletion algorithm is costy without the knowledge of group order, it is executed by the regulator with the RSA group order in the proposed blockchain"*, and Algorithms 5 and 7 both take `phi(N)` as an input. The regulator already holds the double-trapdoor CH key, so it is the redaction authority by construction | Recorded because an earlier implementation rebuilt the accumulator instead, at O(n) exponentiations. Measured at RSA-3072: 34 ms at n=50, 69 ms at n=100, 139 ms at n=200, against a flat 8.4 ms with the group order — so the rebuild **inflated Ref[22]'s Exp 2 curve by ~83x at 1,000 blocks and ~830x at 10,000** |

> This baseline has the largest gap between its published setup and ours: they
> disabled PoW, excluded communication, and ran Python on a 2 GB virtual machine.
> **Their published numbers must never appear alongside ours in any table.** Only our
> re-implementation's numbers are admissible — which is exactly what the
> fair-comparison rule in `SKILL.md` requires.

---

## 7. Fidelity checklist

- [ ] Accumulator is a real cryptographic accumulator, not a hash set
- [ ] Both membership *and* non-membership witnesses are generated and verified
- [ ] `UA.Del` genuinely invalidates prior versions — verify a reversion attack is caught
- [ ] Double-trapdoor CH uses both trapdoors as specified, not a single-trapdoor stand-in
- [ ] Largest-sequence-number rule is enforced
- [ ] `Delete(L)` computes `H_prime(·)` for every deleted block, with one `CH.Adapt` per consecutive subset
- [ ] `ValChain` genuinely traverses all blocks — no caching that would hide linear cost
- [ ] Regulator key check is real, not stubbed
- [ ] No parameter appears as a literal anywhere in the implementation

> Two checks carry the most weight. The reversion-attack test proves the accumulator
> actually does its job — the paper's central security claim. And `ValChain` must not
> be accidentally optimised with a cache: its linear cost is the property Experiment 3
> compares against, and hiding it would understate ZK-Redact's advantage while making
> the baseline look better than the scheme actually is.
