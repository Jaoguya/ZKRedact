# ZK-Redact Evaluation — Task List

Three experiments, one figure each. Everything below assumes the Go implementation,
Hyperledger Fabric 2.5, and the measurement boundaries fixed in Section V-B.

---

## Phase 0 — Blockers (must clear before any measurement)

- [ ] **Fix Eq. (52): PAI root recomputation.** Currently linear in the index size,
      which contradicts the `O(ν + log|I|)` audit bound. Replace with an incremental
      or sparse Merkle tree. Until this is done, Experiment 3 will measure the
      opposite of the claim.
- [ ] Confirm the ZK public statement excludes redaction location and content
      (both belong in the witness). Circuit must be finalised before proving keys
      are generated, or every Experiment 1 number is invalidated by a later change.
- [ ] Obtain circuit constraint counts for the authorization circuit — needed for
      the Experiment 1 discussion and to sanity-check proving/verification times.
- [ ] Decide the auditor key registration path (`PK_A`), since Experiment 3's
      auditor authorization adder depends on it.

---

## Phase 1 — Shared infrastructure

### 1.1 Configuration and reproducibility
- [ ] Single runtime config file holding every swept parameter (no hard-coded values).
- [ ] Result record schema: resolved config, random seed, dataset ID, code revision,
      environment fingerprint, timestamp, raw per-request timings.
- [ ] Write results as one row per request (not pre-aggregated) so percentiles and
      decompositions can be recomputed without re-running.
- [ ] Verify determinism: same config + same seed → identical output. Run twice, diff.

### 1.2 Dataset generator
- [ ] Seeded generator producing 100,000 transactions: 256-byte immutable core
      payload, 512-byte redactable payload.
- [ ] 100 registered requesters distributed across four organizations.
- [ ] 10 redaction policies at predicate depth three (membership ∧ role ∧ policy version).
- [ ] Ingestion loader for each of the four systems' native representations.
      **Ingestion is not timed** — assert equivalent ledger state before measuring.

### 1.3 Request trace
- [ ] 5,000 redaction requests, fixed order, replayed identically by all systems.
- [ ] Closed-loop arrival model with configurable concurrency level.
- [ ] Conflict ratio parameter, swept over {0, 0.25, 0.50}.
- [ ] Target distribution over transactions, configurable.

### 1.4 Cryptographic substrate (shared by all four systems)
- [ ] SHA-256 hashing.
- [ ] Groth16 over BLS12-381 via `gnark` for `π_ρ`; generate and cache proving/verifying keys.
- [ ] Chameleon hash over P-256, with `CH.Adapt` instrumented as its own timer.
- [ ] Schnorr signatures over P-256.
- [ ] 3072-bit RSA universal accumulator (for ref22).
- [ ] Microbenchmark each primitive standalone first — these are the floors every
      later number must be consistent with.

### 1.5 Fabric network
- [ ] 4 orgs × 2 peers, 3-node Raft ordering service.
- [ ] Block cutting fixed at 100 tx/block, 1000 ms timeout, identical for all systems.
- [ ] Resource caps: 1 vCPU and 2 GB per peer on the 32-vCPU / 64 GB host.
- [ ] Chaincode for ZK-Redact redaction commit + PAI anchoring.

### 1.6 Baselines
- [ ] **ref10 (EMT):** committee voting, aggregated Schnorr verification, extended
      Merkle tree. Build **both** transports — in-process arm (like-for-like control)
      and deployed Fabric arm (true deployed cost).
- [ ] **ref13 (VRBC):** manager trapdoor check, blockchain authentication tree,
      challenge–response audit.
- [ ] **ref22 (Shen et al.):** regulator key check, double-trapdoor CH, accumulator audit.
- [ ] Cross-check each implementation against the figures reported in its own paper
      before using it as a baseline. Document any discrepancy.

### 1.7 Instrumentation
- [ ] Separate timers for cryptographic work (off-chain, in-process) and ledger /
      consensus cost. **Never summed** into one number.
- [ ] Per-request counters: consensus blocks, round trips, signature verifications.
- [ ] Freshness flag `Fresh_ρ` recorded per batched request.

---

## Phase 2 — Experiment 1: Verification Throughput

**Figure:** x = number of concurrent requests (1→1024, log₂); y = throughput, req/s (log)

- [ ] Harness measuring the authorization path only — starts at admission to the
      authorization component, stops at final decision. Execution and commit excluded.
- [ ] Sweep concurrency geometrically: 1, 2, 4, …, 1024.
- [ ] Sweep shard count N ∈ {1,2,4,8,16,32,64}; plot N ∈ {1,8,64}.
- [ ] Sweep proof batch size B ∈ {1,2,4,8,16,32,64} × waiting bound Δ ∈ {1,6,13,63} ms.
- [ ] Toggle native batch verification on/off.
- [ ] Run all four baselines (ref10 on both transports) across the concurrency sweep.
- [ ] Confirm the ablation grid is populated at every magnitude: (N=1,B=1),
      (N>1,B=1), (N=1,B>1), (N>1,B>1).
- [ ] Extract: crossover concurrency vs each baseline, saturation point per shard
      count, scaling efficiency (speedup ÷ N), p50/p95/p99 latency.
- [ ] Build `tab:exp1-scaling` — latency percentiles, scaling efficiency, saturation point.
- [ ] Plot `fig/exp1-throughput`.

---

## Phase 3 — Experiment 2: Redaction Processing Overhead

**Figure:** x = number of redaction requests (100→5000); y = avg overhead, ms/request

- [ ] Harness measuring execution only — starts when an already-authorized request
      enters redaction execution, stops when the state transition is committed and
      the provenance record is generated. Authorization excluded.
- [ ] Sweep workload size: 100, 250, 500, 1000, 2500, 5000 requests.
- [ ] Sweep redaction batch size B_R ∈ {1,2,4,8,16,32,64}; plot B_R ∈ {1,8,64}.
- [ ] Sweep waiting bound Δ_R ∈ {63,125,250,500} ms.
- [ ] Sweep conflict ratio {0, 0.25, 0.50}.
- [ ] Run baselines at their native operating point (all are effectively B_R = 1).
- [ ] Decompose cost: total `CH.Adapt` time (per-request floor) vs blockchain-side
      time per batch (the amortizable part).
- [ ] Record stale-exclusion rate — fraction with `Fresh_ρ = 0` requiring re-authorization.
- [ ] Record achieved redactions/second.
- [ ] Identify the operating point where marginal amortization gain = marginal
      staleness loss.
- [ ] Build `tab:exp2-decomposition` — CH.Adapt time, blockchain-side time,
      redactions/s, stale-exclusion rate, per plotted configuration.
- [ ] Plot `fig/exp2-overhead`.

---

## Phase 4 — Experiment 3: Provenance Retrieval and Audit Verification Cost

**Figure:** x = redactions in transaction history ν ∈ {1,2,4,8,16} (log₂);
y = audit verification time, ms. Each scheme drawn twice: L=100 solid, L=1000 dashed.

- [ ] **Confirm Phase 0 PAI fix is in place first.**
- [ ] Build ledgers at both sizes: L = 100 and L = 1000 blocks.
- [ ] Generate audited transactions with history depth ν ∈ {1,2,4,8,16} at each
      ledger size. Verify the anchored PAI states match the redaction rounds executed.
- [ ] Implement each scheme's own audit path:
      - ZK-Redact: retrieve authenticated history, verify against `R_PAI^(e)`
      - ref13: challenge–response over the blockchain authentication tree
      - ref10: query blocks, recompute extended Merkle tree
      - ref22: collect current block versions, compare against accumulator state
- [ ] Time retrieval latency and auditor verification **separately** — never summed.
- [ ] Record evidence transferred in bytes.
- [ ] Measure auditor authorization cost separately as a constant adder: signature
      verification, freshness check, `Π_a^audit` evaluation.
- [ ] Sanity check before plotting: ZK-Redact's L=100 and L=1000 curves should be
      near-coincident. **If they separate, stop — the PAI fix did not take.**
- [ ] Build `tab:exp3-retrieval` — retrieval latency, evidence bytes, auditor
      authorization adder.
- [ ] Plot `fig/exp3-audit`.

---

## Phase 5 — Analysis and write-up

- [ ] Repeat each configuration ≥5 times; report median with visible spread.
- [ ] Cross-check every measured number against the Table I complexity predictions.
      Any mismatch is either an implementation bug or a wrong complexity claim —
      resolve before writing prose.
- [ ] Verify no reported number came from an analytical model or extrapolation.
- [ ] Fill the three `[To be completed from the measurement run]` blocks in
      Section V-C.
- [ ] Confirm figures are legible at IEEE single-column width in greyscale
      (Experiment 3 has 8 lines — colour must not be load-bearing; rely on line
      style and markers).
- [ ] Archive raw results, configs, and seeds alongside the code revision.

---

## Known risks

| Risk | Mitigation |
|---|---|
| PAI root fix not landed before benchmarking | Phase 0 gate; Experiment 3 sanity check |
| Circuit changes after key generation | Freeze circuit before Phase 1.4 |
| Baseline implementations not faithful to their papers | Cross-check against published figures (1.6) |
| Experiment 3 figure unreadable at 8 lines | Line style + markers, greyscale test |
| Host load drift across long sweeps | Fixed resource caps, interleave configurations rather than running each to completion |