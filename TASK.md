# ZK-Redact Evaluation — Task List

Three experiments, one figure each. Everything below assumes the Go implementation,
Hyperledger Fabric 2.5, and the measurement boundaries fixed in Section V-B.

**Rewritten 2026-09-11 against the actual repository state** — code, config,
`go build`/`go vet`/`go test ./...`, and `go run ./cmd/validate-config` — not
against the previous version of this file, which had been reset to a blank
template on 2026-09-08 and no longer matched reality. Every `[x]` below cites
the evidence; every `[ ]` is either genuinely not started or, in two cases,
**actively failing its own test right now**. Where this file previously said a
component was missing and it turned out to exist, the file was wrong, not the
code — read `[x]` items for the pointer, not as a claim you have to trust.

---

## Phase 0 — Blockers (must clear before any measurement)

- [ ] **⚠️ REOPENED — Eq. (52) PAI root recomputation: the update is fixed, the
      end-to-end audit-cost claim is NOT.** The root update itself is
      incremental and `O(touched × log|I|)`, not linear (`internal/pai/index.go:277`,
      `merkle.UpdateLeaf`) — that part of the original blocker is closed.
      But `TestExp3RunsZKRedactAcrossLedgerSizes`
      (`experiments/exp3_audit/zkredact_test.go`) **fails right now**, with
      exactly the failure mode this file's own Phase 4 sanity check warns
      about: *"If they separate, stop — the PAI fix did not take."*
      Measured (2026-09-11, this host):
      ```
      ledger=4   depth=1  blocks=2  verify=5.0199ms
      ledger=40  depth=1  blocks=2  verify=15.028ms
      scaling: linear (cost x5.99 over ledger x10), claim holds: false
      ```
      **What is and is not confirmed:** blocks traversed is flat (2 at both
      ledger sizes) — retrieval genuinely does not re-scan the ledger.
      Verification TIME is not flat — it roughly tripled over a 10x ledger
      growth. That is closer to the paper's own bound of `O(ν + log|I|)`
      (`log(40)/log(4) ≈ 2.66`) than to linear, and the test's ledger range
      (4 vs 40) is too small to cleanly separate "sublogarithmic" from
      "linear" — but the test does not currently make that distinction, and
      as written it FAILS. **Do not report Fig. exp3-audit or Table
      `tab:exp3-retrieval` until this is resolved one way or the other**:
      either the test's classifier needs a wider ledger range / a bound-aware
      check, or there is a genuine `O(log|I|)`-per-verification cost hiding
      inside the verify step that should be surfaced as its own line item
      rather than folded into "ledger-independent."
- [ ] **⚠️ NEW — Exp 2 cost decomposition is not instrumented for ZK-Redact at
      every swept point.** `TestOptimalBatchIsNotPooledAcrossConflictRatios`
      fails: `"zkredact at batch 2, conflict 0.5: zkredact reported zero
      CryptoTime over 10 successful redactions; cost decomposition is not
      instrumented (CH.Adapt cannot be free)"`. This is a guard in the runner
      itself (`experiments/exp2_redaction/runner.go:613`), not a test
      artifact, and `batch=2, conflict_ratio=0.5` is inside the actual
      configured sweep (`redaction_batch.sizes` includes 2;
      `workload.conflict_ratios` includes 0.50) — **a real campaign run today
      will hit this exact grid point and abort.** Needs the CH.Adapt timer
      checked for whichever code path ZK-Redact takes at `B_R=2` under
      conflict, before Phase 3 can be considered done.
- [x] Confirm the ZK public statement excludes redaction location and content
      (both belong in the witness). — `pkg/zk/circuit.go`:
      `AuthorizationCircuit` has exactly two `gnark:",public"` fields
      (`StatementDigest`, `RegistryRoot`); `Loc` and `Mod` are private witness,
      with the reasoning recorded in the circuit's own doc comment.
- [x] Obtain circuit constraint counts for the authorization circuit. —
      `pkg/zk/zk.go::Params.Constraints` is captured from `ccs.GetNbConstraints()`
      at setup and pinned in `config/experiment.yaml:539` (`constraint_count:
      16445`); `cmd/build-zk` refuses to proceed if the compiled circuit and
      the pinned value disagree (`main.go:87`).
- [x] Decide the auditor key registration path (`PK_A`). — `internal/pai/auth.go`
      implements `Auditor` as `E_a^AU = (AID_a, pk_a, Π_a^audit)` per the
      paper's own equation reference in the source comment.

---

## Phase 1 — Shared infrastructure

### 1.1 Configuration and reproducibility
- [x] Single runtime config file holding every swept parameter. —
      `config/experiment.yaml`; every value the packages read arrives through
      it (`pkg/workload/generator.go`'s own doc comment: "nothing here has a
      built-in default"). Enforced by `go run ./cmd/validate-config`, which
      currently reports **0 errors, 3 warnings** against the committed config
      (see Phase 5).
- [x] Result record schema: resolved config, seed, dataset ID, code revision,
      environment fingerprint, timestamp, raw per-request timings. — `pkg/results`.
- [x] Write results as one row per request, never pre-aggregated. — confirmed
      by the schema above; `RESULTS_DIR` output is CSV+JSON per Makefile/SKILL.md.
- [x] Determinism: same config + seed → identical output. — `meta.seed:
      20260905` drives dataset generation, trace ordering and every
      randomised protocol choice per `config/experiment.yaml`'s own comment;
      not independently re-run in this pass.

### 1.2 Dataset generator
- [x] Seeded generator, 100,000 transactions, 256-byte core / 512-byte
      redactable payload. — `pkg/workload/generator.go`; values confirmed live
      in `config/experiment.yaml`: `base_transactions: 100000`,
      `core_payload_bytes: 256`, `redactable_payload_bytes: 512`.
- [x] 100 registered requesters across four organizations. —
      `identities.count: 100`, `environment.network.organizations: 4`.
- [x] 10 redaction policies at predicate depth three. — `policies.count: 10`,
      `predicate_depth: 3`.
- [x] Ingestion loader for each system's native representation, untimed. —
      each scheme's `Setup`/`build` (e.g. `internal/schemes/ref13/wiring.go::build`)
      materialises the shared dataset into its own on-chain form; `Setup` is
      excluded from every measured boundary per `docs/experiments.md` §1.2.

### 1.3 Request trace
- [x] 5,000 redaction requests, fixed order, replayed identically. —
      `workload.total_requests: 5000`.
      ⚠️ `validate-config` warns this gives fewer than 100 samples in the top
      percentile — p99 will read as noise at this size (see Phase 5).
- [x] Closed-loop arrival model, configurable concurrency. — `pkg/workload`.
- [x] Conflict ratio swept over {0, 0.25, 0.50}. — `conflict_ratios: [0.0,
      0.25, 0.50]`.
- [x] Configurable target distribution. — `target_distribution: "uniform"`
      (`"zipf"` also implemented, `zipf_s: 1.1`).

### 1.4 Cryptographic substrate
- [x] SHA-256 hashing. — used throughout; `crypto.RequireHash` gates it.
- [x] Groth16 over BLS12-381 via `gnark`, proving/verifying keys cached. —
      `pkg/zk`; `cmd/build-zk`.
- [x] Chameleon hash over P-256, `CH.Adapt` instrumented as its own timer. —
      `pkg/ch/chameleon.go` (curve-parameterised;
      `config/experiment.yaml`'s security block derives P-256); `CryptoTime`
      in `experiments/exp2_redaction/runner.go` is meant to be exactly this
      timer — **see the Phase 0 blocker above: it is not reliably nonzero.**
- [x] Schnorr signatures over P-256. — `pkg/crypto/schnorr.go`.
- [x] 3072-bit RSA universal accumulator (ref22). — `pkg/accumulator`;
      `Bits` defaults from `security.target_bits` per the file's own comment,
      "Ref[22] specifies 3072."
- [x] Microbenchmark each primitive standalone. — `pkg/ch/chameleon_test.go`,
      `pkg/ch/variants_test.go`, `pkg/crypto/committee_bench_test.go`,
      `pkg/merkle/merkle_test.go`, `pkg/vc/{aggregate,vc}_test.go`,
      `pkg/zk/verify_bench_test.go`. No dedicated `pkg/accumulator` benchmark
      found — worth adding, not blocking.

### 1.5 Fabric network
- [x] 4 orgs × 2 peers, 3-node Raft ordering service. — `environment.network.organizations:
      4`, `peers_per_org: 2`; `network/compose.yaml` names `orderer0/1/2.example.com`.
- [x] Block cutting fixed, identical for all systems. — `block_max_transactions:
      100`; `block_timeout_ms: 250` (`network/configtx.yaml`'s `BatchTimeout:
      250ms` agrees with this value).
      ⚠️ **Flagging, not fixing — this is a `.yaml` comment, out of this
      file's scope.** `config/experiment.yaml`'s own budget-derivation comment
      near `environment.network` still says `1000` in two `[DERIVED from
      block_timeout_ms = 1000]` notes and the live value is `250`; the actual
      timeout was rescaled at least once (`docs/baselines/ref10-emt.md:172`
      documents the *previous* rescale, 2000→1000, and separately flags "every
      fabric figure taken at 1000 ms must be re-measured" — that note is
      itself now one rescale further behind the committed `250`).
- [x] Resource caps, identical for all systems. — `peer_cpu_limit: "3.0"`,
      `peer_memory_limit: "6g"` in `config/experiment.yaml`.
      ⚠️ **Same class of flag.** The CPU-budget comment immediately above this
      value in the same file still does its arithmetic against `peer_cpu_limit
      1.0` (`8 Fabric peers × 1.0 ~ 8 vCPU`), not the live `3.0` (which would
      be `8 × 3.0 = 24 vCPU`, most of the 32-vCPU host). The comment's
      conclusion — headroom for the system under test — may or may not still
      hold at the real value; worth recomputing before trusting the budget
      narrative, not touched here since it lives in `.yaml`, not `.md`.
- [x] Chaincode for redaction commit + PAI anchoring. —
      `network/chaincode/redaction/contract.go`, deployed as a service
      (`network/chaincode-service.yaml`, ccaas).

### 1.6 Baselines
- [x] **ref10 (EMT):** committee voting, aggregated Schnorr verification,
      extended Merkle tree, **both transports built.** — `internal/schemes/ref10/`;
      `scheme.go::newTransport` builds `in_process` or `fabric`; the Fabric
      path is exercised by `fabric_register.go::buildIdentities` and is one of
      the ten properties mutation-tested in
      `docs/baselines/ref10-emt.md` §7 ("a `fabric` transport that falls back
      to in-process" — tested, fails the suite if it happens).
      ⚠️ **The committed config currently selects `in_process`** (`validate-config`
      warns on this deliberately) — Exp 1/2 numbers taken under the committed
      config are Ref[10]'s lower bound, not its deployed cost, until
      `vote_transport: fabric` is set for the run that produces final numbers.
- [x] **ref13 (VRBC):** manager trapdoor check, blockchain authentication
      tree, challenge–response audit, path-union optimized auditing. —
      `internal/schemes/ref13/{bat,audit,verify,wiring}.go`, `pkg/vc` (Pointproofs-style
      vector commitment: `Setup`/`Commit`/`Open`/`Verify`,
      `AggregateOpen`/`AggregateVerify`). Every item in
      `docs/paper-conformance.md` §5 and `docs/baselines/ref13-vrbc.md` §7's
      fidelity checklist is `[x]`. **This file previously said "not
      implemented"; it was wrong** — so was `docs/paper-conformance.md`, fixed
      in this pass.
- [x] **ref22 (Shen et al.):** regulator key check, double-trapdoor CH,
      trapdoorless RSA accumulator audit (Append/ValApp, Modify/ValMod,
      Delete/ValDel, ValChain). — `internal/schemes/ref22/ledger.go`,
      `pkg/accumulator`. Same correction as ref13:
      `docs/paper-conformance.md` §6 previously marked every algorithm
      row `⬜ Not started`; all are built, fixed in this pass.
- [ ] Cross-check each implementation against its own paper's figures,
      **automated negative tests.** `docs/paper-conformance.md` and
      `docs/baselines/*.md` are thorough written cross-checks and are
      current as of this pass. But `make fidelity-check` — the automated
      negative-test target — is a stub: `@echo "TODO: Ref[13] must detect a
      tampered block"` / `"TODO: Ref[22] must catch a reversion attack"` /
      `"TODO: Ref[10] must reject a redaction altering core data"` / `"TODO:
      Ref[10] must reject below-threshold votes"`, then `@false`. All four
      TODOs. (Individual unit tests likely already cover some of
      these — e.g. `TestAuditDetectsATamperedBlock` in ref13 — this target is
      specifically about wiring them into one automated gate, not about
      whether the underlying property is tested at all.)

### 1.7 Instrumentation
- [x] Separate timers for crypto work vs ledger/consensus cost, never summed. —
      `internal/gateway`, `internal/redactor/{executor,ledger}.go`,
      per-scheme timing in `internal/schemes/*`.
- [x] Per-request counters: consensus blocks, round trips, signature
      verifications. — `auth_cost` per `docs/experiments.md`'s capability-matrix
      note; `TestLiveAuthorizationCostIsBlockTime` in ref10 asserts on it directly.
- [x] Freshness flag `Fresh_ρ` recorded per batched request. — threaded through
      `internal/pai/auth.go`, `internal/redactor`, all four scheme packages,
      `pkg/config`, `pkg/scheme`.

---

## Phase 2 — Experiment 1: Verification Throughput

**Figure:** x = concurrent requests (1→1024, log₂); y = throughput, req/s (log)

- [x] Harness measures the authorization path only. —
      `experiments/exp1_verification/runner.go` + `runner_test.go`; `ok` in
      `go test ./...` (0.637s).
- [x] Concurrency sweep 1…1024 geometric. — `concurrency_levels: [1, 2, 4, 8,
      16, 32, 64, 128, 256, 512, 1024]`.
- [x] Shard count sweep {1,2,4,8,16,32,64}; plotted at {1,8,64}. —
      `sharding.counts: [1, 2, 4, 8, 16, 32, 64]`; plot selection in `cmd/plot/load.go`.
- [x] Proof batch size × wait bound sweep. — `proof_batch.sizes: [1, 2, 4, 8,
      16, 32, 64]`.
- [x] Native batch verification on/off toggle. — `native_batch_verify`,
      validated by `validate-config`'s batching check (must contain both
      settings or the ablation is untested).
- [x] All four baselines run across the concurrency sweep. —
      `config/experiment.yaml:783`, `systems: ["zkredact", "ref10_emt",
      "ref13_vrbc", "ref22_shen"]`.
- [x] Ablation grid populated at every magnitude. — enforced by
      `validate-config`'s sharding/batching checks (§ "Checks performed" in
      `cmd/validate-config/README.md`).
- [x] Extract crossover concurrency, saturation point, scaling efficiency,
      p50/p95/p99. — `cmd/plot/load.go` builds `exp1-latency-p50` and related
      series; percentile fields exist on the measurement type.
- [ ] Build `tab:exp1-scaling`. — no table-builder artifact found by name; not
      confirmed either way from the repo (`results/` is gitignored, so a
      generated table would not be visible here regardless).
- [x] Plot `fig/exp1-throughput`. — `exp1-throughput` and `exp1-throughput-512`
      both defined in `cmd/plot/load.go` and `scripts/plot_figures.py`.

---

## Phase 3 — Experiment 2: Redaction Processing Overhead

**Figure:** x = redaction requests (100→5000); y = avg overhead, ms/request

- [x] Harness measures execution only, authorization excluded. —
      `experiments/exp2_redaction/runner.go`.
- [x] Workload size sweep 100…5000. — `workload_sizes: [100, 250, 500, 1000,
      2500, 5000]`.
- [x] Redaction batch size sweep {1,2,4,8,16,32,64}; plotted at {1,8,64}. —
      `redaction_batch.sizes: [1, 2, 4, 8, 16, 32, 64]`; `delete_set_sizes`
      mirrors it exactly, per config comment.
- [x] Waiting bound sweep {63,125,250,500} ms. — present in
      `redaction_batch.wait_bounds_ms` (derived from the block interval, per
      the config's own note).
- [x] Conflict ratio sweep {0, 0.25, 0.50}. — shared with 1.3.
- [x] Baselines run at their native operating point (B_R = 1). — config's
      `systems:` list for this experiment includes all four.
- [ ] **Decompose cost: CH.Adapt vs blockchain-side time per batch.** — the
      mechanism exists (`CryptoTime`, `LedgerTime`,`CryptoShare` in
      `runner.go`) **but is not reliably instrumented** — see the reopened
      Phase 0 blocker. `go test ./experiments/exp2_redaction/...` currently
      **FAILS**.
- [x] Record stale-exclusion rate. — `stale_exclusion_rate` metric,
      `Fresh_ρ == 0` tracked per request.
- [x] Record achieved redactions/second. — part of the same result schema.
- [x] Identify the batch size where marginal amortization gain = marginal
      staleness loss. — `res.OptimalBatchSize` in the runner; asserted by
      `TestOptimalBatchIsNotPooledAcrossConflictRatios` — **which currently
      fails for the reason above**, so this item is blocked on the same fix.
- [ ] Build `tab:exp2-decomposition`. — same caveat as `tab:exp1-scaling`: no
      table-builder found by name, and would depend on the cost-decomposition
      fix above regardless.
- [x] Plot `fig/exp2-overhead`. — defined in both plotters; restored and
      pointed at the current figure list per commit `25a2b52`.

---

## Phase 4 — Experiment 3: Provenance Retrieval and Audit Verification Cost

**Figure:** x = redactions in history ν ∈ {1,2,4,8,16} (log₂); y = audit
verification time, ms. Each scheme drawn twice: L=100 solid, L=1000 dashed.

- [ ] **Confirm Phase 0 PAI fix is in place first.** — **NOT YET, per the
      reopened Phase 0 blocker above.** `go test ./experiments/exp3_audit/...`
      currently **FAILS**: `TestExp3RunsZKRedactAcrossLedgerSizes` reports
      `claim holds: false`.
- [x] Ledgers at L = 100 and L = 1000 blocks. — `ledger_sizes: [100, 1000]`
      in `config/experiment.yaml`. (This file's own spec already said `100,
      1000` before this rewrite — it was the top-level `README.md` that
      wrongly said `1k→10k`; that is fixed separately.)
- [x] History depth sweep ν ∈ {1,2,4,8,16} at each ledger size. —
      `history_depths: [1, 2, 4, 8, 16]`.
- [x] Each scheme's own audit path implemented. — ZK-Redact
      (`internal/schemes/zkredact/audit.go`), Ref[13] (BAT challenge-response,
      `internal/schemes/ref13/audit.go`), Ref[10] (block query + EMT
      recomputation, `internal/schemes/ref10`), Ref[22] (`ValChain`,
      `internal/schemes/ref22/ledger.go`) — mapped explicitly in
      `docs/experiments.md` §4.3.
- [x] Retrieval and verification timed separately, never summed. —
      `RetrievalTime`/`VerificationTime` are distinct fields on the result
      type (confirmed in the failing test's own log output).
- [x] Evidence bytes recorded. — `EvidenceBytes` field, same source.
- [x] Auditor authorization cost measured as a separate constant adder. —
      `AuthorizationTime` field, same source; `docs/experiments.md` §4.2
      explains why it is isolated.
- [ ] **Sanity check: ZK-Redact's L=100 and L=1000 curves should be
      near-coincident.** — **THEY ARE NOT, per the live test run above.**
      Blocks traversed is flat (good); verification time is not (bad). This
      is the same item as the reopened Phase 0 blocker, listed here again
      because it is this phase's explicit stop condition.
- [ ] Build `tab:exp3-retrieval`. — not confirmed; blocked on the above regardless.
- [x] Plot `fig/exp3-audit`. — `exp3-audit` and `exp3-audit-cost` both defined
      in `cmd/plot/load.go` and `scripts/plot_figures.py`.

---

## Phase 5 — Analysis and write-up

- [ ] **Repeat each configuration ≥5 times; report median with visible
      spread.** — **NOT the current state, deliberately.** The committed
      `meta.repetitions: 1` carries an extensive derivation in
      `config/experiment.yaml` (Ref[10]'s measured CV at n=1 is 0.12-0.16%,
      which the comment argues is defensible for Ref[10] specifically) —
      but the same comment flags this as **not yet justified for ZK-Redact**,
      whose CPU-bound path (Groth16 verification under sharding) has never
      had its own variance measured, and names the open action item
      explicitly: *"Task 9's first job is to take the same variance datum for
      ZK-Redact's Exp 2 CryptoTime on the full topology and raise this if
      that CV is worse."* That task exists only in this config comment now —
      "Task 9" does not correspond to any numbered item in this file's current
      structure, since this file was reset to the Phase 0-5 format after
      whatever numbering produced "Task 9" existed. Recorded here so it is not
      lost again. **Also: at `repetitions: 1`, `cmd/plot`'s min-to-max error
      bars are skipped for every point (N < 2), so today's figures would
      carry no between-run spread at all — the config comment says this
      explicitly and the write-up must not describe the points as medians
      with spread until this changes.**
- [ ] Cross-check every measured number against Table I's complexity
      predictions. — not verified this pass; the capability matrix exists
      (`docs/experiments.md` §5) but a systematic reconciliation against
      actual measured numbers was not found and `results/` is gitignored, so
      it cannot be checked from this repo regardless.
- [x] No reported number comes from an analytical model or extrapolation, as
      a standing rule. — enforced structurally: `docs/experiments.md` §0 states
      the rule, `validate-config` checks `allow_published_numbers_in_tables ==
      false`, and every timing path in the schemes above times real execution.
      Not the same as confirming a specific published number is real — that
      is unverifiable without the actual `results/` output.
- [ ] Fill the three `[To be completed from the measurement run]` blocks in
      Section V-C. — **not found verbatim in the current manuscript**
      (`ZK-Redact_notation_revised.tex`, the newer of the two `.tex` files
      outside this repo, at `../`). The manuscript's own `\plotfig` macro
      comment says it "draws the figure once `cmd/plot` has produced the
      file, and a framed note until then" — meaning figures are still
      showing placeholders as of this pass. Re-check this item's exact
      wording against the current manuscript rather than trusting this
      line, since the phrasing may have changed with the notation revision.
- [ ] Confirm figures are legible at IEEE single-column width in greyscale
      (Exp 3 has 8 lines). — `cmd/plot/svg.go` orders error bars under
      markers per its own comment; marker/line-style differentiation not
      independently re-verified this pass.
- [ ] Archive raw results, configs, and seeds alongside the code revision. —
      **not verifiable from this repository.** `/results/` is gitignored by
      design (`.gitignore`: "regenerated from config + seed, never
      committed"); `scripts/launch-run.sh` publishes worker results to S3.
      Whether a full, final archived run exists is a fact this repo cannot
      answer — ask directly rather than trusting either a `[x]` or a `[ ]` here.

**Pre-flight, from `go run ./cmd/validate-config` against the live config
(2026-09-11): 0 errors, 3 warnings** — `meta.repetitions = 1` (see above),
`baselines.ref10_emt.vote_transport = in_process` (see Phase 1.6),
`workload.total_requests = 5000` gives fewer than 100 top-percentile samples.
None block a run; all three say today's numbers need a caveat attached.

---

## Known risks

| Risk | Mitigation |
|---|---|
| PAI root fix not landed before benchmarking | **Live, not hypothetical: `TestExp3RunsZKRedactAcrossLedgerSizes` fails today.** See Phase 0. |
| Exp 2 cost decomposition silently zero for some baselines | **Live, not hypothetical: `TestOptimalBatchIsNotPooledAcrossConflictRatios` fails today.** See Phase 0. |
| Circuit changes after key generation | Freeze circuit before Phase 1.4 — `constraint_count` is pinned and `build-zk` refuses drift (Phase 0). |
| Baseline implementations not faithful to their papers | Cross-checked in writing (`docs/paper-conformance.md`, `docs/baselines/*.md`, both corrected this pass); the automated negative-test gate (`make fidelity-check`) is still a stub — see 1.6. |
| Experiment 3 figure unreadable at 8 lines | Not independently re-verified this pass. |
| Host load drift across long sweeps | Fixed resource caps (see the 1.5 flag on `peer_cpu_limit`'s stale comment), interleaved configuration order. |
| Repetition count too low to support close comparisons | **Live, deliberately**: `repetitions: 1`. See Phase 5. |
