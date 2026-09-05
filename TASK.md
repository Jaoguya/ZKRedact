# TASK — handoff

Evaluation framework for **ZK-Redact**, comparing it against three
re-implemented baselines on one shared Hyperledger Fabric harness.

**Branch:** `main`
**Code:** ~20,400 lines Go across 66 files, plus the Fabric network
**Verified:** ✅ Go 1.27.1 — `go build` and `go vet` clean across both modules,
gofmt-clean, **190 tests (321 with subtests) passing**, `make validate-config`
clean (one WARN, `vote_transport: in_process`), and the redaction chaincode verified on a live Fabric network: smoke
10/10, the live suite green under `-race`, concurrent authorization holding at
every level from 1 to 1024, and **Exp 1 running end to end over the fabric
transport**.

⚠️ All live verification above is on the **minimal** topology, on an
8 vCPU / 8 GB macOS host. It establishes that the mechanism works; it produces
no measurements. The full topology has been brought up and deployed before, but
no experiment has run on it — see §3.5.

---

## Decisions waiting on you

Neither blocks task 7; both block the full runs.

**1. Exp 1's sweep size over fabric.** The configured sweep is 42.8 days. Cost is
`total_requests x SUM(1/c) x 6.17 s x repetitions`, and `SUM(1/c) ~ 2` across the
11 levels, so requests and repetitions trade one for one. Within a 12-hour
budget:

| block | requests | reps | hours |
|---|---|---|---|
| 2000 ms | 1,000 | 3 | **10.3** |
| 2000 ms | 500 | 3 | 5.1 |
| 1000 ms | 1,000 | 3 | 5.1 |

Measured variance says 3 repetitions is ample (CV 0.16%; 30 buys 0.06
percentage points). **p99 is the casualty**: it needs >= 10,000 requests by the
config's own stability criterion, and `p99_reliable` already reports false. p50
and p95 survive. Best settled at task 9, once ZK-Redact's own variance can be
measured — deciding now means deciding on Ref[10], the scheme with no tail.

**2. The full topology has never run an experiment.** `up full` now REFUSES
until `gateway.peer_endpoint` moves from 7051 to 11051, and it needs the EC2
host — this laptop is 8 vCPU / 8 GB. Every number recorded so far is a
correctness check on the minimal topology, not a measurement.

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

make build                      # compiles clean
make test                       # gofmt + vet + 190 tests
make validate-config            # passes; one expected WARN, see below
make build-zk                   # compiles the circuit, checks it against the config
```

> **The tree compiles**, and the chaincode runs on a real network. Deps are
> yaml.v3, `fabric-gateway` and `gnark` 0.16.3; the chaincode is a separate
> module so its Fabric contract API stays out of the main graph.
> `make validate-config` reports ONE expected WARN — `vote_transport:
> in_process`, which clears once the network is up with `fabric` selected. The
> circuit WARN is gone: `constraint_count` and `public_input_count` are measured
> and recorded (task 4).

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

**Exp 1 shows Ref[13] and Ref[22] beating ZK-Redact at low concurrency.** No
longer a prediction — Ref[22] measures 0.12 us against ZK-Redact's 1.34 ms, a
factor of ~10,000. That is correct and expected: their "authorization" is a
single key-possession check, because neither paper defines a per-request
authorization protocol. Do not invent one for them; that would be fabricating a
result. The capability matrix (generated from code, see `Capabilities()`)
carries the interpretation, and the crossover under load is the actual finding.

Two guards enforce this rather than leaving it to good intentions: the
all-granted check is gated on a scheme DECLARING `PolicyBound`, so Ref[22]
cannot be failed for honestly granting everything — and cannot dodge the check
without that declaration appearing in the capability matrix the results carry.

---

## Done ✅

| Package | What it is |
|---|---|
| `pkg/scheme` | The interface all four systems implement — the fairness contract |
| `pkg/config` | Single config schema, shared by validator and runtime |
| `pkg/crypto` | Security-level tables (curves, RSA, proof systems) + Schnorr |
| `pkg/metrics` | Exact percentiles, throughput |
| `pkg/workload` | Deterministic dataset + trace generation |
| `pkg/results` | Output with reproducibility metadata |
| `pkg/ch` | **3 chameleon hash constructions, tested** |
| `pkg/merkle` | Merkle tree + proofs, tested |
| `experiments/exp1,2,3` | All three runners |
| `cmd/validate-config` | Config gate |
| `cmd/run-experiment` | Entry point |
| `pkg/zk` | **Groth16 circuit for Phase 2**, 16445 constraints, 2 public inputs |
| `pkg/accumulator` | **Trapdoorless universal RSA accumulator**, membership + non-membership |
| `internal/gateway` | Phase 2 — auth, dedup, identity minimisation |
| `internal/pvl` | Phase 3 — sharding + batching, the standing verification layer |
| `internal/schemes/ref10` | **All five algorithms, 75 tests** — networked voting verified live |
| `internal/schemes/ref22` | **Accumulator + Algorithms 1, 2, 5-9**, wired end to end |
| `cmd/build-zk` | Compiles and measures the circuit; fails on config drift |
| `network/` | Chaincode + both topologies + smoke test, verified on a live peer |

**Three of four schemes now run Exp 1 end to end.** Only `ref13` still returns
`ErrNotImplemented`, so `-schemes` must exclude it:

```bash
go run ./cmd/run-experiment -config config/pilot.yaml -exp verification \
    -schemes zkredact,ref10_emt,ref22_shen
```

ZK-Redact's Phases 4-6 (`internal/redactor`, `internal/pai`) are not built, so
Exp 2 and Exp 3 cannot run against it yet.

### What the three measured schemes cost, per authorization

| Scheme | Authorization work | Cost |
|---|---|---|
| Ref[22] | regulator key possession | **0.12 us** |
| ZK-Redact | Groth16 verification (16445 constraints) | **1.34 ms** |
| Ref[10] | committee vote over Fabric, 3 blocks | **6.17 s** |

Those spans — ~10,000x and ~50,000,000x — are the finding, not a flaw. Each
scheme is doing what its own paper specifies, and the capability matrix carries
the interpretation. Ref[10] is the only baseline with a real distributed
authorization protocol, which is why it is Exp 1's named competitor.

---

## Remaining tasks, in order

### 0. Compile ✅ done
`go build ./...` and `go vet ./...` are clean and both test packages pass.
Re-run `make test` after every change — it is now a real gate, not an aspiration.

### 1. Schnorr signatures → `pkg/crypto` ✅ done
`pkg/crypto/schnorr.go`, 20 tests. Curve is resolved *and* level-checked in one
call — `crypto.SignatureCurve(security.signature_curve, security.target_bits)` —
so there is no path that picks a curve without checking it. `crypto.RequireHash`
refuses a `security.hash` the challenge does not implement.

Two things to keep in mind when wiring it:

- **`VerifyVotes` is deliberately linear, with no early exit.** Ref[10]'s
  `Σ = {ξ_1,…,ξ_j}` is a collection, not a cryptographic aggregate; Algorithm 3
  verifies each vote. A real aggregate scheme would make verification sublinear
  in committee size and hand Ref[10] a speedup its design does not provide.
- **The challenge binds the public key** (`e = H(R ‖ P ‖ m)`), which Schnorr'89
  does not. Recorded as a deviation in the Ref[10] spec and pinned by
  `TestChallengeBindsPublicKey` — the only test that detects its absence.

Negative tests were mutation-checked: an always-accept `Verify`, a dropped key
prefix, a fixed nonce, and a `VerifyVotes` that skips verification each make the
suite fail.

### 2. Ref[10] EMT ✅ done
Spec: [`docs/baselines/ref10-emt.md`](docs/baselines/ref10-emt.md)

All five algorithms are implemented and tested (44 tests, ten mutation checks).

| Algorithm | Where |
|---|---|
| 1 EMT verification, `H_tx = H(H_c ‖ H_w)` | `emt.go`, `Scheme.verifyEMT` |
| 2 CA validation, policy `P_C`, Eq. 6 | `voting.go`, `certAuthority.validate` |
| 3 Committee selection `RS_SHA256`, voting | `committee.go`, `runVoteRound` |
| 4 Schnorr vote signatures | `pkg/crypto` + `localTransport` |
| 5 Local redaction | `Scheme.Redact`, `ledger.applyRedaction` |

**End-to-end verified.** All three experiments now run against Ref[10] and
write results:

```bash
go run ./cmd/run-experiment -config config/pilot.yaml -exp all -schemes ref10_emt
```

`config/pilot.yaml` is a scaled-down copy for smoke-testing — the real config is
a c6i.8xlarge workload (11 concurrency levels x 30 repetitions x 10,000 requests
is 3.3M authorizations, roughly 15 elliptic-curve operations each for Ref[10]).
`-schemes` restricts the run to a subset and records the restriction in every
results file, since the other three systems still fail `Setup`.

What the first real run showed: 441 granted / 59 denied of 500 requests (11.8%,
matching the fraction of identities failing `S OR R OR V`), throughput scaling
596 -> 4240 rps to concurrency 8, `CryptoTime` 218 ms against `LedgerTime`
20.6 ms, and Exp 3 audit cost climbing with ledger size exactly as Ref[10]'s
design requires.

**Networked voting now runs** (tasks 3 and 3.5). `vote_transport: fabric` puts
ballots through endorsement and ordering against the deployed contract, and
Exp 1 completes over it. The figures quoted above came from `in_process` and are
a lower bound by a factor of ~8,000: the same authorization costs 1.7 ms
in-process and **16.3 s** over fabric, because a round waits out
`(1 + committee_size)` blocks. See §3.5 — that gap is what makes the configured
Exp 1 sweep infeasible over fabric.

Two things worth knowing before building on this:

- **`Audit` must never read `emtTx.RedactedBy`.** That field exists so the
  harness can build history of known depth during untimed setup. Reading it
  would hand Ref[10] the per-transaction index its design lacks, and Exp 3
  compares exactly that absence.
- **`crypto.VerifyVotes` has no early exit, but the vote round does.** The round
  closing on threshold is the recorded deviation (spec §2, favours Ref[10]);
  Σ re-verification in `Redact` and `Audit` must stay exhaustive.

### 3. Fabric network + chaincode ✅ done

`network/` holds the chaincode, both topologies, and the scripts.

| Piece | State |
|---|---|
| Redaction chaincode (Algorithm 3) | ✅ deployed and verified on a live peer |
| `fabricTransport` + Gateway adapter | ✅ wired into `ref10.Setup` |
| `compose.minimal.yaml` (1 org) | ✅ verification topology |
| `compose.yaml` (4 orgs × 2 peers, 3 orderers) | ✅ measurement topology; brought up and deployed, but **no experiment has run on it** |
| `scripts/smoke.sh` | ✅ 10 checks, mutation-verified |

```bash
./network/scripts/network.sh up minimal   # or: up full
./network/scripts/network.sh deploy
./network/scripts/smoke.sh
```

`vote_transport: fabric` now works, and needs the `gateway:` block in
`config/experiment.yaml`. Setup refuses `fabric` without it rather than falling
back to in-process voting, which would report a lower bound as a measurement.

Chaincode is packaged as **ccaas**, not `golang`. The `golang` type makes the
peer build an image over the Docker socket, which fails under Docker Desktop on
Windows with a broken pipe naming neither the chaincode nor the socket. Running
the contract as its own service removes the peer's build step and is what
production deployments use.

> **Still to do before recording numbers:** bring up `up full` on the EC2 host
> and set `vote_transport: fabric`. Everything verified so far is on the minimal
> topology, so Ref[10]'s Exp 1 and Exp 2 figures remain a lower bound and
> `validate-config` warns.
>
> `up full` will now **refuse** until `gateway.peer_endpoint` names a port that
> topology exposes — it is `localhost:7051` (minimal); the full topology puts
> peer0.org1 on **11051**.

> **Carried over from Exp 3.** `prepareLedger` re-runs `Setup` once per ledger
> size. That is correct — each size needs its own ledger — but it means every
> scheme must stay cheap to re-materialise. Worth watching when ZK-Redact's
> setup starts compiling circuits, since a slow `Setup` there multiplies across
> the whole ledger sweep.

### 3.5 Live-path checks — ✅ 1 and 2 done, 3 done on minimal

All three were run on macOS/arm64 (Go 1.27.1, Fabric 2.5.9, Docker Desktop)
against the **minimal** topology. They are correctness checks, not measurements:
an 8 vCPU / 8 GB laptop cannot produce Exp 1 numbers. Re-run 3 on the EC2 host
with `up full` before recording anything.

**1. Race detector on the live path ✅** — `go test -race -tags live` passes all
four live tests. No data races in the gateway session cache.

**2. Concurrency at the real levels ✅** — `TestLiveConcurrentAuthorize` now
sweeps `experiments.verification_throughput.concurrency_levels` read from the
config instead of a hardcoded `4`; `LIVE_CONCURRENCY_LEVELS` scopes it down for
a smaller host. Under `-race`, 1 → 1024: **every level 100% granted, zero
failures**. Approval rate does not move with concurrency, so rounds do not
interfere.

This is what found the gateway ceiling. At Fabric's default limit, 512 and 1024
each completed **exactly 500** authorizations and failed the rest with
`exceeding concurrency limit (500)`. A measured run would have recorded
throughput flattening at 500 and read it as the saturation point of sharding.
Both compose files now set `CORE_PEER_LIMITS_CONCURRENCY_GATEWAYSERVICE`, and
`network.sh` refuses a limit below the sweep.

**3. A real experiment through the fabric transport ✅ (minimal topology)** —
Exp 1 now runs end to end with `vote_transport: fabric`. Getting there needed
four fixes: the identity shortfall, the vote window, the replay collision, and
the gateway limit above. First run, 24 requests, 20 granted / 4 denied at every
level:

| Concurrency | auth/sec | p50 latency |
|---|---|---|
| 1 | 0.074 | 16.31 s |
| 2 | 0.147 | 16.29 s |
| 4 | 0.294 | 16.31 s |
| 8 | 0.489 | 16.31 s |

> **Verified, not assumed — and then fixed.**
> `TestLiveAuthorizationCostIsBlockTime` sweeps committee size and decomposes
> the cost. It first showed 3 -> 8.14 s, 5 -> 12.28 s, 7 -> 16.28 s: per-vote
> slope 2.03 s against a 2.00 s block, Init intercept 2.05 s. Linear, both terms
> exactly one block, ~2% overhead. The transport was wasting nothing — the cost
> was `(1 + committee_size)` sequential block waits.
>
> **But the serialization was ours, not Ref[10]'s.** Algorithm 3 does not
> serialize voting; committee members are independent nodes whose ballots belong
> in one block. Making `Collect` concurrent returned `MVCC_READ_CONFLICT`,
> because the chaincode's `Vote` tallied on every ballot and so read every
> member's ballot key.
>
> **Fixed.** The tally is now a separate `Close` transaction; `Vote` writes only
> its own ballot key and reads nothing another ballot writes. Ballots share one
> block, and a round costs a flat **3 blocks** — Init, ballots, Close —
> regardless of committee size:
>
> | committee_size | before | after |
> |---|---|---|
> | 3 | 8.14 s | **6.14 s** |
> | 5 | 12.28 s | **6.18 s** |
> | 7 | 16.28 s | **6.17 s** |
>
> Per-member slope is **0 s**, down from one full block. The test now pins that
> flatness: a non-zero slope means a read of another member's ballot has crept
> back into `Vote`. Recorded in the Ref[10] deviation list — what remains is the
> explicit `Close` (3 blocks rather than 2), which counts marginally *against*
> Ref[10].
>
> One consequence: each authorization now holds `1 + committee_size` gateway
> calls at once, so the peer's limit is `max_concurrency x (1 + committee_size)`
> = 8192, not 2048. Found the same way — concurrency 1024 quietly lost 98 of
> 1024 requests at the old limit. `network.sh` checks the new bound.

**The configured Exp 1 sweep is still not runnable over fabric.** At 6.17 s per
authorization (down from 16.3 s, a 2.6x improvement):

| | |
|---|---|
| all 11 levels, one repetition | 34 h |
| x10 repetitions | 14.3 days |
| x30 repetitions (configured) | **42.8 days** |

Cost is `total_requests x SUM(1/c) x 6.17 s x repetitions`, and `SUM(1/c) ~ 2`
across the 11 levels — so requests and repetitions trade one for one. Cutting
requests is the better lever, since the config's own comment already qualifies
it (">= 10,000 for a stable p99"):

| at 10 repetitions | |
|---|---|
| 10,000 requests | 14.3 days |
| 5,000 | 7.1 days |
| 2,000 | 2.9 days |
| 1,000 | **1.4 days** |

**A decision is still needed before the full run.** Note that p99 is the first
casualty of cutting requests — the pilot already reported
`p99_reliable: false`. p50 and p95 survive.

> **Ledger freshness.** Request ids are now tagged per replay
> (`<id>#c<level>.r<rep>`), which makes replays distinct *within* a run. They
> are deterministic, so **a second run against the same ledger collides again**.
> Bring the network up fresh (`network.sh up` clears the volumes; `deploy`
> alone does not) before each experiment run.

### 4. ZK circuits → `pkg/zk` ✅ done

Groth16 over BLS12-381 via gnark 0.16.3. The circuit is the Phase 2 relation
`R_red(x_i, w_i) = 1`.

| File | What it is |
|---|---|
| `circuit.go` | the constraint system |
| `zk.go` | Setup / Prove / Verify / BatchVerify, host-side MiMC |
| `registry.go` | credential Merkle tree over MiMC |
| `policy.go` | dataset predicates compiled to circuit terms |
| `statement.go` | x_i and eta_i = H(x_i) |
| `cmd/build-zk` | compiles, measures, and checks the config against reality |

**Measured, and recorded in the config — the last two nulls are gone:**

| | |
|---|---|
| `constraint_count` | **16445** |
| `public_input_count` | **2** |
| compile + setup | 1.8 s |

Shape comes from the config, not from the code: predicate depth 3
(`dataset.policies.predicate_depth`) and a depth-7 registry
(`dataset.identities.count` = 100). Change either and the numbers must be
re-measured — `make build-zk` now **fails** on a mismatch rather than reporting
a floor for a circuit nobody is running (mutation-checked).

Three decisions worth knowing before building Phase 3 on this:

- **Exactly two public inputs, and that is a cost decision.** Groth16
  verification is one scalar multiplication per public input, and Exp 1 measures
  that verification. Everything else about the request folds into
  `eta_i = H(x_i)`, which the verifier recomputes from the request it already
  holds. `RegistryRoot` is separate only because it is system state, not part of
  `x_i`.
- **MiMC, not SHA-256.** `pkg/merkle` stays for the PAI in Phase 5; the
  credential registry needs a hash the circuit can afford. A SHA-256 tree would
  cost tens of thousands of constraints per level and put the circuit's size
  somewhere unrelated to the scheme's design.
- **The credential leaf binds the attributes** (`leaf = H(rho ‖ A)`). Without
  it the circuit would prove "some attributes satisfy the policy" rather than
  "mine do", and any prover could invent a satisfying assignment.

**A denial is not a failure.** `NewAssignment` returns `ErrPolicyNotSatisfied` /
`ErrOutOfScope` rather than attempting a proof that cannot be built. Attempting
it would surface a denial as a constraint-solver failure — in a run,
indistinguishable from a broken circuit.

14 tests, 61 assertions including subtests. The ones that matter:

| Test | Catches |
|---|---|
| `TestAttributesAreNotPublicInputs` | the scheme quietly ceasing to be privacy-preserving |
| `TestCircuitRejectsTamperedInstances` | 11 mutations — forged credential, swapped attributes, flipped operator, replayed digest, out-of-scope location |
| `TestHostEvaluationMatchesCircuit` | host/circuit disagreement over every attribute assignment |
| `TestDigestBindsEveryStatementField` | a statement field left out of eta_i, changeable after proving |
| `TestTermSetMatchesWorkloadGenerator` | the circuit's vocabulary drifting from the dataset's |

> **The privacy test is checked semantically, not by counting.** Two different
> requesters, different attributes, different credentials, proving the same
> statement must produce byte-identical public witnesses. Moving the attributes
> to public inputs would leave every functional test passing, make verification
> *faster*, and yield a full set of plausible Exp 1 numbers for a scheme that no
> longer hides anything.

### 5. ZK-Redact internals — Phases 2 and 3 ✅, Phases 4-6 remaining

| Package | Phase | State |
|---|---|---|
| `internal/gateway` | 2 — request auth, dedup | ✅ done |
| `internal/pvl` | 3 — sharding + batching. **Core of Exp 1** | ✅ done |
| `internal/redactor` | 4 — batch execution. **Core of Exp 2** | not started |
| `internal/pai` | 5, 6 — provenance + audit. **Core of Exp 3** | not started |

**ZK-Redact now runs Exp 1 end to end.** First measured sweep, 200 requests,
103 granted / 97 denied at every configuration:

| shards | conc 1 | conc 8 | conc 32 | conc 128 |
|---|---|---|---|---|
| 1 | 127 | 1495 | 1545 | 1520 |
| 4 | 127 | 988 | 3143 | 3553 |
| 16 | 127 | 1103 | 3072 | **4062** |

auth/sec. Two things in that table are the actual mechanism working:

- **Sharding pays off only under load** — 2.7x at concurrency 128, nothing at
  concurrency 1 where there is no parallelism to exploit.
- **Sharding HURTS at concurrency 8** (988 against 1495 for a single shard).
  Spreading 8 in-flight proofs across 4 shards leaves each with too few to fill
  a batch, so they close on the wait bound instead. That trade-off is a result,
  not a defect.

#### Four things that had to be got right

**1. Proving is the requester's work and is NOT timed.** Groth16 proving
measured ~160 ms against ~1.3 ms verification. `docs/experiments.md` §2.2 scopes
ZK-Redact's authorization to "verify ZK proof, shard assignment, intra-shard
batching". Folding proving in would have reported ZK-Redact as ~100x slower and
inverted the Exp 1 comparison, while failing no test.

Handled by a new OPTIONAL `scheme.TracePreparer` interface: the runner calls
`PrepareTrace` before each timed replay. Baselines do not implement it and are
unaffected. **`Authorize` refuses an unprepared request rather than proving
inline** — a lazy fallback would put the excluded cost straight back into the
measurement with nothing to show it.

**2. Verifying one proof per call makes sharding a no-op.** The first working
run reported *identical* throughput at N = 1, 4 and 16, because there is never
more than one proof in flight to distribute. `pvl.Service` is the fix: a
standing layer that concurrent requests submit into, implementing Phase 3
Step 2's `Close(B) = (|B| = B) OR (tau >= Delta)`. Both halves are pinned by
tests — without the size rule a busy shard waits out Delta every time; without
the wait bound a half-full batch hangs and the delay is charged to verification.

**3. The all-denied guard was missing, and it fired immediately.** Exp 1 checked
for a scheme granting everything but not for one denying everything — the faster
failure of the two, since rejection is the cheapest path through any of these
schemes. ZK-Redact's first run posted **60 of 60 denied at ~13,000
"authorizations"/sec** and nothing else looked wrong. Guard added.

**4. The gateway's clock is the trace's, not the wall's.** That was the cause of
the all-denied run: `pkg/workload` stamps the trace from a fixed epoch
(2026-01-01) so runs are reproducible from the seed, and checking freshness
against `time.Now()` made every request months stale. "Now" is now anchored at
the newest request in the replay, which keeps the check doing its real job
without mutating the trace every scheme shares.

#### Also fixed here

- **The shard sweep was declared but never executed.** `ShardCounts` was passed
  in and `Point.ShardCount` existed, but the Run loop never swept it — Exp 1's
  swept variable for ZK-Redact did not run. Now swept, via a new optional
  `scheme.Resharder`; a scheme without shards is not swept over shard counts,
  the same refusal exp2 makes for batch sizes on a non-batching scheme.
- **`config.SchemeParams("zkredact")` returned an empty map**, so the scheme
  could never be set up. It now supplies shard count, batch size and wait bound,
  native-batch-verify, signature curve, payload size and queue depth. The FIRST
  value of each sweep is passed, which the config orders as the
  ablation-DISABLED arm — a runner that forgets to sweep then measures the
  unsharded, unbatched system, visibly the wrong answer, rather than silently
  reporting the best configuration as the only one.
- **`zkredact.gateway.freshness_window_ms`** added to config with its
  derivation.
- **`Reshard` avoids recompilation.** The circuit does not depend on N, so a
  sweep point costs new goroutines, not a trusted setup.

### 6. Ref[22] Shen ✅ done

| Piece | State |
|---|---|
| Double-trapdoor CH (`pkg/ch/doubletrapdoor.go`) | ✅ was already done |
| **Trapdoorless universal accumulator** (`pkg/accumulator`) | ✅ done |
| **Algorithms 1, 2, 5, 6, 7, 8, 9** (`internal/schemes/ref22/ledger.go`) | ✅ done |
| `Setup` / `Authorize` / `Redact` / `DeleteSet` / `Audit` wiring | ✅ done |

**The accumulator is real, not a hash set.** RSA over a 3072-bit modulus,
deterministic hash-to-prime representatives, and **both** membership and
non-membership witnesses — the second is what makes it universal, and it is what
lets `ValMod` prove a superseded version is gone rather than merely absent.

`TestRevertedVersionIsDetected` is the fidelity check
[`ref22-shen.md`](docs/baselines/ref22-shen.md) says carries the most weight: it
keeps a pre-redaction witness, redacts, and asserts the old witness no longer
verifies **and** that non-membership of the old version is provable. A hash-set
stand-in passes every other test in the package and fails this one.

#### Five defects found while building it

| Defect | Presented as |
|---|---|
| Bezout coefficients transposed in the non-membership witness | every non-membership proof failing, which reads as a broken accumulator rather than two swapped variables |
| Block never stored its chameleon hash `h` | "chameleon hash does not verify" on every block |
| `A` and `w` refreshed inside the CH-covered content | the chain ceasing to verify after each append |
| Blocks linked by SHA-256 of content, not by `h` | the chain breaking at the block after every redaction — precisely what a chameleon hash exists to prevent |
| `Delete` adapted the last block of a run but cleared every payload in it | deleted blocks failing CH verification |

The linkage one is the instructive one: hashing content instead of `h` compiles,
passes append and modify tests in isolation, and only fails once a redaction is
followed by a chain walk.

#### Two things that had to be got right

**`AllMembershipWitnesses` is O(n log n), not O(n²).** An RSA accumulator
invalidates every outstanding witness on any update, so Ref[22] regenerates them
after each redaction. One at a time that is O(n²) modular exponentiations, and
Exp 3 builds ledgers of 10,000 blocks — around 10^8 exponentiations of 3072-bit
integers, at which point the baseline could not be constructed, never mind
measured. RootFactor (Sander-Ta-Shma) computes exactly the same witnesses by
halving the exponent set. **An algorithmic improvement to witness generation, not
a shortcut in what the accumulator proves.**

**`ValChain` takes no cache**, and `TestValChainCostGrowsWithChainLength` runs it
twice to prove it. Its linear cost is the property Exp 3 compares against;
memoising it would make this baseline look flat, understate ZK-Redact's
advantage, and leave no other test failing.

**Ref[22] runs Exp 1 end to end.** A 20,000-block chain builds in 4m14s
(untimed setup), and authorization measures **0.12 us** — 580k to 3.7M
authorizations/sec:

| concurrency | auth/sec | p50 |
|---|---|---|
| 1 | 580,408 | 0.38 us |
| 2 | 3,692,421 | 0.12 us |
| 4 | 2,376,285 | 0.12 us |
| 8 | 1,916,168 | 0.12 us |

> **This is the expected result, not an anomaly.** Ref[22]'s authorization is
> regulator key possession — there is no per-request protocol to run, and
> `docs/experiments.md` §2.2 says so. Against ZK-Redact's 1.34 ms Groth16
> verification that is a factor of ~10,000, and against Ref[10]'s 6.17 s it is
> ~50 million. The capability matrix carries the interpretation: Ref[22] is fast
> here because it does less, and what it does not do is exactly what ZK-Redact
> claims. Inventing an authorization protocol to narrow the gap would be
> fabricating a result.

#### Two more defects, found by running it

| Defect | Presented as |
|---|---|
| `HashToPrime` searched ~177 candidates on every verification | four minutes to build a chain; at Exp 3's ledger sizes the baseline could not be constructed |
| Witnesses regenerated inside `Append` | O(n^2 log n) chain construction |

The first is fixed by publishing the search nonce, so a verifier runs ONE
primality test instead of repeating the search — standard practice for
hash-to-prime, and not a shortcut in what is proved: the verifier still confirms
the representative is prime and belongs to that element. The second by building
the chain first and computing witnesses once; redactions still regenerate
immediately, because there the cost is real.

> **The all-granted guard had to be made capability-aware.** It fired on
> Ref[22]'s first successful run — 40 of 40 granted. But Ref[22] declares
> `PolicyBound: false`, and granting everything is its honest outcome; failing
> the run would force inventing an authorization protocol for it. The guard now
> applies only to schemes that CLAIM policy-bound authorization, which a scheme
> cannot dodge without that declaration appearing in the capability matrix the
> results carry.

> **Recorded deviation.** `GenerateUntrusted` produces the modulus, so the
> generating process briefly knows its factors — it is not trapdoorless. A real
> deployment uses an RSA UFO or a multi-party ceremony. Acceptable here because
> the evaluation measures COST, and every accumulator operation's cost depends
> on the modulus size rather than on who knows its factors. The security
> argument would not survive this; the timing measurement is unchanged by it.

### 7. Ref[13] VRBC — the last scheme, and the highest risk ⬅️ **next**

Ephemeral-trapdoor CH is **done** (`pkg/ch/ephemeral.go`). Remaining: the q-ary
BAT with Pointproofs-style vector commitments over BLS12-381.

**Estimated 2-4 sessions**, against ~1-2 for a task like Ref[22]. Three reasons
the range is wider:

- **No Go implementation exists.** Pointproofs (Gorbunov et al., CCS 2020) has
  to be built from the paper: structured reference string, commitment, opening
  proofs, cross-commitment aggregation. gnark-crypto supplies BLS12-381 pairings
  and MSM, so the primitives are there — the construction is not.
- **There is nothing to test against, and that is the real risk.** With Ref[10]
  the client and the chaincode were two implementations of one thing, so golden
  vectors held both sides together. Here there is no reference output: a
  wrong-but-self-consistent construction passes every test while producing wrong
  numbers. That is this project's core failure mode in its worst form.
- **The paper may under-specify.**
  [`ref13-vrbc.md`](docs/baselines/ref13-vrbc.md) calls the vector commitment
  "the **main implementation cost**" and says it must be audited against §3.2.2.

> **Start with a spike, not the full build.** Implement only the Pointproofs
> commitment and one opening proof, check it against the paper's equations, and
> re-estimate from measured ground. Committing to a schedule before that is
> guessing.

> **`bat_arity_q` is an unpriced decision.** The spec notes redaction and audit
> costs FALL with q while append costs RISE, so "a single value can flatter or
> penalise the baseline" and it should ideally be swept. Sweeping adds work here
> and runtime to Exp 3.

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

**First variance datum (Ref[10], fabric, minimal topology, 5 repetitions):**

| concurrency | mean auth/s | stddev | CV |
|---|---|---|---|
| 1 | 0.1960 | 0.00023 | **0.12%** |
| 8 | 1.3033 | 0.00214 | **0.16%** |

Near-zero, and structurally so: Ref[10]'s cost over fabric is three block waits,
and `BatchTimeout` is a clock rather than a contended resource. SEM is
`CV/sqrt(n)`, so 3 reps gives 0.09% and 30 gives 0.03% — **30 buys 0.06
percentage points** on comparisons whose effects are hundreds of percent.

Three cautions before setting `meta.repetitions` from this:

1. **It is Ref[10] only.** Ref[10] waits on a clock; ZK-Redact's path is ZKP
   verification and sharding, which is CPU-bound and therefore sensitive to
   scheduling, cache and thermal state. The repetition count must be set by the
   **noisiest** system, and that system does not exist yet (task 5). This is why
   task 9 comes after task 5.
2. **It is the minimal topology on a laptop.** Four orgs, cross-org endorsement,
   Raft and gossip will add variance — though the cost stays block-dominated.
3. **Exp 2 and Exp 3 are unmeasured.** Exp 2's `CryptoTime` is CPU-bound and
   will not look like this.

> **Consequence for the run plan.** Parallelising repetitions across N EC2
> instances (one repetition each) is sound and cuts wall clock ~N-fold, but
> **one repetition per instance confounds run-to-run variance with
> machine-to-machine variance** — a degraded host becomes an undetectable
> outlier. Use >= 2 repetitions per instance so the two are separable, and keep
> the per-file `Hostname`/`NumCPU` fingerprint `pkg/results` already records so
> an instance effect can be tested for before pooling. It also needs a
> repetition-id flag on `run-experiment`, which does not exist: every instance
> would otherwise label its rows `repetition: 0`.

> **Nothing consumes repetitions yet.** All three runners append each repetition
> as its own `Point` and never aggregate — there is no mean, median or interval
> across repetitions anywhere. `metrics.Latency.StdDev` is within-run latency
> spread, not between-run variance. Until `cmd/plot` (task 8) computes something
> from them, extra repetitions are rows nobody reads.

### 10. Full runs + write-up

---

## Findings already made — do not re-derive

### Code breaks where it has never run

**Twenty-seven defects so far.** Every one sat on a path that compiled, passed
the tests around it, and had never actually executed — and every one failed by
pointing somewhere other than its cause:

| Defect | Presented as |
|---|---|
| Schnorr sign inverted in the chaincode | a network that never reached threshold |
| `committee_size` absent from the wire | the membership guard silently failing open |
| Member ids used as Fabric identity directories | a missing file deep in the SDK |
| Client and contract ranked committees differently | a membership bug, not a one-byte hash difference |
| `RegisterNodes` never called | a chaincode fault, not a missing setup step |
| `network.sh` hardcoded the minimal channel profile | a full run that was one org wide |
| `up` reused containers after regenerating crypto | "certificate signed by unknown authority" |
| `deploy` addressed minimal ports on the full topology | an endorsement policy failure |
| No anchor peers in the channel | "no peer combination can satisfy the policy" |
| Clock guard blocked dry runs | `make pilot` failing on every dev machine |
| Live tests reused request ids | passing once, then failing as "round already exists" |
| `network.sh`/`smoke.sh` committed non-executable | "permission denied" on a fresh clone |
| `FABRIC_BIN` defaulted to `/c/fabric/bin` | "cryptogen not found" on the host `setup-ec2.sh` had just provisioned |
| Peer gateway concurrency left at Fabric's default 500 | Exp 1 throughput flattening at ~500 — a sharding saturation knee |
| `gateway.peer_endpoint` fixed at the minimal topology's port | `up full` then dialing 7051: nothing, or a stale minimal peer whose numbers get recorded as the full topology's |
| Identity check compared `committee_size`, not the node set | network came up "ok" with 8 identities; every fabric run then failed inside `Setup` |
| `vote_window_ms` sized for in-process voting | a gRPC `DeadlineExceeded` that read as a transport fault, not as the invalid run it was |
| Exp 1 replaying one trace 330 times | "round already exists" on the second replay |
| ZK-Redact gateway checked freshness against wall-clock time | 60 of 60 denied at ~13,000 "authorizations"/sec, and nothing else looked wrong |
| PVL verified one proof per call | identical throughput at N = 1, 4 and 16 — a sharding result that was really the harness never sharding |
| Exp 1's shard sweep declared but never executed | ZK-Redact's swept variable silently not swept |
| `SchemeParams("zkredact")` returned an empty map | the scheme could never be set up at all |
| `ScalingEfficiency` divided by a single unreplicated point | one outlier at concurrency 1 shifting the whole scaling curve, uncorrectable by more repetitions |
| Bezout coefficients transposed in the non-membership witness | every non-membership proof failing — a broken accumulator, not two swapped variables |
| Ref[22] blocks linked by SHA-256 of content, not by the chameleon hash | the chain breaking at the block after every redaction, defeating the point of a chameleon hash |
| Ref[22] block never stored its chameleon hash; `A`/`w` refreshed inside CH-covered content | the chain ceasing to verify after each append |
| `HashToPrime` searched ~177 candidates on every verification | four minutes to build a chain; unbuildable at Exp 3's ledger sizes |

The lesson is procedural, not technical: **write the test that runs the path,
and run it twice.** Several of these were found only by running something a
second time, or on a topology that had been configured but never started.

Two implementations of one thing diverged three times — the Schnorr equations,
the committee ranking, and the wire format. Where the chaincode cannot import
`pkg/crypto` because it is a separate module, golden vectors held on both sides
are the only thing that keeps them together.

### The three schemes use three different chameleon hashes
This was nearly a silent error twice over. All three are implemented, and
`ch.CheckRequired` is now **called from all four `Setup` methods** — it was
previously defined but never invoked, so the mapping below was documentation
rather than enforcement. Verified by flipping an entry in `ch.Implemented` and
confirming `Setup` refuses.

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
| Scheme **claiming `PolicyBound`** granting every request → fail | `exp1` | a stub that always approves, which benchmarks beautifully. Capability-gated: Ref[13] and Ref[22] declare no policy evaluation, so granting everything is their honest outcome |
| Scheme denying every request, granting none → fail | `exp1` | rejection is the cheapest path, so an all-denying scheme posts the best numbers in the study |
| Unprepared request → `Authorize` fails | `zkredact` | the requester's ~160 ms proving cost silently re-entering the ~1.3 ms measured path |
| Non-sharding scheme swept over shard counts → not swept | `exp1` | fabricating a shard curve for a system with no shards |
| `CryptoTime == 0` with successful redactions → fail | `exp2` | cost decomposition not instrumented |
| Claims `LedgerIndependentAudit` but traverses the ledger → fail | `exp3` | a scheme contradicting its own capability declaration |
| Non-batching scheme swept over batch sizes → refused | `exp2` | fabricating a curve the scheme cannot produce |
| Ref[10] threshold not a real majority → `Setup` fails | `ref10` | an undersized committee making the main competitor look fast |
| Ref[10] `vote_transport: fabric` before the network exists → `Setup` fails | `ref10` | in-process latency being recorded as a distributed protocol's cost |
| Ref[10] `vote_transport: in_process` → validator WARN | `validate-config` | publishing a lower bound as Ref[10]'s Exp 1 result |
| Ref[10] eligible pool smaller than `committee_size` → `Setup` fails | `ref10` | a silently shrunken committee weakening the threshold |
| Ref[13] corruption rate ≠ 0.01 → `Setup` fails | `ref13` | `challenged_blocks` silently losing its 95%/99% meaning |
| Ref[22] accumulator < 3072 bits → `Setup` fails | `ref22` | a baseline benchmarked below the shared security level |
| CH construction a scheme needs not implemented → `Setup` fails | all four schemes, via `ch.CheckRequired` | a baseline silently given a cheaper chameleon hash than its paper specifies |
| `baselines.ref22_shen.accumulator_bits` ≠ `security.accumulator_bits` → error | `validate-config` | the runtime security level drifting from the documented one — `ref22.Setup` reads the baseline copy |
| Clock too coarse to resolve the measurements → run refused | `run-experiment` | a full results file of quantised, plausible-looking numbers |
| Fabric identities fewer than dataset members → `Setup` fails | `ref10` | a partial map letting some committees vote and others not |
| `vote_transport: fabric` without gateway settings → `Setup` fails | `ref10` | in-process latency reported as a networked measurement |
| Committee ranking pinned by golden vectors on both sides | `ref10` + chaincode | client and contract drawing different committees |
| Schnorr agreement pinned by golden vectors on both sides | `ref10` + chaincode | the contract rejecting every honest vote |
| Curve below `target_bits` → validation error | `validate-config` | the BN254 trap |
| `delete_set_sizes` ≠ `redaction_batch.sizes` → error | `validate-config` | two Exp 2 curves on incomparable axes |
| Shard sweep not exceeding vCPUs → error | `validate-config` | saturation knee outside the plot |
| `vote_window_ms` below `(1+committee_size) x block_timeout_ms` under `fabric` → error | `validate-config` | a window that expires mid-round, reported as a transport fault |
| Vote window expiry detected on the round's context, not the error type | `ref10` | a gateway `DeadlineExceeded` bypassing the "discard the run" path |
| Peer gateway concurrency limit below the exp1 sweep → `up` fails | `network.sh` | the peer's 500-request ceiling recorded as a sharding saturation point |
| `gateway.peer_endpoint` not a port the chosen topology exposes → `up` fails | `network.sh` | minimal-topology numbers recorded as the measurement topology's |
| Per-org identities fewer than `dataset.identities.count` → `up` fails | `network.sh` | a network that comes up "ok" and fails later inside `Setup` |
| Tree not gofmt-clean → `make test` fails | `Makefile` | formatting drift accumulating unnoticed |
| Build-tagged live suite type-checked by `make test` | `Makefile` | `-tags live` code rotting until the moment the network is up |

Sweeps that find no saturation point or no optimal batch size return **0**,
meaning *extend the sweep* — not *no optimum exists*.

---

## Open questions

| # | Question | Notes |
|---|---|---|
| 1 | Dataset: synthetic or calibrated to real data? | Currently synthetic, fixed 256B/512B payloads. Content does not affect any measured cost — only size does. Real sizes have a distribution; ours does not. Discussed but not decided. |
| 2 | Network size fixed or swept? | 4 orgs × 2 peers assumes network scaling is not a claimed result. |
| 3 | Payload sizes | Deliberately not Ref[13]'s 660 B, which measured public Ethereum, not a permissioned ledger. If the target application has known sizes, use and cite those. |

Two `[CONFIRM]` markers in the config track questions 2 and 3:
`grep -n CONFIRM config/experiment.yaml`. **Question 1 has no marker** — it is
tracked only here, so it is the one most likely to be forgotten.

---

## Layout

```
config/experiment.yaml   all parameters, each marked DERIVED/METHOD/PROPOSED/CONFIRM
docs/
  experiments.md         experiment spec + fairness contract
  paper-conformance.md   every claim vs its paper citation
  baselines/*.md         per-baseline scope, timing boundaries, deviations
pkg/                     shared libraries
  zk/                    Groth16 circuit, registry, policy compiler (Phase 2)
  accumulator/           trapdoorless universal RSA accumulator (Ref[22])
internal/
  gateway/               Phase 2 admission control
  pvl/                   Phase 3 sharded batch verification
  schemes/               the four systems under test
experiments/             one runner per experiment
cmd/                     validate-config, run-experiment, build-zk
scripts/setup-ec2.sh     host provisioning (install | verify)
network/
  chaincode/redaction/   Algorithm 3 as chaincode (separate Go module)
  compose.minimal.yaml   1 org — verification only
  compose.yaml           4 orgs x 2 peers + 3 orderers — measurement topology
  scripts/network.sh     up [minimal|full] | deploy | status | down
  scripts/smoke.sh       end-to-end checks against the deployed contract
```

## Commands

```bash
make build                                  # compile everything
make test                                   # vet + tests
make validate-config                        # config gate
make build-zk                               # compile + measure the circuit
make pilot                                  # dataset + trace, no execution
make experiment-verification-throughput     # Exp 1
make experiment-redaction-throughput        # Exp 2
make experiment-provenance-audit            # Exp 3
make experiments                            # all three

make test-live                              # live Fabric integration
./network/scripts/network.sh up minimal     # 1 org — verification only
./network/scripts/network.sh up full        # 4 orgs — measurement topology
./network/scripts/network.sh deploy
./network/scripts/smoke.sh                  # 10 checks against the deployed contract
```

`make test` stays free of Docker. `make test-live` is build-tagged so it cannot
pass quietly when no network is running.

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
