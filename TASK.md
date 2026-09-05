# TASK — handoff

Evaluation framework for **ZK-Redact**, comparing it against three
re-implemented baselines on one shared Hyperledger Fabric harness.

**Branch:** `main`
**Code:** ~14,000 lines Go across 41 files, plus the Fabric network
**Verified:** ✅ Go 1.27.1 — `go build` and `go vet` clean across both modules,
149 tests passing, `make validate-config` clean, and the redaction chaincode
verified on a live Fabric network on **both topologies**: smoke 10/10 on each,
and the Go client's fabric vote path passing end to end against four
organisations with cross-org endorsement.

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
make test                       # vet + 149 tests
make validate-config            # passes; one expected WARN, see below
```

> **The tree compiles**, and the chaincode runs on a real network. Deps are
> yaml.v3 plus `fabric-gateway`; the chaincode is a separate module so its
> Fabric contract API stays out of the main graph. `make validate-config`
> reports two expected WARNs — the ZK circuit's `constraint_count` /
> `public_input_count`, which clear once `make build-zk` measures them, and
> `vote_transport: in_process`, which clears once the network is up with
> `fabric` selected.

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
| `pkg/crypto` | Security-level tables (curves, RSA, proof systems) + Schnorr |
| `pkg/metrics` | Exact percentiles, throughput |
| `pkg/workload` | Deterministic dataset + trace generation |
| `pkg/results` | Output with reproducibility metadata |
| `pkg/ch` | **3 chameleon hash constructions, tested** |
| `pkg/merkle` | Merkle tree + proofs, tested |
| `experiments/exp1,2,3` | All three runners |
| `cmd/validate-config` | Config gate |
| `cmd/run-experiment` | Entry point |
| `internal/schemes/ref10` | **All five algorithms, 75 tests** — networked voting verified live |
| `network/` | Chaincode + both topologies + smoke test, verified on a live peer |

The other three schemes — `zkredact`, `ref13`, `ref22` — have real structure and
real parameter validation, but their cryptography still returns
`ErrNotImplemented`. Only Ref[10] runs end to end today, which is why
`-schemes ref10_emt` is needed to execute anything.

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

**Networked voting is wired** (task 3). `vote_transport: fabric` runs ballots
through endorsement and ordering against the deployed contract. The figures
quoted above came from `in_process`, so they remain a lower bound until a run
on the full topology with `fabric` selected replaces them.

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
| `compose.yaml` (4 orgs × 2 peers, 3 orderers) | ✅ measurement topology, **not yet run** |
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
> and set `vote_transport: fabric`. Until then Ref[10]'s Exp 1 and Exp 2 figures
> remain a lower bound, and `validate-config` warns.

> **Carried over from Exp 3.** `prepareLedger` re-runs `Setup` once per ledger
> size. That is correct — each size needs its own ledger — but it means every
> scheme must stay cheap to re-materialise. Worth watching when ZK-Redact's
> setup starts compiling circuits, since a slow `Setup` there multiplies across
> the whole ledger sweep.

### 3.5 Run these on AWS before starting task 4 ⬅️ **do this first**

Three things cannot be checked on a Windows laptop, and every defect this
project has hit so far lived where the code had never actually run. Task 4 adds
the largest new component in the project, so close these before the surface
grows.

```bash
./scripts/setup-ec2.sh && source ~/.bashrc
make build && make test && make validate-config
./network/scripts/network.sh up full
./network/scripts/network.sh deploy
./network/scripts/smoke.sh
```

Then, in order:

**1. Race detector on the live path.** Needs cgo, which the Windows host had no
compiler for. The fabric transport caches one gateway per member behind a
mutex, and Exp 1 drives it from up to 1024 goroutines.

```bash
go test -race -tags live ./internal/schemes/ref10/ -run TestLive -v
```

A race here is not a crash you would notice — it is corrupted ballots partway
through a sweep.

**2. Concurrency at the real levels.** `TestLiveConcurrentAuthorize` uses 4,
which was enough to show requests overlap rather than queue. It is not enough
to show the transport holds at 64, 256 or 1024. Raise the constant and run it
at the levels `experiments.verification_throughput.concurrency_levels` actually
uses.

Watch for: rounds interfering (approval rate should not move with concurrency),
gateway connections exhausting the peer, and endorsement timeouts that read as
latency rather than as failures.

**3. A real experiment through the fabric transport.** No experiment has ever
run with `vote_transport: fabric` — only single authorizations and the
four-way concurrency test.

```bash
# in config/experiment.yaml: vote_transport: fabric
make experiment-verification-throughput
```

The clock guard refuses this on a coarse-clock host, so EC2 is the first place
it can happen. Expect it to be slow: one authorization took ~10s against the
minimal topology, and the full config is 11 concurrency levels x 30 repetitions
x 10,000 requests. Start from `config/pilot.yaml`.

**Until all three pass, Ref[10]'s Exp 1 and Exp 2 numbers remain a lower
bound.** The in-process figures already in this file were measured without a
network.

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

### Code breaks where it has never run

Eleven defects have been found in this component. Every one sat on a path that
compiled, passed the tests around it, and had never actually executed — and
every one failed by pointing somewhere other than its cause:

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
| Scheme granting every request, denying none → fail | `exp1` | a stub that always approves, which benchmarks beautifully |
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
internal/schemes/        the four systems under test
experiments/             one runner per experiment
cmd/                     validate-config, run-experiment
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
