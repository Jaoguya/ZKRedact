# validate-config

Validates `config/experiment.yaml` before any experiment runs.

```bash
go run ./cmd/validate-config                      # default path
go run ./cmd/validate-config path/to/config.yaml
```

| Exit code | Meaning |
|---|---|
| 0 | No errors. Warnings may still be present. |
| 1 | Errors found — **do not run experiments** |
| 2 | File unreadable or unparseable |

---

## Why this exists

Two reasons, and the second is the important one.

**Fail fast.** A missing parameter should surface in the first second, not three
hours into a sweep.

**Catch the silent failures.** Several config errors do not crash anything. They
produce clean, plausible numbers that quietly mean nothing:

| Error | What you would see |
|---|---|
| Pairing curve below the declared security level | Ref[13] simply looks faster. Nothing indicates why. |
| `delete_set_sizes` misaligned with `redaction_batch.sizes` | Two Exp 2 curves plotted on incomparable axes. Both look fine. |
| Shard sweep never exceeding vCPU count | The saturation knee falls outside the plot. The curve looks linear. |
| `corrupted_block_rate` changed away from 0.01 | `challenged_blocks` silently stops meaning 95%/99% detection. |
| Committee smaller than its stated fault assumption | Ref[10] looks faster than its own design allows. |

Every one of these makes some system look better than a fair comparison permits.
None of them throws an error at runtime. That is what this tool is for.

---

## Checks performed

**Security uniformity** — the most consequential group. Every curve is looked up
against `security.target_bits`. Anything below target is an error.

> BN254 is called out specifically. It was quoted at 128-bit for years until the
> Kim–Barbulescu exTNFS improvements (2016) reduced it to roughly 100–110 bits.
> Much ZK tooling still defaults to it, so an accidental BN254 is easy to
> introduce and impossible to spot in the results.

**Sharding vs. hardware** — `sharding.counts` must include 1 (the ablation
baseline) and must exceed `environment.vcpus`, so saturation is demonstrated
rather than assumed.

**Batching ablations** — `proof_batch.sizes` and `redaction_batch.sizes` must
include 1; `native_batch_verify` must contain both settings, or the Phase 3
independence claim goes untested.

**Baseline alignment** — Ref[22]'s delete-set sizes must match ZK-Redact's batch
sizes exactly. Ref[13]'s `arity_q` warns when fixed to a single value, since `q`
moves append cost and audit cost in opposite directions.

**Ref[10] committee sizing** — threshold must be a real majority and must not
exceed the committee; committee must fit the available peers; and if
`fault_tolerance_f` is set, the `3f+1` / `2f+1` relationship is checked.

**Ref[13] audit derivation** — `challenged_blocks` is the one value legitimately
reused from a paper, and its justification is a derivation with a premise: 1%
corruption. Changing `corrupted_block_rate` without recomputing the sample sizes
is an error.

**Dataset capacity** — `base_transactions` must cover
`max(ledger_sizes) × block_max_transactions`, or Exp 3 runs short mid-sweep.

**Experiment integrity** — concurrency must start at 1 (the regime where the
trapdoor baselines legitimately win); `decompose_cost` must be true; ledger sizes
must span at least one order of magnitude.

**Reproducibility** — every `output.record.*` flag must be true, and
`allow_published_numbers_in_tables` must be false.

**Repetition floor and sample size** — `meta.repetitions` below 10 warns
(the Status section above shows the current config is at 1, deliberately);
`workload.total_requests` too small for the top percentile you're reporting
also warns. Neither blocks a run; both say the result you get needs the
caveat attached.

---

## Dependencies

Flagged per [`SKILL.md`](../../SKILL.md), which requires any dependency beyond
the declared toolchain to be documented here.

| Dependency | Version | Purpose |
|---|---|---|
| `gopkg.in/yaml.v3` | v3.0.1 | YAML parsing |

No YAML parser ships in the Go standard library. `yaml.v3` is the de facto
standard and is already required by any component that reads the shared config,
so this adds nothing the project would not need regardless.

---

## Status

Built, compile-tested, and wired into the Makefile (`validate-config:` runs
`go run ./cmd/validate-config $(CONFIG)` and every experiment target depends
on it). Run against the committed `config/experiment.yaml`, checked
2026-09-11:

```
0 error(s), 3 warning(s)
Config is valid.
```

The three warnings are real and currently live, not stale — each says the
committed config is tuned for a budget-conscious variance-measurement run,
not yet a final one:

| Warning | What it means |
|---|---|
| `meta.repetitions = 1`, below the floor of 10 | Deliberate, per `config/experiment.yaml`'s own derivation — a 30-repetition floor was rejected as "the digit, not the derivation" once Ref[10]'s measured CV (0.12-0.16%) showed one sample was defensible for it. **Not yet shown for ZK-Redact**, whose CPU-bound path has never had its variance measured; raising `repetitions` if that CV is worse is the config's own open item. |
| `baselines.ref10_emt.vote_transport = in_process` | The committed config measures Ref[10]'s **lower bound**, not its deployed cost. Set to `fabric` before recording the numbers this repo reports as final. |
| `workload.total_requests = 5000` gives < 100 top-percentile samples | p99 will read as noise at this sample size. |

---

## Adding to the Makefile

```make
.PHONY: validate-config
validate-config:
	go run ./cmd/validate-config

# Gate every experiment behind validation
experiments: validate-config
	...
```

Wiring it as a prerequisite of the experiment targets is the point — validation
that has to be remembered is validation that gets skipped.
