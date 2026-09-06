// Command validate-config checks config/experiment.yaml before any experiment
// runs.
//
// It exists because a bad parameter should fail in the first second, not three
// hours into a sweep — and because several config errors are silent: they do
// not crash anything, they just quietly invalidate the comparison. A pairing
// curve below the declared security level, or a baseline swept over a different
// range than ZK-Redact, produces perfectly clean numbers that mean nothing.
//
// The schema and the security tables live in pkg/config and pkg/crypto, shared
// with the runtime. Local copies would drift, and a drifted schema silently
// ignores fields — so a parameter the researcher set is not the one the run
// used.
//
// Usage:
//
//	validate-config [path]      # default: config/experiment.yaml
//
// Exit codes:
//
//	0  no errors (warnings may be present)
//	1  one or more errors — do not run experiments
//	2  file could not be read or parsed
package main

import (
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"

	"zkredact/pkg/config"
	"zkredact/pkg/crypto"
	"zkredact/pkg/zk"
)

// -----------------------------------------------------------------------------
// Findings
// -----------------------------------------------------------------------------

type severity int

const (
	sevError severity = iota
	sevWarn
	sevInfo
)

func (s severity) label() string {
	switch s {
	case sevError:
		return "ERROR"
	case sevWarn:
		return "WARN "
	default:
		return "INFO "
	}
}

type finding struct {
	sev   severity
	field string
	msg   string
	why   string // why this matters — omitted when self-evident
}

type report struct{ findings []finding }

func (r *report) errf(field, msg, why string) {
	r.findings = append(r.findings, finding{sevError, field, msg, why})
}
func (r *report) warnf(field, msg, why string) {
	r.findings = append(r.findings, finding{sevWarn, field, msg, why})
}
func (r *report) infof(field, msg string) {
	r.findings = append(r.findings, finding{sevInfo, field, msg, ""})
}

func (r *report) counts() (errs, warns int) {
	for _, f := range r.findings {
		switch f.sev {
		case sevError:
			errs++
		case sevWarn:
			warns++
		}
	}
	return
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func maxInt(xs []int) int {
	m := math.MinInt
	for _, x := range xs {
		if x > m {
			m = x
		}
	}
	return m
}

func minInt(xs []int) int {
	m := math.MaxInt
	for _, x := range xs {
		if x < m {
			m = x
		}
	}
	return m
}

func contains(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func containsStr(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func sameSet(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]int(nil), a...)
	bc := append([]int(nil), b...)
	sort.Ints(ac)
	sort.Ints(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}

func fmtInts(xs []int) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = fmt.Sprint(x)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// -----------------------------------------------------------------------------
// Checks
// -----------------------------------------------------------------------------

func checkMeta(c *config.Config, r *report) {
	if c.Meta.Seed == nil {
		r.errf("meta.seed", "not set",
			"without a fixed seed, runs are not reproducible and results cannot be regenerated")
	}
	if c.Meta.Repetitions == nil {
		r.errf("meta.repetitions", "not set", "")
	} else if *c.Meta.Repetitions < 10 {
		r.warnf("meta.repetitions",
			fmt.Sprintf("%d is below the conventional floor of 10", *c.Meta.Repetitions),
			"latency percentiles are unstable with few repetitions")
	}
}

// checkSecurityUniformity is the most important check in this program.
//
// A mismatch here does not crash anything. It produces clean, plausible numbers
// in which one system is faster purely because it was given weaker parameters.
func checkSecurityUniformity(c *config.Config, r *report) {
	if c.Security.TargetBits == nil {
		r.errf("security.target_bits", "not set",
			"every other security check is relative to this value")
		return
	}
	target := *c.Security.TargetBits

	check := func(field string, name *string, required, pairing bool) {
		if name == nil {
			if required {
				r.errf(field, "not set", "")
			}
			return
		}
		var err error
		if pairing {
			err = crypto.RequirePairingCurve(*name, target)
		} else {
			err = crypto.RequireCurve(*name, target)
		}
		if err == nil {
			// Over-provisioning is not an error, but it penalises the scheme
			// relative to the others, so it is worth surfacing.
			if bits, e := crypto.CurveBits(*name); e == nil && bits > target {
				r.warnf(field, fmt.Sprintf("%s is ~%d-bit, above target_bits=%d", *name, bits, target),
					"over-provisioning penalises this system relative to the others")
			}
			return
		}
		var unknown crypto.ErrUnknownCurve
		if errors.As(err, &unknown) {
			r.warnf(field, err.Error(),
				"add it to pkg/crypto so uniformity can be enforced")
			return
		}
		r.errf(field, err.Error(), "")
	}

	check("security.signature_curve", c.Security.SignatureCurve, true, false)
	check("security.chameleon_hash_curve", c.Security.ChameleonHashCurve, true, false)
	check("security.pairing_curve", c.Security.PairingCurve, c.Baselines.Ref13.Enabled, true)

	if c.Security.AccumulatorBits != nil {
		if err := crypto.RequireRSA(*c.Security.AccumulatorBits, target); err != nil {
			r.errf("security.accumulator_bits", err.Error(),
				"Ref[22] would be measured at a weaker level than the other systems")
		}
		// The baseline block declares its own copy, and that copy is what
		// ref22.Setup actually reads. If the two drift apart, the security
		// level enforced at runtime is not the one this file documents.
		if b := c.Baselines.Ref22.AccumulatorBits; b != nil && *b != *c.Security.AccumulatorBits {
			r.errf("baselines.ref22_shen.accumulator_bits",
				fmt.Sprintf("%d does not match security.accumulator_bits=%d",
					*b, *c.Security.AccumulatorBits),
				"the baseline copy is what ref22.Setup reads, so a mismatch means Ref[22] runs at a level this config does not state")
		}
	} else if c.Baselines.Ref22.Enabled {
		r.errf("security.accumulator_bits", "not set but ref22_shen is enabled", "")
	}

	if c.Security.ZKProofSystem == nil {
		r.errf("security.zk_proof_system", "not set",
			"this determines the Exp 1 verification floor")
		return
	}
	ps := crypto.ProofSystem(*c.Security.ZKProofSystem)
	if !ps.Valid() {
		r.errf("security.zk_proof_system",
			fmt.Sprintf("unknown proof system %q", *c.Security.ZKProofSystem), "")
		return
	}
	// The Exp 1 ablation grid sweeps native batch verification on and off. A
	// backend without batch support leaves half that grid unmeasurable, which
	// is better caught now than mid-sweep.
	wantsBatch := false
	for _, v := range c.ZKRedact.ProofBatch.NativeBatchVerify {
		if v {
			wantsBatch = true
		}
	}
	if wantsBatch && !ps.SupportsBatchVerification() {
		r.errf("security.zk_proof_system",
			fmt.Sprintf("%s does not support batch verification, but native_batch_verify includes true", ps),
			"the Phase 3 independence claim cannot be tested without both settings")
	}
}

func checkEnvironment(c *config.Config, r *report) {
	n := c.Environment.Network
	if c.Environment.VCPUs == nil {
		r.errf("environment.vcpus", "not set", "the sharding sweep is derived from this")
	}
	if n.Organizations == nil || n.PeersPerOrg == nil {
		r.errf("environment.network", "organizations/peers_per_org not set", "")
	}
	if n.BlockTimeoutMS == nil || n.BlockMaxTransactions == nil {
		r.errf("environment.network", "block parameters not set",
			"block cadence directly affects redaction commit latency")
	}
	if n.OrdererNodes != nil && *n.OrdererNodes%2 == 0 {
		r.warnf("environment.network.orderer_nodes",
			fmt.Sprintf("%d is even", *n.OrdererNodes),
			"Raft expects an odd node count for a clean majority quorum")
	}
}

// checkSharding enforces the relationship between shard count and available
// cores. Sharding is CPU parallelism: if the sweep never exceeds the core
// count, the saturation knee falls outside the plot and Exp 1's central result
// is simply not visible.
func checkSharding(c *config.Config, r *report) {
	counts := c.ZKRedact.Sharding.Counts
	if len(counts) == 0 {
		r.errf("zkredact.sharding.counts", "empty", "")
		return
	}
	if !contains(counts, 1) {
		r.errf("zkredact.sharding.counts", "does not include 1",
			"N=1 is the sharding-disabled ablation baseline; without it, no speedup can be computed")
	}
	if c.Environment.VCPUs == nil {
		return
	}
	vcpus := *c.Environment.VCPUs
	top := maxInt(counts)
	switch {
	case top < vcpus:
		r.errf("zkredact.sharding.counts",
			fmt.Sprintf("max shard count %d is below vcpus=%d", top, vcpus),
			"parallel speedup cannot saturate within the sweep, so the scaling limit will not appear in the results")
	case top == vcpus:
		r.warnf("zkredact.sharding.counts",
			fmt.Sprintf("max shard count %d exactly equals vcpus=%d", top, vcpus),
			"extend past the core count so saturation is demonstrated rather than assumed")
	default:
		r.infof("zkredact.sharding.counts",
			fmt.Sprintf("max %d exceeds vcpus=%d — saturation should be visible; if throughput still rises past %d, the harness is measuring something wrong",
				top, vcpus, vcpus))
	}
}

func checkBatching(c *config.Config, r *report) {
	pb := c.ZKRedact.ProofBatch
	rb := c.ZKRedact.RedactionBatch

	if len(pb.Sizes) > 0 && !contains(pb.Sizes, 1) {
		r.errf("zkredact.proof_batch.sizes", "does not include 1",
			"size 1 is the batching-disabled ablation")
	}
	if len(rb.Sizes) > 0 && !contains(rb.Sizes, 1) {
		r.errf("zkredact.redaction_batch.sizes", "does not include 1",
			"B_R=1 is both the batching-disabled ablation and the point where all three baselines sit")
	}
	if len(pb.NativeBatchVerify) < 2 {
		r.errf("zkredact.proof_batch.native_batch_verify",
			"must contain both false and true",
			"Phase 3 claims sharding gives parallelism independently of native batch verification; one setting cannot test that")
	}

	// Two arms that run the same code are not a comparison.
	//
	// zk.BatchVerify is currently a loop over single verifications, so
	// native_batch_verify true and false take an identical path. The sweep still
	// produces two sets of numbers, they are simply the same measurement twice —
	// and a plot would show them as a result about batch verification. Groth16
	// batching is real (n+2 pairings against 3n; see zk.BatchVerify), it is just
	// not implemented, so this is a WARN rather than an error.
	if !zk.NativeBatchVerify && contains2(pb.NativeBatchVerify, true) {
		r.warnf("zkredact.proof_batch.native_batch_verify",
			"true is configured but the backend implements no native batch verification",
			"both arms take the same code path, so the ablation distinguishes nothing; "+
				"implement zk.BatchVerify's aggregated form or drop the true arm before plotting it as a comparison")
	}

	// The same symptom reached by the other route. Aggregation needs at least
	// two proofs in a batch, so if every configured B is 1 the mode sweep runs
	// identical code however capable the backend is. Checking the backend alone
	// would miss this, and it is the harder one to see in a plot: the arms are
	// labelled differently and the numbers agree.
	if zk.NativeBatchVerify && contains2(pb.NativeBatchVerify, true) && maxInt(pb.Sizes) < 2 {
		r.errf("zkredact.proof_batch.sizes",
			"every batch size is 1, so no batch ever reaches the aggregated check",
			"the native_batch_verify arms take the same path and produce the same "+
				"measurement twice; include a size >= 2 or drop the true arm")
	}

	// Verification batching that outlives a block interval stops measuring
	// batching and starts measuring block cadence.
	if c.Environment.Network.BlockTimeoutMS != nil && len(pb.WaitBoundMS) > 0 {
		bt := *c.Environment.Network.BlockTimeoutMS
		if m := maxInt(pb.WaitBoundMS); m >= bt {
			r.warnf("zkredact.proof_batch.wait_bound_ms",
				fmt.Sprintf("max %dms >= block_timeout_ms=%dms", m, bt),
				"a verification batch spanning a block interval conflates batching with block cadence")
		}
	}
}

// checkBaselineAlignment catches the silent failure mode: baselines swept over
// ranges that do not line up with ZK-Redact's, producing curves that cannot be
// plotted against each other.
func checkBaselineAlignment(c *config.Config, r *report) {
	if c.Baselines.Ref22.Enabled {
		rb := c.ZKRedact.RedactionBatch.Sizes
		ds := c.Baselines.Ref22.DeleteSetSizes
		if len(rb) > 0 && len(ds) > 0 && !sameSet(rb, ds) {
			r.errf("baselines.ref22_shen.delete_set_sizes",
				fmt.Sprintf("%s does not match zkredact.redaction_batch.sizes %s", fmtInts(ds), fmtInts(rb)),
				"Exp 2 plots these two curves on one axis; misaligned ranges make them incomparable without any visible error")
		}
	}

	if c.Baselines.Ref13.Enabled {
		q := c.Baselines.Ref13.ArityQ
		if len(q) == 0 {
			r.errf("baselines.ref13_vrbc.arity_q", "empty", "")
		} else if len(q) == 1 {
			r.warnf("baselines.ref13_vrbc.arity_q",
				fmt.Sprintf("single value %d", q[0]),
				"q moves append cost and audit cost in opposite directions, so one fixed value lets that choice decide the outcome of Exp 2 and Exp 3 — sweep it, or justify the value explicitly in the paper")
		}
		if c.Baselines.Ref13.VectorDimensionFormula == nil {
			r.warnf("baselines.ref13_vrbc.vector_dimension_formula", "not set",
				"N is not independent: a node commits to its own data plus q children, so N = q + 1")
		}
	}
}

// checkRef10Committee verifies the fault assumption is internally consistent.
// An undersized committee makes Ref[10] — the primary Exp 1 competitor — look
// artificially fast, which is the easiest objection for a reviewer to raise.
func checkRef10Committee(c *config.Config, r *report) {
	b := c.Baselines.Ref10
	if !b.Enabled {
		return
	}
	if b.CommitteeSize == nil || b.VoteThreshold == nil {
		r.errf("baselines.ref10_emt", "committee_size/vote_threshold not set", "")
		return
	}

	// Votes that never cross the wire cost almost nothing. Ref[10] is the Exp 1
	// competitor precisely because its authorization is a distributed protocol,
	// so measuring it in-process understates the one thing it is here to
	// contribute. A warning rather than an error: in-process is the right
	// setting for developing and testing the scheme, and wrong only for
	// recording results.
	switch {
	case b.VoteTransport == nil:
		r.errf("baselines.ref10_emt.vote_transport", "not set",
			"Ref[10] must state whether votes cross the network; leaving it implicit is how in-process latency gets published as a protocol cost")
	case *b.VoteTransport == "in_process":
		r.warnf("baselines.ref10_emt.vote_transport", "in_process — votes do not cross the network",
			"Exp 1 and Exp 2 numbers for Ref[10] are a LOWER BOUND, not its cost; set fabric before recording results")
	case *b.VoteTransport != "fabric":
		r.errf("baselines.ref10_emt.vote_transport",
			fmt.Sprintf("unknown value %q", *b.VoteTransport),
			"want in_process or fabric")
	}

	// Over the fabric transport a round issues one Init plus one Vote per
	// committee member, submitted serially, and every submit waits for its
	// transaction to be ordered into a block. So the window has a hard floor of
	// (1 + committee_size) x block_timeout_ms; below it the round cannot
	// finish, whatever the protocol does.
	//
	// The window is documented as a timeout that "effectively never fires". At
	// 5000 ms against a 7-member committee and a 2 s block it fired on every
	// round — and the gateway reports the expired deadline as a gRPC status
	// error, so it read as a transport fault rather than as the invalid run it
	// is. This check is the derivation, not a guessed constant.
	if b.VoteTransport != nil && *b.VoteTransport == "fabric" &&
		b.VoteWindowMS != nil && b.CommitteeSize != nil &&
		c.Environment.Network.BlockTimeoutMS != nil {

		floor := (1 + *b.CommitteeSize) * *c.Environment.Network.BlockTimeoutMS
		if *b.VoteWindowMS < floor {
			r.errf("baselines.ref10_emt.vote_window_ms",
				fmt.Sprintf("%d ms is below the %d ms floor for the fabric transport",
					*b.VoteWindowMS, floor),
				fmt.Sprintf("a round makes 1+%d serial submits, each waiting up to "+
					"block_timeout_ms=%d for ordering; the window would expire "+
					"mid-round and the run would be invalid",
					*b.CommitteeSize, *c.Environment.Network.BlockTimeoutMS))
		}
	}
	size, thr := *b.CommitteeSize, *b.VoteThreshold

	if thr > size {
		r.errf("baselines.ref10_emt.vote_threshold",
			fmt.Sprintf("threshold %d exceeds committee size %d", thr, size),
			"no redaction could ever be approved")
	}
	if thr <= size/2 {
		r.errf("baselines.ref10_emt.vote_threshold",
			fmt.Sprintf("threshold %d is not a majority of %d", thr, size),
			"two conflicting redactions could both be approved")
	}

	if b.FaultToleranceF != nil {
		f := *b.FaultToleranceF
		if wantSize, wantThr := 3*f+1, 2*f+1; size != wantSize || thr != wantThr {
			r.warnf("baselines.ref10_emt",
				fmt.Sprintf("committee=%d threshold=%d does not match BFT sizing for f=%d (expected %d/%d)",
					size, thr, f, wantSize, wantThr),
				"the fault assumption is the justification for these numbers; if they diverge, record why")
		}
	} else {
		r.warnf("baselines.ref10_emt.fault_tolerance_f", "not set",
			"committee size and threshold need a stated fault assumption, or they are magic numbers")
	}

	if c.Environment.Network.Organizations != nil && c.Environment.Network.PeersPerOrg != nil {
		peers := *c.Environment.Network.Organizations * *c.Environment.Network.PeersPerOrg
		if size > peers {
			r.errf("baselines.ref10_emt.committee_size",
				fmt.Sprintf("committee of %d exceeds the %d available peers", size, peers),
				"the committee cannot be formed")
		}
	}
}

// checkRef13AuditDerivation guards the one value legitimately reused from a
// paper. Its justification is a derivation, and the derivation has a premise.
func checkRef13AuditDerivation(c *config.Config, r *report) {
	b := c.Baselines.Ref13
	if !b.Enabled || b.CorruptedBlockRate == nil {
		return
	}
	const assumedRate = 0.01
	if math.Abs(*b.CorruptedBlockRate-assumedRate) > 1e-9 {
		r.errf("baselines.ref13_vrbc.corrupted_block_rate",
			fmt.Sprintf("rate %.4f differs from the 0.01 assumed by challenged_blocks %s",
				*b.CorruptedBlockRate, fmtInts(b.ChallengedBlocks)),
			"challenged_blocks comes from Ateniese et al.'s PDP analysis at 1% corruption; changing the rate invalidates those sample sizes, which must be recomputed rather than carried over")
	}
}

func checkDatasetCapacity(c *config.Config, r *report) {
	ls := c.Experiments.ProvenanceAudit.LedgerSizes
	bt := c.Environment.Network.BlockMaxTransactions
	base := c.Dataset.BaseTransactions
	if len(ls) == 0 || bt == nil || base == nil {
		return
	}
	need := maxInt(ls) * *bt
	if *base < need {
		r.errf("dataset.base_transactions",
			fmt.Sprintf("%d is short of the %d needed for the largest ledger (%d blocks x %d tx)",
				*base, need, maxInt(ls), *bt),
			"the largest Exp 3 ledger cannot be built and the sweep will run short mid-experiment")
	}
}

func checkExperiments(c *config.Config, r *report) {
	// Exp 1
	if e := c.Experiments.VerificationThroughput; e.Enabled {
		if len(e.ConcurrencyLevels) == 0 {
			r.errf("experiments.verification_throughput.concurrency_levels", "empty", "")
		} else {
			if minInt(e.ConcurrencyLevels) != 1 {
				r.errf("experiments.verification_throughput.concurrency_levels",
					fmt.Sprintf("starts at %d, not 1", minInt(e.ConcurrencyLevels)),
					"the single-request point is where the trapdoor baselines legitimately win; omitting it turns the experiment into selection")
			}
			if maxInt(e.ConcurrencyLevels) < 64 {
				r.warnf("experiments.verification_throughput.concurrency_levels",
					fmt.Sprintf("max concurrency %d may be too low", maxInt(e.ConcurrencyLevels)),
					"the crossover where sharding overtakes a single serialization point must fall inside the plot")
			}
		}
		if len(e.Ablations) < 4 {
			r.warnf("experiments.verification_throughput.ablations",
				fmt.Sprintf("%d cells configured, expected 4", len(e.Ablations)),
				"sharding and batching must be separable to evaluate the Phase 3 independence claim")
		}
	}

	// Exp 2
	if e := c.Experiments.RedactionThroughput; e.Enabled {
		if e.DecomposeCost == nil || !*e.DecomposeCost {
			r.errf("experiments.redaction_throughput.decompose_cost", "must be true",
				"CH.Adapt is per-request and cannot be amortised; only blockchain-side cost can. A single aggregate timing cannot show which improved, and invites the paper to imply batching speeds up redaction cryptography")
		}
		for _, m := range []string{"ch_adapt_time", "blockchain_time_per_batch", "stale_exclusion_rate"} {
			if !containsStr(e.Metrics, m) {
				r.errf("experiments.redaction_throughput.metrics",
					fmt.Sprintf("missing %q", m),
					"required to separate the amortisable cost from the floor, and to price the staleness trade-off")
			}
		}
	}

	// Exp 3
	if e := c.Experiments.ProvenanceAudit; e.Enabled {
		if len(e.LedgerSizes) < 2 {
			r.errf("experiments.provenance_audit.ledger_sizes",
				"needs at least two sizes", "flat cannot be distinguished from linear at a single point")
		} else {
			ratio := float64(maxInt(e.LedgerSizes)) / float64(minInt(e.LedgerSizes))
			if ratio < 10 {
				r.errf("experiments.provenance_audit.ledger_sizes",
					fmt.Sprintf("spans only %.1fx", ratio),
					"separating O(1) from O(n) convincingly needs at least one order of magnitude")
			}
		}
		if len(e.HistoryDepths) < 2 {
			r.warnf("experiments.provenance_audit.history_depths",
				"needs at least two depths",
				"the second plot shows cost scaling with the target's own history")
		}
	}
}

func checkWorkload(c *config.Config, r *report) {
	if c.Workload.TotalRequests == nil {
		r.errf("workload.total_requests", "not set", "")
	} else if *c.Workload.TotalRequests < 10000 {
		r.warnf("workload.total_requests",
			fmt.Sprintf("%d gives fewer than 100 samples in the top percentile", *c.Workload.TotalRequests),
			"reported p99 will be noise")
	}
	if c.Workload.TargetDistribution == "zipf" && c.Workload.ZipfS == nil {
		r.errf("workload.zipf_s", "required when target_distribution is zipf", "")
	}
	if c.Workload.TargetDistribution != "uniform" && c.Workload.TargetDistribution != "zipf" {
		r.errf("workload.target_distribution",
			fmt.Sprintf("unknown value %q", c.Workload.TargetDistribution), "")
	}
	if len(c.Workload.ConflictRatios) > 0 {
		hasZero := false
		for _, v := range c.Workload.ConflictRatios {
			if v == 0 {
				hasZero = true
			}
			if v < 0 || v > 1 {
				r.errf("workload.conflict_ratios",
					fmt.Sprintf("%.2f is outside [0,1]", v), "")
			}
		}
		if !hasZero {
			r.warnf("workload.conflict_ratios", "does not include 0.0",
				"the zero-conflict case isolates the fully independent path")
		}
	}
}

func checkOutput(c *config.Config, r *report) {
	rec := c.Output.Record
	required := map[string]*bool{
		"resolved_config":         rec.ResolvedConfig,
		"seed":                    rec.Seed,
		"dataset_id":              rec.DatasetID,
		"git_commit":              rec.GitCommit,
		"environment_fingerprint": rec.EnvironmentFingerprint,
		"timestamp":               rec.Timestamp,
	}
	keys := make([]string, 0, len(required))
	for k := range required {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if v := required[k]; v == nil || !*v {
			r.errf("output.record."+k, "must be true",
				"a result that cannot be regenerated is not publishable under the reproducibility rule")
		}
	}
	if c.Output.AllowPublishedNumbers != nil && *c.Output.AllowPublishedNumbers {
		r.errf("output.allow_published_numbers_in_tables", "must be false",
			"the reference papers' figures come from different languages, hardware and platforms — Ref[22] disabled PoW and excluded communication on a 2 GB VM — so they cannot share a table with ours")
	}
}

func checkPendingMeasurements(c *config.Config, r *report) {
	if c.ZKRedact.Circuit.ConstraintCount == nil || c.ZKRedact.Circuit.PublicInputCount == nil {
		r.warnf("zkredact.circuit", "constraint_count/public_input_count not yet recorded",
			"these are outputs of `make build-zk`, not choices — fill them in after building so the Exp 1 verification floor stays reproducible")
	}
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

func main() {
	path := config.DefaultPath
	if len(os.Args) > 1 {
		path = os.Args[1]
	}

	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	r := &report{}
	checkMeta(cfg, r)
	checkSecurityUniformity(cfg, r)
	checkEnvironment(cfg, r)
	checkSharding(cfg, r)
	checkBatching(cfg, r)
	checkBaselineAlignment(cfg, r)
	checkRef10Committee(cfg, r)
	checkRef13AuditDerivation(cfg, r)
	checkDatasetCapacity(cfg, r)
	checkExperiments(cfg, r)
	checkWorkload(cfg, r)
	checkOutput(cfg, r)
	checkPendingMeasurements(cfg, r)

	fmt.Printf("validate-config: %s (version %s)\n\n", path, cfg.Meta.ConfigVersion)

	for _, sev := range []severity{sevError, sevWarn, sevInfo} {
		for _, f := range r.findings {
			if f.sev != sev {
				continue
			}
			fmt.Printf("%s %s\n        %s\n", f.sev.label(), f.field, f.msg)
			if f.why != "" {
				fmt.Printf("        why: %s\n", f.why)
			}
			fmt.Println()
		}
	}

	errs, warns := r.counts()
	fmt.Printf("%d error(s), %d warning(s)\n", errs, warns)
	if errs > 0 {
		fmt.Println("\nDo not run experiments until the errors above are resolved.")
		os.Exit(1)
	}
	fmt.Println("\nConfig is valid.")
}

// contains2 reports whether a bool slice holds v.
func contains2(xs []bool, v bool) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
