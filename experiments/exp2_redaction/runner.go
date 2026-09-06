// Package exp2_redaction runs Experiment 2: Redaction Throughput.
//
// Question: how much per-request blockchain cost does batch-oriented processing
// amortise, where does the benefit stop, and what does it cost in staleness?
//
// The experiment is NOT named after batching. No baseline batches, so a
// batching-named experiment would have no participants — it would measure
// ZK-Redact's own feature alone. Named after the shared operation instead, the
// baselines become the natural B_R=1 point on the same axis.
//
// The measurement that matters is the cost DECOMPOSITION. Phase 4 is explicit
// (ZK-Redact.md:645-647): CH adaptation is per-request, while batching amortises
// chaincode, validation, commitment and ledger processing. Reporting one
// aggregate duration would make it impossible to say which part improved, and
// would let the paper imply batching accelerates redaction cryptography. It does
// not, and the scheme never claims it does.
package exp2_redaction

import (
	"context"
	"fmt"
	"time"

	"zkredact/pkg/scheme"
)

// Config parameterises one Exp 2 run. Values come from config/experiment.yaml.
type Config struct {
	// BatchSizes must include 1: both the batching-disabled ablation and the
	// point where every baseline sits.
	BatchSizes []int

	// WaitBoundsMS is Delta_R, the staleness knob. Longer waits amortise better
	// but strand more requests on freshness revalidation.
	WaitBoundsMS []int

	// ConflictRatios exercise the serialization rule: same-target requests must
	// serialise while independent ones proceed in parallel.
	//
	// SWEPT, which needs a fresh trace per ratio — the ratio is a property of
	// how the trace is generated, not a knob applied to an existing one. See
	// TraceFor.
	ConflictRatios []float64

	// TraceFor returns the request trace generated at one conflict ratio.
	//
	// Required. Exp 2's stated purpose is the amortisation of blockchain cost
	// AND its staleness price, and conflict rate is a primary driver of
	// staleness: same-target requests must serialise, so a batch containing
	// them strands more work on freshness revalidation. Measuring only at 0
	// samples precisely the regime where staleness is least likely, which is
	// the regime least able to show the effect being measured.
	//
	// One trace per ratio, shared across schemes, so the "same trace, same
	// order, every system" rule still holds within each ratio.
	TraceFor func(conflictRatio float64) ([]*scheme.Request, error)

	Repetitions int

	// Rebuild re-runs a scheme's Setup under swept SETUP-time parameters —
	// Ref[13]'s arity_q, which decides the BAT's shape and so the length of the
	// path every redaction updates.
	//
	// WHY EXP 2 NEEDS THIS. q trades costs in OPPOSITE directions: append cost
	// rises with it while redaction cost falls. config/experiment.yaml says as
	// much, and that any single value "would let our choice decide the outcome
	// of Exp 2 and Exp 3". Measuring one arity would report a number we picked
	// rather than one the design produces.
	//
	// Unlike Exp 1's Reshard this cannot be done in place — the tree shape
	// depends on it — so Setup is re-run. That costs the comparison nothing,
	// since Setup is untimed for every scheme.
	//
	// Optional: nil means no setup sweep is possible.
	Rebuild func(ctx context.Context, s scheme.Scheme, overrides map[string]any) error

	// SetupSweeps reports the swept setup-parameter combinations for one scheme.
	// A scheme without such a knob must get exactly one entry, or it would be
	// measured repeatedly under labels meaningless for it and the duplicates
	// would read as variance.
	SetupSweeps func(s scheme.Scheme) ([]map[string]any, error)
}

// Point is one measured configuration.
type Point struct {
	Scheme        string  `json:"scheme"`
	BatchSize     int     `json:"batch_size"`
	WaitBoundMS   int     `json:"wait_bound_ms"`
	ConflictRatio float64 `json:"conflict_ratio"`
	Repetition    int     `json:"repetition"`

	// SetupParams records the swept setup-time parameters this point was
	// measured under — Ref[13]'s arity_q. Empty for a scheme without one.
	// Without it the arity curves would be indistinguishable in the results.
	SetupParams map[string]any `json:"setup_params,omitempty"`

	// Counts
	Requested     int `json:"requested"`
	Succeeded     int `json:"succeeded"`
	StaleExcluded int `json:"stale_excluded"`
	Failed        int `json:"failed"`

	// Decomposed cost. CryptoTime grows linearly with batch size and is the
	// floor batching cannot go below; LedgerTime is roughly constant per batch
	// and is the only part that amortises.
	//
	// Named crypto_time_ns, not ch_adapt_time_ns: Ref[10] uses no chameleon
	// hash at all, so a CH-specific name would report it as doing work its
	// design does not contain. What this measures is per-request cryptography,
	// whatever form each scheme's takes — CH adaptation for ZK-Redact, Ref[13]
	// and Ref[22]; signature re-verification and hash recomputation for Ref[10].
	CryptoTime time.Duration `json:"crypto_time_ns"`
	LedgerTime time.Duration `json:"blockchain_time_per_batch_ns"`
	TotalTime  time.Duration `json:"total_time_ns"`

	// Derived
	CostPerRequest     time.Duration `json:"cost_per_request_ns"`
	RedactionsPerSec   float64       `json:"redactions_per_second"`
	StaleExclusionRate float64       `json:"stale_exclusion_rate"`

	// CryptoShare is CryptoTime / TotalTime. As batching improves, this rises
	// toward 1 — the point at which further batching cannot help, because all
	// remaining cost is the irreducible per-request crypto.
	CryptoShare float64 `json:"crypto_share"`
}

// Result is the full Exp 2 output.
type Result struct {
	Points []Point `json:"points"`

	// OptimalBatchSize per scheme: the batch size where marginal amortisation
	// gain stops exceeding marginal staleness loss. Zero when no optimum was
	// found inside the swept range, which means the sweep should be extended
	// rather than an optimum assumed.
	OptimalBatchSize map[string]int `json:"optimal_batch_size"`
}

// Run executes Experiment 2.
//
// Schemes must already be set up. Each scheme authorizes the shared trace with
// its OWN mechanism before measurement begins — an Authorization carries
// scheme-specific evidence (a ZK proof, an aggregate signature, a key token),
// so one scheme's authorizations are not valid input to another's Redact.
//
// That authorization pass is NOT timed. It was Exp 1; charging it again here
// would overstate what batching achieves.
func Run(
	ctx context.Context,
	cfg Config,
	schemesUnderTest []scheme.Scheme,
) (*Result, error) {
	if len(cfg.BatchSizes) == 0 {
		return nil, fmt.Errorf("exp2: no batch sizes configured")
	}
	if !containsInt(cfg.BatchSizes, 1) {
		return nil, fmt.Errorf(
			"exp2: batch_sizes must include 1 — it is the batching-disabled " +
				"ablation and the point where every baseline sits")
	}
	if cfg.Repetitions < 1 {
		return nil, fmt.Errorf("exp2: repetitions must be >= 1, got %d", cfg.Repetitions)
	}
	if cfg.TraceFor == nil {
		return nil, fmt.Errorf(
			"exp2: TraceFor is required — the conflict ratio is a property of trace " +
				"generation, so the sweep cannot run against one fixed trace")
	}
	if len(cfg.ConflictRatios) == 0 {
		return nil, fmt.Errorf("exp2: no conflict ratios configured")
	}

	// One trace per ratio, built once and shared by every scheme, so within a
	// ratio all four still see identical requests in identical order.
	type ratioTrace struct {
		ratio float64
		trace []*scheme.Request
	}
	traces := make([]ratioTrace, 0, len(cfg.ConflictRatios))
	for _, ratio := range cfg.ConflictRatios {
		t, err := cfg.TraceFor(ratio)
		if err != nil {
			return nil, fmt.Errorf("exp2: trace at conflict ratio %v: %w", ratio, err)
		}
		if len(t) == 0 {
			return nil, fmt.Errorf("exp2: empty request trace at conflict ratio %v", ratio)
		}
		traces = append(traces, ratioTrace{ratio: ratio, trace: t})
	}

	res := &Result{OptimalBatchSize: make(map[string]int)}

	for _, s := range schemesUnderTest {
		// Setup-time sweeps for this scheme; one empty entry when it has none.
		sweeps := []map[string]any{nil}
		if cfg.SetupSweeps != nil {
			got, err := cfg.SetupSweeps(s)
			if err != nil {
				return nil, fmt.Errorf("exp2: setup sweeps for %s: %w", s.Name(), err)
			}
			if len(got) > 0 {
				sweeps = got
			}
		}

		schemeStart := len(res.Points)

		for _, overrides := range sweeps {
			if overrides != nil {
				if cfg.Rebuild == nil {
					return nil, fmt.Errorf(
						"exp2: %s has swept setup parameters but no Rebuild hook, "+
							"so the sweep would be declared and never executed", s.Name())
				}
				if err := cfg.Rebuild(ctx, s, overrides); err != nil {
					return nil, fmt.Errorf("exp2: rebuilding %s: %w", s.Name(), err)
				}
			}

			// A scheme that does not batch is measured once, at B_R=1. Sweeping
			// it across batch sizes would fabricate a curve it has no mechanism
			// to produce.
			sizes := cfg.BatchSizes
			if !s.Capabilities().BatchRedaction {
				sizes = []int{1}
			}

			for _, rt := range traces {
				for _, size := range sizes {
					for _, wait := range waitsFor(cfg.WaitBoundsMS, s) {
						for rep := 0; rep < cfg.Repetitions; rep++ {
							// RE-AUTHORIZED FOR EVERY CONFIGURATION, not once per
							// scheme.
							//
							// A redaction advances its transaction's version, and
							// an authorization carries the version it was granted
							// against. So the previous configuration's redactions
							// invalidate this configuration's authorizations:
							// every request fails Fresh_i and is counted as stale
							// rather than executed.
							//
							// Authorizing once produced a sweep in which only the
							// FIRST point measured a redaction. Every later point
							// reported 100% staleness, zero CryptoTime and a cost
							// per request derived from no work at all — for
							// ZK-Redact, Ref[13] and Ref[22] alike, since all three
							// revalidate state. The batch-size curve, which is what
							// Exp 2 exists to produce, was built from configurations
							// that redacted nothing. Ref[10] was unaffected only
							// because it performs no freshness check, which meant
							// the one scheme that could not detect the problem was
							// the one that looked healthy.
							//
							// NOT TIMED, so this costs the comparison nothing but
							// wall clock. It is not free wall clock: for ZK-Redact
							// it is one Groth16 proof per request per configuration,
							// because the statement binds the transaction version
							// and a new version needs a new proof. That is the real
							// cost of the workload, not an artefact of the harness.
							authorized, err := authorizeAll(ctx, s, rt.trace)
							if err != nil {
								return nil, fmt.Errorf("exp2: pre-authorization for %s: %w", s.Name(), err)
							}
							if len(authorized) == 0 {
								return nil, fmt.Errorf(
									"exp2: %s authorized none of %d requests at batch size %d, "+
										"conflict ratio %v; there is nothing to redact",
									s.Name(), len(rt.trace), size, rt.ratio)
							}

							p, err := runOne(ctx, s, authorized, size, wait)
							if err != nil {
								return nil, fmt.Errorf("exp2: %s at batch %d, conflict %v: %w",
									s.Name(), size, rt.ratio, err)
							}
							p.Repetition = rep
							p.SetupParams = overrides
							p.ConflictRatio = rt.ratio
							res.Points = append(res.Points, p)
						}
					}
				}
			}
		}

		// Optimal batch size is found within this scheme's own points, AT ONE
		// CONFLICT RATIO.
		//
		// findOptimalBatch aggregates by batch size alone, so handing it points
		// from several ratios would average an optimum that genuinely moves
		// with conflict — more conflict strands more work on revalidation, so
		// the batch size where staleness starts costing more than amortisation
		// saves is not the same number. Averaging them reports a batch size that
		// is optimal at no ratio at all. The same argument the arity comment
		// makes about tree shapes.
		//
		// The baseline ratio is the lowest configured one, which
		// config/experiment.yaml describes as isolating the fully independent
		// path. Every point is retained, so the per-ratio optima are recoverable.
		baseline := cfg.ConflictRatios[0]
		for _, r := range cfg.ConflictRatios {
			if r < baseline {
				baseline = r
			}
		}
		atBaseline := make([]Point, 0, len(res.Points)-schemeStart)
		for _, p := range res.Points[schemeStart:] {
			if p.ConflictRatio == baseline {
				atBaseline = append(atBaseline, p)
			}
		}
		res.OptimalBatchSize[s.Name()] = findOptimalBatch(atBaseline, s.Name())
	}
	return res, nil
}

// authorizeAll runs the shared trace through one scheme's own authorization
// path, returning only the granted requests.
//
// Not timed. Denials are expected and are simply excluded — a request the
// scheme refuses is not a redaction it can be asked to execute.
//
// PrepareTrace runs first for any scheme that needs it. ZK-Redact's Authorize
// REFUSES an unprepared request rather than proving inline, so without this
// call Exp 2 could not authorize a single ZK-Redact request — and the refusal
// is deliberate: proving inside Authorize would charge the measurement for the
// requester's work. Only Exp 1 called it before, which is why the gap survived
// until ZK-Redact's Redact existed to be driven.
func authorizeAll(ctx context.Context, s scheme.Scheme, trace []*scheme.Request) ([]*scheme.Authorization, error) {
	if prep, ok := s.(scheme.TracePreparer); ok {
		if err := prep.PrepareTrace(ctx, trace); err != nil {
			return nil, fmt.Errorf("preparing the trace for %s: %w", s.Name(), err)
		}
	}

	out := make([]*scheme.Authorization, 0, len(trace))
	for _, req := range trace {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		a, err := s.Authorize(ctx, req)
		if err != nil {
			return nil, err
		}
		if a.Granted {
			out = append(out, a)
		}
	}
	return out, nil
}

// waitsFor returns the wait bounds applicable to a scheme. Schemes without
// batching have no wait bound, so they are measured once at zero.
func waitsFor(waits []int, s scheme.Scheme) []int {
	if !s.Capabilities().BatchRedaction || len(waits) == 0 {
		return []int{0}
	}
	return waits
}

// runOne executes the full authorized set through one scheme at one batch size.
func runOne(
	ctx context.Context,
	s scheme.Scheme,
	authorized []*scheme.Authorization,
	batchSize, waitMS int,
) (Point, error) {
	p := Point{
		Scheme:      s.Name(),
		BatchSize:   batchSize,
		WaitBoundMS: waitMS,
		Requested:   len(authorized),
	}

	start := time.Now()
	for i := 0; i < len(authorized); i += batchSize {
		end := i + batchSize
		if end > len(authorized) {
			end = len(authorized)
		}

		select {
		case <-ctx.Done():
			return Point{}, ctx.Err()
		default:
		}

		r, err := s.Redact(ctx, authorized[i:end])
		if err != nil {
			return Point{}, err
		}
		p.Succeeded += r.Succeeded
		p.StaleExcluded += r.StaleExcluded
		p.Failed += r.Failed
		p.CryptoTime += r.CryptoTime
		p.LedgerTime += r.LedgerTime
	}
	p.TotalTime = time.Since(start)

	// A scheme reporting zero crypto time is not doing per-request cryptography,
	// which means the decomposition is not wired up. Catching that here is far
	// cheaper than discovering it when the Exp 2 plot has no floor.
	if p.Succeeded > 0 && p.CryptoTime == 0 {
		return Point{}, fmt.Errorf(
			"%s reported zero CryptoTime over %d successful redactions; "+
				"cost decomposition is not instrumented (CH.Adapt cannot be free)",
			s.Name(), p.Succeeded)
	}

	if p.Succeeded > 0 {
		p.CostPerRequest = time.Duration(int64(p.CryptoTime+p.LedgerTime) / int64(p.Succeeded))
	}
	if secs := p.TotalTime.Seconds(); secs > 0 {
		p.RedactionsPerSec = float64(p.Succeeded) / secs
	}
	if p.Requested > 0 {
		p.StaleExclusionRate = float64(p.StaleExcluded) / float64(p.Requested)
	}
	if total := p.CryptoTime + p.LedgerTime; total > 0 {
		p.CryptoShare = float64(p.CryptoTime) / float64(total)
	}
	return p, nil
}

// findOptimalBatch locates the batch size past which staleness costs more than
// amortisation saves.
//
// Amortisation gain is the relative fall in cost per request; staleness loss is
// the rise in exclusion rate. The optimum is the last size where gain still
// exceeds loss.
//
// Returns 0 when no crossover occurs inside the swept range. That is a
// meaningful outcome: it says the sweep must be extended, not that no optimum
// exists.
func findOptimalBatch(points []Point, schemeName string) int {
	type agg struct {
		cost  time.Duration
		stale float64
		n     int
	}
	by := make(map[int]*agg)

	for _, p := range points {
		if p.Scheme != schemeName {
			continue
		}
		a, ok := by[p.BatchSize]
		if !ok {
			a = &agg{}
			by[p.BatchSize] = a
		}
		a.cost += p.CostPerRequest
		a.stale += p.StaleExclusionRate
		a.n++
	}
	if len(by) < 2 {
		return 0
	}

	sizes := make([]int, 0, len(by))
	for s := range by {
		sizes = append(sizes, s)
	}
	for i := 0; i < len(sizes); i++ {
		for j := i + 1; j < len(sizes); j++ {
			if sizes[j] < sizes[i] {
				sizes[i], sizes[j] = sizes[j], sizes[i]
			}
		}
	}

	mean := func(s int) (cost float64, stale float64) {
		a := by[s]
		if a.n == 0 {
			return 0, 0
		}
		return float64(a.cost) / float64(a.n), a.stale / float64(a.n)
	}

	best := sizes[0]
	for i := 1; i < len(sizes); i++ {
		prevCost, prevStale := mean(sizes[i-1])
		curCost, curStale := mean(sizes[i])
		if prevCost <= 0 {
			continue
		}
		gain := (prevCost - curCost) / prevCost // relative cost reduction
		loss := curStale - prevStale            // absolute staleness increase
		if gain <= loss {
			return best
		}
		best = sizes[i]
	}
	// Still improving at the top of the sweep: no optimum was observed.
	return 0
}

func containsInt(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
