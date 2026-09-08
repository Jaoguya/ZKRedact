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
	"sync"
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

	// WorkloadSizes is the PRIMARY AXIS: how many redaction requests the
	// workload contains. The figure plots average overhead per request against
	// it, so the amortisation is observed converging rather than read off one
	// workload size.
	//
	// Each size takes a PREFIX of the trace. Every system therefore sees the
	// same first n requests in the same order, which is the one-trace rule
	// applied to a shorter run rather than a differently generated one.
	//
	// COST. A size multiplies the arms, and every arm re-authorizes its own
	// prefix — for ZK-Redact one Groth16 proof per request. Crossing this
	// dimension with the full Delta_R and conflict sweeps would multiply the
	// run by len(WorkloadSizes); it is therefore swept only at the HEADLINE
	// arm, the first wait bound and the first conflict ratio, which is exactly
	// the arm cmd/plot draws the overhead figure from. Every other arm runs at
	// the full workload alone, so the Delta_R and conflict curves keep the
	// sweep they already had.
	//
	// Empty means one size: the whole trace.
	WorkloadSizes []int

	// Concurrency is how many requests are offered at once, under the
	// closed-loop arrival process config/experiment.yaml declares.
	//
	// REQUIRED FOR DELTA_R TO MEAN ANYTHING, which is why it is here and was
	// not before. A batch closes on size OR on the wait bound, and with a
	// serial replay the size rule always won: the whole trace was resident
	// before the loop began, so every batch was full at birth and tau was
	// always zero. Only an arrival process can make a batch close SHORT, and
	// only a short close exercises Delta_R.
	//
	// It also bounds what B_R can reach. Under a closed loop at most
	// Concurrency requests are ever in flight, so a batch cannot exceed it: at
	// Concurrency 1 a B_R of 64 degenerates to a batch of one that additionally
	// waits out Delta_R, which is strictly worse than not batching and is a
	// property of the harness rather than of the scheme.
	//
	// Zero means max(BatchSizes) — the smallest value at which every swept B_R
	// is still reachable, so the knob and not the offered load decides the
	// batch size. Setting it below that is legitimate but must be deliberate:
	// it measures batching under starvation, and MeanBatchSize on every point
	// will show it.
	Concurrency int

	// ArmShard splits the sweep across hosts: this process measures only the
	// arms whose index is congruent to Index modulo Total.
	//
	// An ARM is one (setup sweep, conflict ratio, batch size, wait bound)
	// combination — 84 of them for ZK-Redact, each re-authorizing the whole
	// trace before it can redact. That re-authorization is one Groth16 proof
	// per request per arm, so the sweep is embarrassingly parallel and its
	// per-host setup is 9.5 s: splitting it is nearly free.
	//
	// Total 0 or 1 means no split.
	ArmShardIndex int
	ArmShardTotal int

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
	Scheme string `json:"scheme"`

	// WorkloadSize is how many requests this point's workload contained — the
	// x-axis of the Exp 2 figure.
	WorkloadSize int `json:"workload_size"`

	BatchSize     int     `json:"batch_size"`
	WaitBoundMS   int     `json:"wait_bound_ms"`
	ConflictRatio float64 `json:"conflict_ratio"`
	Concurrency   int     `json:"concurrency"`
	Repetition    int     `json:"repetition"`

	// What the batcher actually did, which is what makes a Delta_R sweep
	// checkable rather than merely labelled.
	//
	// BatchesShortClosed counts batches that closed on tau >= Delta_R instead
	// of on |B| = B_R. It is the direct evidence the wait bound fired at all:
	// when it is zero across a whole sweep, Delta_R changed nothing and the
	// four curves are four copies — which is exactly the state this experiment
	// was in before the batcher existed, and which nothing in the output said.
	//
	// MeanBatchSize is the companion check. A mean far below B_R means the
	// offered load, not the knob, decided the batch size, and the point is
	// measuring starvation rather than batching.
	BatchesClosed      int     `json:"batches_closed"`
	BatchesShortClosed int     `json:"batches_short_closed"`
	MeanBatchSize      float64 `json:"mean_batch_size"`

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
	// Default the offered load to the largest batch: the smallest concurrency
	// at which every swept B_R is still reachable. Below it the harness, not
	// the knob, caps the batch — see Config.Concurrency.
	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = maxInt(cfg.BatchSizes)
	}
	if concurrency < maxInt(cfg.BatchSizes) {
		// Legitimate, but it must not be silent: it measures batching under
		// starvation, and the batch-size curve will flatten for a reason that
		// has nothing to do with the scheme.
		fmt.Printf("exp2: WARNING concurrency %d is below max batch size %d — "+
			"batches larger than %d cannot form; check mean_batch_size on every point\n",
			concurrency, maxInt(cfg.BatchSizes), concurrency)
	}
	if cfg.ArmShardTotal > 1 &&
		(cfg.ArmShardIndex < 0 || cfg.ArmShardIndex >= cfg.ArmShardTotal) {
		return nil, fmt.Errorf("exp2: arm shard %d is outside 0..%d",
			cfg.ArmShardIndex, cfg.ArmShardTotal-1)
	}
	if cfg.Repetitions < 1 {
		return nil, fmt.Errorf("exp2: repetitions must be >= 1, got %d", cfg.Repetitions)
	}
	for _, n := range cfg.WorkloadSizes {
		if n < 1 {
			return nil, fmt.Errorf("exp2: workload size %d is not a positive request count", n)
		}
		if n < concurrency {
			// The prefix cannot fill the offered load, so the batch size is
			// decided by the workload rather than by B_R, and the point
			// measures starvation. Refused rather than warned: it would sit at
			// the left end of the headline figure, where the curve is read.
			return nil, fmt.Errorf(
				"exp2: workload size %d is below the offered concurrency %d — "+
					"the prefix cannot fill a batch, so B_R would not be the "+
					"binding constraint at that point", n, concurrency)
		}
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
		armIndex := 0

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

			waits := waitsFor(cfg.WaitBoundsMS, s)
			for ti, rt := range traces {
				for _, size := range sizes {
					for wi, wait := range waits {
						// The workload axis is swept only on the headline arm;
						// see Config.WorkloadSizes for why.
						headline := ti == 0 && wi == 0
						for _, workload := range workloadsFor(cfg, len(rt.trace), headline) {
							// Arm index is counted over the FULL sweep, not over the
							// arms this host runs, so every shard agrees on which
							// arm is which and no arm is measured twice.
							thisArm := armIndex
							armIndex++
							if !cfg.runsArm(thisArm) {
								continue
							}
							trace := rt.trace[:workload]
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
								authorized, err := authorizeAll(ctx, s, trace)
								if err != nil {
									return nil, fmt.Errorf("exp2: pre-authorization for %s: %w", s.Name(), err)
								}
								if len(authorized) == 0 {
									return nil, fmt.Errorf(
										"exp2: %s authorized none of %d requests at batch size %d, "+
											"conflict ratio %v; there is nothing to redact",
										s.Name(), len(trace), size, rt.ratio)
								}

								p, err := runOne(ctx, s, authorized, size, wait, concurrency)
								if err != nil {
									return nil, fmt.Errorf("exp2: %s at batch %d, conflict %v: %w",
										s.Name(), size, rt.ratio, err)
								}
								p.Repetition = rep
								p.SetupParams = overrides
								p.ConflictRatio = rt.ratio
								p.WorkloadSize = workload
								res.Points = append(res.Points, p)
							}
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
		// A SHARD MUST NOT CLAIM AN OPTIMUM. findOptimalBatch compares batch
		// sizes against each other, and a host holding a few arms is comparing
		// a few points from a curve it cannot see. The optimum is a property of
		// the POOLED sweep — the same rule that puts Exp 1's concurrency-1
		// check in cmd/merge-results rather than in the runner.
		if cfg.ArmShardTotal > 1 {
			continue
		}
		res.OptimalBatchSize[s.Name()] = findOptimalBatch(atBaseline, s.Name())
	}
	return res, nil
}

// runsArm reports whether this host measures the arm at that index.
func (c Config) runsArm(index int) bool {
	if c.ArmShardTotal <= 1 {
		return true
	}
	return index%c.ArmShardTotal == c.ArmShardIndex
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

// runOne offers the full authorized set to one scheme at one batch size and one
// wait bound, under a closed-loop arrival process.
//
// WHY THIS IS NOT A SLICING LOOP ANY MORE. It used to walk `authorized` in
// steps of B_R and hand each slice to Redact. That implements only half of
// Phase 4's closing rule — the size half — and it makes the other half
// unmeasurable, because a slice taken from a fully resident list is full the
// instant it is cut and tau is always zero. Delta_R was consequently a label on
// the output rather than an input to anything, and its four configured values
// produced four identical sets of numbers at four times the cost. See
// batcher.go, and internal/pvl/service.go for the same fix on the Exp 1 side.
//
// Now `concurrency` submitters draw from a shared queue and each blocks until
// the batch carrying its request has executed. Batches therefore fill from
// genuine arrivals, close short when those run out, and Delta_R bounds how long
// the oldest request in an open batch waits — which is what it was always
// specified to do.
func runOne(
	ctx context.Context,
	s scheme.Scheme,
	authorized []*scheme.Authorization,
	batchSize, waitMS, concurrency int,
) (Point, error) {
	p := Point{
		Scheme:      s.Name(),
		BatchSize:   batchSize,
		WaitBoundMS: waitMS,
		Concurrency: concurrency,
		Requested:   len(authorized),
	}

	// The queue holds every request that may be in flight at once. Sized to the
	// offered load for the reason pvl.NewService gives: a shorter queue would
	// block submitters on the channel and charge that wait to redaction.
	b, err := newBatcher(s, batchSize, time.Duration(waitMS)*time.Millisecond,
		concurrency, len(authorized))
	if err != nil {
		return Point{}, err
	}

	start := time.Now()
	b.start(ctx)

	next := make(chan *scheme.Authorization)
	go func() {
		defer close(next)
		for _, a := range authorized {
			select {
			case next <- a:
			case <-ctx.Done():
				return
			}
		}
	}()

	var wg sync.WaitGroup
	var subMu sync.Mutex
	var subErr error
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for a := range next {
				if err := b.submit(ctx, a); err != nil {
					subMu.Lock()
					if subErr == nil {
						subErr = err
					}
					subMu.Unlock()
					return
				}
			}
		}()
	}
	wg.Wait()

	stats := b.finish()
	p.TotalTime = time.Since(start)

	// A batch that failed to execute is a failed measurement, not a slow one:
	// its requests were never redacted, so every derived figure below would be
	// computed over work that did not happen.
	if err := b.failure(); err != nil {
		return Point{}, err
	}
	if subErr != nil {
		return Point{}, subErr
	}

	p.Succeeded = stats.Succeeded
	p.StaleExcluded = stats.StaleExcluded
	p.Failed = stats.Failed
	p.CryptoTime = stats.CryptoTime
	p.LedgerTime = stats.LedgerTime
	p.BatchesClosed = stats.Closed
	p.BatchesShortClosed = stats.ShortClosed
	if stats.Closed > 0 {
		p.MeanBatchSize = float64(stats.SizeSum) / float64(stats.Closed)
	}

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

func maxInt(xs []int) int {
	m := 0
	for _, x := range xs {
		if x > m {
			m = x
		}
	}
	return m
}

// workloadsFor is the workload sizes to measure on one arm.
//
// The headline arm — first conflict ratio, first wait bound — carries the whole
// sweep, because that is the arm the overhead figure is drawn from. Every other
// arm runs at the full trace only, so the Delta_R and conflict-ratio sweeps are
// unchanged and the run does not multiply by len(WorkloadSizes).
//
// A configured size longer than the trace is clamped to the trace rather than
// refused: it is the same measurement, and refusing would make the config
// depend on workload.total_requests in two places.
func workloadsFor(cfg Config, traceLen int, headline bool) []int {
	if len(cfg.WorkloadSizes) == 0 || !headline {
		return []int{traceLen}
	}
	out := make([]int, 0, len(cfg.WorkloadSizes))
	seen := make(map[int]struct{}, len(cfg.WorkloadSizes))
	for _, n := range cfg.WorkloadSizes {
		if n > traceLen {
			n = traceLen
		}
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}
