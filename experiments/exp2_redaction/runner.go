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
	ConflictRatios []float64

	Repetitions int
}

// Point is one measured configuration.
type Point struct {
	Scheme        string  `json:"scheme"`
	BatchSize     int     `json:"batch_size"`
	WaitBoundMS   int     `json:"wait_bound_ms"`
	ConflictRatio float64 `json:"conflict_ratio"`
	Repetition    int     `json:"repetition"`

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
	trace []*scheme.Request,
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
	if len(trace) == 0 {
		return nil, fmt.Errorf("exp2: empty request trace")
	}

	res := &Result{OptimalBatchSize: make(map[string]int)}

	for _, s := range schemesUnderTest {
		authorized, err := authorizeAll(ctx, s, trace)
		if err != nil {
			return nil, fmt.Errorf("exp2: pre-authorization for %s: %w", s.Name(), err)
		}
		if len(authorized) == 0 {
			return nil, fmt.Errorf(
				"exp2: %s authorized none of %d requests; there is nothing to redact",
				s.Name(), len(trace))
		}

		// A scheme that does not batch is measured once, at B_R=1. Sweeping it
		// across batch sizes would fabricate a curve it has no mechanism to
		// produce.
		sizes := cfg.BatchSizes
		if !s.Capabilities().BatchRedaction {
			sizes = []int{1}
		}

		for _, size := range sizes {
			for _, wait := range waitsFor(cfg.WaitBoundsMS, s) {
				for rep := 0; rep < cfg.Repetitions; rep++ {
					p, err := runOne(ctx, s, authorized, size, wait)
					if err != nil {
						return nil, fmt.Errorf("exp2: %s at batch %d: %w", s.Name(), size, err)
					}
					p.Repetition = rep
					res.Points = append(res.Points, p)
				}
			}
		}
		res.OptimalBatchSize[s.Name()] = findOptimalBatch(res.Points, s.Name())
	}
	return res, nil
}

// authorizeAll runs the shared trace through one scheme's own authorization
// path, returning only the granted requests.
//
// Not timed. Denials are expected and are simply excluded — a request the
// scheme refuses is not a redaction it can be asked to execute.
func authorizeAll(ctx context.Context, s scheme.Scheme, trace []*scheme.Request) ([]*scheme.Authorization, error) {
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
