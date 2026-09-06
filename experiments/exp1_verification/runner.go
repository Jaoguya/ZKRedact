// Package exp1_verification runs Experiment 1: Verification Throughput.
//
// Question: how many redaction requests per second can each system authorize,
// and how does that scale with concurrent load?
//
// The harness is deliberately identical for all four systems. Each is driven
// through scheme.Authorize at the same concurrency levels, over the same trace,
// in the same order. What differs is only what each scheme does internally — a
// ZK proof verification, a committee vote, or a key-possession check — which is
// the finding, not an unfairness in the measurement.
//
// Two properties of this design are load-bearing:
//
//   - Concurrency is the primary axis, and the sweep starts at 1. The
//     single-request point is where the trapdoor baselines legitimately win.
//     Reporting only the high-load regime would be selection, so both are
//     mandatory (docs/experiments.md §2.6).
//
//   - Closed-loop load. A fixed number of workers each issue the next request
//     as soon as their previous one completes, so offered load cannot exceed
//     what the system can absorb and the saturation point is unambiguous.
package exp1_verification

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"zkredact/pkg/metrics"
	"zkredact/pkg/scheme"
)

// Config parameterises one Exp 1 run. Values come from
// config/experiment.yaml; nothing here carries a default.
type Config struct {
	ConcurrencyLevels []int
	Repetitions       int

	// ShardCounts applies to ZK-Redact only. Baselines run once per concurrency
	// level, since they have no equivalent knob.
	ShardCounts []int

	// NativeBatchVerify enumerates the verification modes to measure:
	// false is per-record, true is batch. Applies only to a scheme that has
	// both paths.
	NativeBatchVerify []bool

	// BatchSizes is B, the intra-shard batch size. It must be swept alongside
	// NativeBatchVerify: at B=1 a batch holds one proof, aggregation is skipped,
	// and both verification modes take the same path — so a mode sweep on its own
	// measures nothing and reports it as a comparison.
	BatchSizes []int

	// Ablations enumerate the sharding/batching combinations required to test
	// the Phase 3 independence claim.
	Ablations []Ablation
}

// Ablation is one cell of the sharding x batching grid.
type Ablation struct {
	Sharding bool `json:"sharding"`
	Batching bool `json:"batching"`
}

// Point is one measured configuration: a scheme at a concurrency level.
type Point struct {
	Scheme      string    `json:"scheme"`
	Concurrency int       `json:"concurrency"`
	ShardCount  int       `json:"shard_count,omitempty"`
	BatchSize   int       `json:"proof_batch_size,omitempty"`
	Ablation    *Ablation `json:"ablation,omitempty"`
	Repetition  int       `json:"repetition"`

	// NativeBatchVerify records which verification path produced this point.
	// Kept separate from Ablation.Batching: batching is B > 1, while this is
	// whether the aggregated pairing check ran, and the two are independent.
	NativeBatchVerify bool `json:"native_batch_verify"`

	Throughput float64         `json:"authorized_requests_per_second"`
	Latency    metrics.Summary `json:"latency"`

	Granted int64 `json:"granted"`
	Denied  int64 `json:"denied"`
	Errors  int64 `json:"errors"`

	// ScalingEfficiency is speedup over the N=1 run divided by N. Zero for
	// schemes without a shard knob. A value near 1 means near-ideal
	// parallelism; a collapsing value locates the saturation point.
	ScalingEfficiency float64 `json:"scaling_efficiency,omitempty"`

	Elapsed time.Duration `json:"elapsed_ns"`
}

// Result is the full Exp 1 output.
type Result struct {
	Points []Point `json:"points"`

	// SaturationPoint maps each scheme to the concurrency level beyond which
	// throughput stopped rising materially.
	SaturationPoint map[string]int `json:"saturation_point"`
}

// Run executes Experiment 1 across every scheme, concurrency level and
// repetition.
//
// Schemes must already be set up. Setup is not timed: the four systems cannot
// share a ledger format, so each materialises the identical source dataset into
// its own representation beforehand.
func Run(ctx context.Context, cfg Config, schemesUnderTest []scheme.Scheme, trace []*scheme.Request) (*Result, error) {
	if len(cfg.ConcurrencyLevels) == 0 {
		return nil, fmt.Errorf("exp1: no concurrency levels configured")
	}
	if cfg.Repetitions < 1 {
		return nil, fmt.Errorf("exp1: repetitions must be >= 1, got %d", cfg.Repetitions)
	}
	if len(trace) == 0 {
		return nil, fmt.Errorf("exp1: empty request trace")
	}
	if cfg.ConcurrencyLevels[0] != 1 {
		return nil, fmt.Errorf(
			"exp1: concurrency sweep must start at 1; the single-request point is " +
				"where the trapdoor baselines legitimately lead, and omitting it makes " +
				"the comparison selective")
	}

	res := &Result{SaturationPoint: make(map[string]int)}

	for _, s := range schemesUnderTest {
		// Every scaling-efficiency number for this scheme is divided by its
		// single-worker throughput, so that denominator is measured with ALL
		// the repetitions and averaged.
		//
		// Taking it from repetition 0 alone made one unreplicated measurement
		// the reference for the whole curve: an outlier there shifted every
		// point, and running more repetitions could not correct it, because the
		// others were never consulted. The sweep is required to start at 1
		// (checked above) precisely so this baseline exists.
		var baseSamples []float64
		schemeStart := len(res.Points)

		// Shard counts apply only to a scheme that HAS shards. A baseline has
		// none, so it runs once per concurrency level; sweeping it over shard
		// counts would fabricate a curve its design cannot produce, which is
		// the same failure exp2 refuses for batch sizes.
		shardCounts := []int{0} // 0 means "not applicable"
		resharder, sharded := s.(scheme.Resharder)
		if sharded && len(cfg.ShardCounts) > 0 {
			shardCounts = cfg.ShardCounts
		}

		// The batching arm of the ablation grid. A scheme with only one
		// verification path is measured once; one with both is measured as
		// per-record AND as batch, which is what makes the Phase 3
		// independence claim testable rather than asserted.
		batchModes := []bool{false} // false = per-record
		tuner, tunable := s.(scheme.BatchVerifierTuner)
		if tunable && len(cfg.NativeBatchVerify) > 0 {
			batchModes = cfg.NativeBatchVerify
		}

		// B, swept for the same reason as the shard count. Without this the
		// verification-mode sweep above is inert: a batch of one never reaches
		// the aggregated pairing check, so both modes run identical code and the
		// grid reports one measurement twice.
		batchSizes := []int{0} // 0 means "not applicable"
		rebatcher, rebatchable := s.(scheme.Rebatcher)
		if rebatchable && len(cfg.BatchSizes) > 0 {
			batchSizes = cfg.BatchSizes
		}

		for _, shards := range shardCounts {
			if sharded && shards > 0 {
				if err := resharder.Reshard(shards); err != nil {
					return nil, fmt.Errorf("exp1: %s reshard to %d: %w", s.Name(), shards, err)
				}
			}

			for _, batch := range batchSizes {
				if rebatchable && batch > 0 {
					if err := rebatcher.Rebatch(batch); err != nil {
						return nil, fmt.Errorf("exp1: %s rebatch to %d: %w", s.Name(), batch, err)
					}
				}

				for _, native := range batchModes {
					if tunable {
						if err := tuner.SetNativeBatchVerify(native); err != nil {
							return nil, fmt.Errorf("exp1: %s set batch mode %v: %w", s.Name(), native, err)
						}
					}

					for _, conc := range cfg.ConcurrencyLevels {
						for rep := 0; rep < cfg.Repetitions; rep++ {
							replay := replayTrace(trace, conc, rep)

							// Requester-side work and per-replay state resets happen
							// here, OUTSIDE the timed region. For ZK-Redact that is
							// proof generation, which costs an order of magnitude more
							// than the verification Exp 1 measures.
							if prep, ok := s.(scheme.TracePreparer); ok {
								if err := prep.PrepareTrace(ctx, replay); err != nil {
									return nil, fmt.Errorf("exp1: %s prepare trace: %w", s.Name(), err)
								}
							}

							p, err := runOne(ctx, s, replay, conc)
							if err != nil {
								return nil, fmt.Errorf("exp1: %s at concurrency %d: %w", s.Name(), conc, err)
							}
							p.Repetition = rep
							p.ShardCount = shards
							p.BatchSize = batch
							p.NativeBatchVerify = native

							// Recorded per point, so a plot cannot mix the arms.
							// Sharding is "on" above one shard; batching is on above
							// a batch of one, which is the config's own disabled arm.
							if tunable || sharded || rebatchable {
								p.Ablation = &Ablation{
									Sharding: shards > 1,
									Batching: batch > 1,
								}
							}

							// The scaling baseline is per shard count: comparing a
							// 64-shard run against a 1-shard single-worker measurement
							// would report the sharding speedup as scaling efficiency.
							// Pinned to the first batch size and mode for the same
							// reason — one baseline cannot span two configurations.
							if conc == 1 && shards == baselineShards(shardCounts) &&
								native == batchModes[0] && batch == batchSizes[0] {
								baseSamples = append(baseSamples, p.Throughput)
							}
							res.Points = append(res.Points, p)
						}
					}
				}
			}
		}

		// Filled in after the sweep, since the baseline is not complete until
		// every concurrency-1 repetition has run.
		baseThroughput := mean(baseSamples)
		if baseThroughput > 0 {
			for i := schemeStart; i < len(res.Points); i++ {
				if res.Points[i].Concurrency > 1 {
					res.Points[i].ScalingEfficiency =
						(res.Points[i].Throughput / baseThroughput) / float64(res.Points[i].Concurrency)
				}
			}
		}
		_ = shardCounts

		res.SaturationPoint[s.Name()] = findSaturation(res.Points, s.Name())
	}
	return res, nil
}

// mean returns the arithmetic mean, or 0 for an empty sample.
func mean(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	var sum float64
	for _, x := range xs {
		sum += x
	}
	return sum / float64(len(xs))
}

// replayTrace returns the trace with each request id tagged by the replay it
// belongs to.
//
// Exp 1 replays one trace at every concurrency level and repetition — 330 times
// at the configured sweep. Ref[10] derives its on-ledger contract address from
// the request id (Algorithm 3, addr(con_k)), so an untagged replay reopens a
// round that already exists and the run dies on the second one. The ledger is
// not reset between replays, and resetting it would erase the growth Exp 3
// measures.
//
// The tag goes on the IDENTIFIER only. Requester, target transaction, content
// and policy are untouched, so the workload each scheme sees is unchanged and
// every scheme receives the same tags in the same order — the shared-trace
// fairness contract is preserved. Tagging here rather than inside a scheme
// keeps addr = f(request id) exactly as Ref[10] specifies, and keeps the
// committee draw deterministic: it depends on the id, not on the order
// goroutines happened to pick requests up.
func replayTrace(trace []*scheme.Request, concurrency, rep int) []*scheme.Request {
	out := make([]*scheme.Request, len(trace))
	for i, r := range trace {
		clone := *r
		clone.ID = fmt.Sprintf("%s#c%d.r%d", r.ID, concurrency, rep)
		out[i] = &clone
	}
	return out
}

// runOne drives a single scheme at one concurrency level under closed-loop load.
func runOne(ctx context.Context, s scheme.Scheme, trace []*scheme.Request, concurrency int) (Point, error) {
	lat := metrics.NewLatency(len(trace))
	tp := metrics.NewThroughput()

	var (
		granted, denied, errCount int64
		next                      int64 // shared cursor into the trace
		firstErr                  error
		errOnce                   sync.Once
		wg                        sync.WaitGroup
	)

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				// Every worker draws from one shared cursor, so all schemes see
				// the same requests in the same order regardless of worker count.
				i := atomic.AddInt64(&next, 1) - 1
				if i >= int64(len(trace)) {
					return
				}
				select {
				case <-runCtx.Done():
					return
				default:
				}

				start := time.Now()
				auth, err := s.Authorize(runCtx, trace[i])
				elapsed := time.Since(start)

				switch {
				case err != nil:
					atomic.AddInt64(&errCount, 1)
					// An unimplemented scheme is fatal, not skippable: a
					// comparison missing one system is worse than none.
					errOnce.Do(func() {
						firstErr = err
						cancel()
					})
					return
				case auth.Granted:
					atomic.AddInt64(&granted, 1)
				default:
					atomic.AddInt64(&denied, 1)
				}

				// Only successful authorizations count toward latency and
				// throughput. Timing failures would mix two different operations
				// into one distribution.
				lat.Record(elapsed)
				tp.Add(1)
			}
		}()
	}

	wg.Wait()
	tp.Stop()

	if firstErr != nil {
		return Point{}, firstErr
	}

	// A scheme that never denies anything is not evaluating authorization. This
	// does not prove the logic is correct, but it catches a stub that always
	// approves — which would otherwise look like excellent performance.
	//
	// APPLIED ONLY TO SCHEMES THAT CLAIM POLICY-BOUND AUTHORIZATION. Ref[13] and
	// Ref[22] declare PolicyBound false because neither paper defines a
	// per-request authorization protocol — their check is key possession, which
	// the regulator always passes. Granting everything is the honest outcome
	// there, and docs/experiments.md §2.2 says so; failing the run for it would
	// force inventing an authorization protocol for them, which is exactly the
	// fabrication this project refuses.
	//
	// The capability declaration is what makes this safe: a scheme cannot dodge
	// the guard without also declaring it does not evaluate policy, and that
	// declaration appears in the capability matrix the results carry.
	if s.Capabilities().PolicyBound && granted > 0 && denied == 0 {
		return Point{}, fmt.Errorf(
			"%s claims policy-bound authorization but granted all %d requests and "+
				"denied none; the policy check is probably not running (a scheme that "+
				"cannot reject is not verifying)",
			s.Name(), granted)
	}

	// And the mirror image, which is the FASTER failure of the two: rejecting a
	// request costs almost nothing, so a scheme that denies everything posts the
	// best throughput in the study and a perfectly clean scaling curve.
	//
	// Observed, not hypothetical. ZK-Redact's gateway checked request freshness
	// against wall-clock time while pkg/workload stamps the trace from a fixed
	// epoch, so every request was months stale: 60 of 60 denied at ~13,000
	// "authorizations" per second. Nothing else in the run looked wrong.
	if denied > 0 && granted == 0 {
		return Point{}, fmt.Errorf(
			"%s denied all %d requests and granted none; it is measuring the cost "+
				"of rejection, not of authorization, and rejection is the cheapest "+
				"path through any of these schemes",
			s.Name(), denied)
	}

	return Point{
		Scheme:      s.Name(),
		Concurrency: concurrency,
		Throughput:  tp.PerSecond(),
		Latency:     lat.Summarize(),
		Granted:     granted,
		Denied:      denied,
		Errors:      errCount,
		Elapsed:     tp.Elapsed(),
	}, nil
}

// findSaturation returns the concurrency level past which throughput stopped
// rising by more than 5%.
//
// The threshold is a reporting convention, not a claim: the underlying points
// are all retained, so a reader can apply a different one. Zero means throughput
// was still climbing at the top of the sweep — in which case the sweep must be
// extended rather than concluding no saturation exists.
func findSaturation(points []Point, schemeName string) int {
	const relGain = 0.05

	best := make(map[int]float64)
	for _, p := range points {
		if p.Scheme != schemeName {
			continue
		}
		if p.Throughput > best[p.Concurrency] {
			best[p.Concurrency] = p.Throughput
		}
	}
	if len(best) < 2 {
		return 0
	}

	levels := make([]int, 0, len(best))
	for c := range best {
		levels = append(levels, c)
	}
	for i := 0; i < len(levels); i++ {
		for j := i + 1; j < len(levels); j++ {
			if levels[j] < levels[i] {
				levels[i], levels[j] = levels[j], levels[i]
			}
		}
	}

	for i := 1; i < len(levels); i++ {
		prev, cur := best[levels[i-1]], best[levels[i]]
		if prev > 0 && (cur-prev)/prev < relGain {
			return levels[i-1]
		}
	}
	return 0
}

// baselineShards returns the shard count the scaling baseline is taken at.
//
// The FIRST swept value, which config/experiment.yaml orders so that it is the
// sharding-disabled arm. Taking the baseline at whichever shard count happened
// to run first would fold the sharding speedup into scaling efficiency, which
// is supposed to measure only the effect of added concurrency.
func baselineShards(counts []int) int {
	if len(counts) == 0 {
		return 0
	}
	return counts[0]
}
