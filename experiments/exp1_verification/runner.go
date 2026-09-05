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
	Scheme      string          `json:"scheme"`
	Concurrency int             `json:"concurrency"`
	ShardCount  int             `json:"shard_count,omitempty"`
	Ablation    *Ablation       `json:"ablation,omitempty"`
	Repetition  int             `json:"repetition"`

	Throughput  float64         `json:"authorized_requests_per_second"`
	Latency     metrics.Summary `json:"latency"`

	Granted     int64           `json:"granted"`
	Denied      int64           `json:"denied"`
	Errors      int64           `json:"errors"`

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
		// Baseline throughput at N=1, used to compute scaling efficiency.
		var baseThroughput float64

		for _, conc := range cfg.ConcurrencyLevels {
			for rep := 0; rep < cfg.Repetitions; rep++ {
				p, err := runOne(ctx, s, trace, conc)
				if err != nil {
					return nil, fmt.Errorf("exp1: %s at concurrency %d: %w", s.Name(), conc, err)
				}
				p.Repetition = rep

				if conc == 1 && rep == 0 {
					baseThroughput = p.Throughput
				}
				if baseThroughput > 0 && conc > 1 {
					p.ScalingEfficiency = (p.Throughput / baseThroughput) / float64(conc)
				}
				res.Points = append(res.Points, p)
			}
		}
		res.SaturationPoint[s.Name()] = findSaturation(res.Points, s.Name())
	}
	return res, nil
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
	if granted > 0 && denied == 0 {
		return Point{}, fmt.Errorf(
			"%s granted all %d requests and denied none; authorization logic is "+
				"probably not running (a scheme that cannot reject is not verifying)",
			s.Name(), granted)
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
