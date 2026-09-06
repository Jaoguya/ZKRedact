package exp2_redaction

import (
	"context"
	"strings"
	"testing"

	"zkredact/internal/schemes/zkredact"
	"zkredact/pkg/scheme"
	"zkredact/pkg/workload"
)

// Exp 2 driven against the real ZK-Redact scheme.
//
// Package-level tests of the runner use stub schemes, which agree with whatever
// the runner does. This one runs the actual Phase 4 implementation through the
// actual sweep, because the two have never met and every defect this project
// has found lived exactly in that gap.

func exp2Fixture(t *testing.T) (scheme.Scheme, []*scheme.Request) {
	t.Helper()

	const txs = 60
	wcfg := workload.Config{
		Seed:                   3,
		BaseTransactions:       txs,
		CorePayloadBytes:       64,
		RedactablePayloadBytes: 128,
		IdentityCount:          12,
		IdentityAttributes:     []string{"sender", "receiver", "validator", "org", "role"},
		PolicyCount:            2,
		PredicateDepth:         3,
		TotalRequests:          16,
		TargetDistribution:     "uniform",
	}
	ds, err := workload.GenerateDataset(wcfg)
	if err != nil {
		t.Fatalf("dataset: %v", err)
	}
	trace, err := workload.GenerateTrace(wcfg, ds)
	if err != nil {
		t.Fatalf("trace: %v", err)
	}

	s := zkredact.New()
	if err := s.Setup(context.Background(), scheme.SetupParams{
		Dataset: ds, Seed: 3, SecurityBits: 128,
		Params: map[string]any{
			"shard_count": 1, "proof_batch_size": 1, "proof_batch_wait_ms": 10,
			"native_batch_verify": false, "freshness_window_ms": 3600000,
			"signature_curve": "P-256", "hash": "SHA-256",
			"redactable_payload_bytes": 128, "block_max_transactions": 10,
			"auditor_count": 3, "max_concurrency": 8,
		},
	}); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	t.Cleanup(func() { _ = s.Teardown(context.Background()) })
	return s, trace
}

// TestExp2SweepsZKRedactWithoutStranding is the check that the sweep measures
// redactions rather than staleness.
//
// EVERY configuration must commit work. A configuration whose requests were all
// excluded still produces a Point — with a cost per request computed from a
// handful of survivors, or from none — and nothing downstream distinguishes
// "batching did not help here" from "nothing ran here". The batch-size curve
// would then be built almost entirely from configurations that redacted
// nothing.
func TestExp2SweepsZKRedactWithoutStranding(t *testing.T) {
	s, trace := exp2Fixture(t)

	res, err := Run(context.Background(), Config{
		BatchSizes:     []int{1, 2, 4},
		Repetitions:    2,
		ConflictRatios: []float64{0.0},
		TraceFor:       func(float64) ([]*scheme.Request, error) { return trace, nil },
	}, []scheme.Scheme{s})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Points) == 0 {
		t.Fatal("no points produced")
	}

	for _, p := range res.Points {
		t.Logf("B_R=%-2d rep=%d  requested=%-3d succeeded=%-3d stale=%-3d failed=%-3d "+
			"crypto=%v ledger=%v",
			p.BatchSize, p.Repetition, p.Requested, p.Succeeded,
			p.StaleExcluded, p.Failed, p.CryptoTime, p.LedgerTime)
	}

	for _, p := range res.Points {
		if p.Succeeded == 0 {
			t.Errorf("B_R=%d rep=%d committed nothing: %d of %d requests were "+
				"excluded as stale. The configuration produced a data point that "+
				"measures no redaction at all.",
				p.BatchSize, p.Repetition, p.StaleExcluded, p.Requested)
		}
	}
}

// The conflict ratio must actually be swept, and recorded on every point.
//
// It was previously declared in Config, passed in from the config file, and
// never looped over — while cmd/run-experiment generated one trace at a
// hardcoded 0.0 and every Point carried conflict_ratio: 0 as a zero value. The
// results asserted an experimental condition that was never set, and the
// plotter, which already groups by "conflict", had nothing to group.
func TestConflictRatioIsSweptAndRecorded(t *testing.T) {
	s, trace := exp2Fixture(t)

	ratios := []float64{0.0, 0.25, 0.5}
	asked := make(map[float64]int)

	res, err := Run(context.Background(), Config{
		BatchSizes:     []int{1, 2},
		Repetitions:    1,
		ConflictRatios: ratios,
		TraceFor: func(r float64) ([]*scheme.Request, error) {
			asked[r]++
			return trace, nil
		},
	}, []scheme.Scheme{s})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// One trace per ratio, built once and shared across schemes.
	for _, r := range ratios {
		if asked[r] != 1 {
			t.Errorf("TraceFor(%v) called %d times, want 1", r, asked[r])
		}
	}

	seen := make(map[float64]int)
	for _, p := range res.Points {
		seen[p.ConflictRatio]++
	}
	for _, r := range ratios {
		if seen[r] == 0 {
			t.Errorf("no points recorded at conflict ratio %v", r)
		}
	}
	if len(seen) != len(ratios) {
		t.Errorf("points carry %d distinct conflict ratios, want %d", len(seen), len(ratios))
	}
}

// A missing TraceFor must be refused, not silently treated as one fixed trace.
func TestRunRefusesAMissingTraceHook(t *testing.T) {
	s, _ := exp2Fixture(t)
	_, err := Run(context.Background(), Config{
		BatchSizes:     []int{1},
		Repetitions:    1,
		ConflictRatios: []float64{0.0},
	}, []scheme.Scheme{s})
	if err == nil {
		t.Fatal("Run accepted a config with no TraceFor")
	}
	if !strings.Contains(err.Error(), "TraceFor") {
		t.Errorf("error %q does not name the missing hook", err)
	}
}

// The optimum must be computed at one ratio. It genuinely moves with conflict —
// more conflict strands more work on revalidation — so averaging across ratios
// reports a batch size that is optimal at none of them.
func TestOptimalBatchIsNotPooledAcrossConflictRatios(t *testing.T) {
	s, trace := exp2Fixture(t)

	res, err := Run(context.Background(), Config{
		BatchSizes:     []int{1, 2, 4},
		Repetitions:    1,
		ConflictRatios: []float64{0.5, 0.0}, // deliberately not in ascending order
		TraceFor:       func(float64) ([]*scheme.Request, error) { return trace, nil },
	}, []scheme.Scheme{s})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The baseline is the LOWEST ratio, not the first listed.
	atBaseline := 0
	for _, p := range res.Points {
		if p.ConflictRatio == 0.0 {
			atBaseline++
		}
	}
	if atBaseline == 0 {
		t.Fatal("no points at the baseline ratio")
	}
	if _, ok := res.OptimalBatchSize[s.Name()]; !ok {
		t.Errorf("no optimal batch size reported for %s", s.Name())
	}
}
