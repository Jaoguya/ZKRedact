package exp2_redaction

import (
	"context"
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
		BatchSizes:  []int{1, 2, 4},
		Repetitions: 2,
	}, []scheme.Scheme{s}, trace)
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
