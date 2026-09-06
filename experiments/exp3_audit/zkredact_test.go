package exp3_audit

import (
	"context"
	"fmt"
	"testing"
	"time"

	"zkredact/internal/schemes/zkredact"
	"zkredact/pkg/metrics"
	"zkredact/pkg/scheme"
	"zkredact/pkg/workload"
)

// Exp 3 driven against the real ZK-Redact scheme, including the Prepare hook
// that rebuilds the ledger at each swept size.
//
// The runner's own tests use stub schemes and therefore cannot catch a scheme
// whose Audit path disagrees with what the runner expects — the ledger-
// independence guard especially, which fails the run rather than plotting a
// contradiction.

func zkParams() map[string]any {
	return map[string]any{
		"shard_count": 1, "proof_batch_size": 1, "proof_batch_wait_ms": 10,
		"native_batch_verify": false, "freshness_window_ms": 3600000,
		"signature_curve": "P-256", "hash": "SHA-256",
		"redactable_payload_bytes": 128, "block_max_transactions": 10,
		"auditor_count": 3, "max_concurrency": 8,
	}
}

func zkDataset(t *testing.T, txs int) *scheme.Dataset {
	t.Helper()
	ds, err := workload.GenerateDataset(workload.Config{
		Seed: 5, BaseTransactions: txs,
		CorePayloadBytes: 64, RedactablePayloadBytes: 128,
		IdentityCount:      12,
		IdentityAttributes: []string{"sender", "receiver", "validator", "org", "role"},
		PolicyCount:        2, PredicateDepth: 3,
		TotalRequests: txs, TargetDistribution: "uniform",
	})
	if err != nil {
		t.Fatalf("dataset: %v", err)
	}
	return ds
}

// prepareOne mirrors cmd/run-experiment's prepareLedger closely enough to
// exercise the same contract: rebuild at a size, then build history by
// alternating Authorize and Redact one revision at a time.
func prepareOne(t *testing.T, ctx context.Context, s scheme.Scheme, blocks int, depths []int) (map[int][]string, error) {
	t.Helper()

	const blockTx = 10
	ds := zkDataset(t, blocks*blockTx)
	if err := s.Setup(ctx, scheme.SetupParams{
		Dataset: ds, Seed: 5, SecurityBits: 128, Params: zkParams(),
	}); err != nil {
		return nil, fmt.Errorf("setup at %d blocks: %w", blocks, err)
	}

	authorize := func(req *scheme.Request) (*scheme.Authorization, error) {
		if prep, ok := s.(scheme.TracePreparer); ok {
			if err := prep.PrepareTrace(ctx, []*scheme.Request{req}); err != nil {
				return nil, err
			}
		}
		return s.Authorize(ctx, req)
	}

	// A requester the scheme actually grants, found by asking.
	var requester string
	probe := ds.Transactions[len(ds.Transactions)-1].ID
	for i, id := range ds.Identities {
		a, err := authorize(&scheme.Request{
			ID: fmt.Sprintf("probe-%d-%d", blocks, i), RequesterID: id.ID,
			TargetTxID: probe, NewContent: []byte("probe"),
			PolicyID: ds.Policies[0].ID, Timestamp: time.Now(),
		})
		if err != nil {
			return nil, err
		}
		if a.Granted {
			requester = id.ID
			break
		}
	}
	if requester == "" {
		return nil, fmt.Errorf("no identity satisfies the policy")
	}

	out := make(map[int][]string, len(depths))
	next := 0
	for _, depth := range depths {
		target := ds.Transactions[next].ID
		next++
		for i := 0; i < depth; i++ {
			a, err := authorize(&scheme.Request{
				ID:          fmt.Sprintf("hist-%d-%s-%d", blocks, target, i),
				RequesterID: requester, TargetTxID: target,
				NewContent: []byte(fmt.Sprintf("revision %d", i+1)),
				PolicyID:   ds.Policies[0].ID, Timestamp: time.Now(),
			})
			if err != nil {
				return nil, err
			}
			if !a.Granted {
				return nil, fmt.Errorf("history for %s denied at revision %d: %s",
					target, i+1, a.Reason)
			}
			r, err := s.Redact(ctx, []*scheme.Authorization{a})
			if err != nil {
				return nil, err
			}
			if r.Succeeded != 1 {
				return nil, fmt.Errorf(
					"history for %s: revision %d did not commit (%d ok, %d stale, %d failed)",
					target, i+1, r.Succeeded, r.StaleExcluded, r.Failed)
			}
		}
		out[depth] = []string{target}
	}
	return out, nil
}

// TestExp3RunsZKRedactAcrossLedgerSizes is the end-to-end check. The runner
// itself fails the run if a scheme declaring LedgerIndependentAudit traverses
// the whole ledger, so reaching a result at all is part of what is asserted.
func TestExp3RunsZKRedactAcrossLedgerSizes(t *testing.T) {
	ctx := context.Background()
	s := zkredact.New()
	t.Cleanup(func() { _ = s.Teardown(ctx) })

	depths := []int{1, 2}
	res, err := Run(ctx, Config{
		LedgerSizes:   []int{4, 40},
		HistoryDepths: depths,
		Repetitions:   1,
		AuditorID:     "auditor-0",
		Prepare: func(ctx context.Context, sc scheme.Scheme, ledgerSize int, _ map[string]any) (map[int][]string, error) {
			return prepareOne(t, ctx, sc, ledgerSize, depths)
		},
	}, []scheme.Scheme{s})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	for _, p := range res.Points {
		t.Logf("ledger=%-3d depth=%-2d verified=%-5v blocks=%-2d records=%d bytes=%-5d "+
			"auth=%v retrieve=%v verify=%v",
			p.LedgerSize, p.HistoryDepth, p.Verified, p.BlocksTraversed,
			p.RecordsReturned, p.EvidenceBytes,
			p.AuthorizationTime, p.RetrievalTime, p.VerificationTime)
	}

	clockUsable := metrics.RequireUsableClock() == nil
	if !clockUsable {
		t.Log("clock too coarse for sub-tick assertions; structural checks still run")
	}

	for _, p := range res.Points {
		if !p.Verified {
			t.Errorf("ledger %d depth %d did not verify", p.LedgerSize, p.HistoryDepth)
		}
		if p.Semantics != string(scheme.SemanticsPerTxProvenance) {
			t.Errorf("semantics %q, want per_tx_provenance", p.Semantics)
		}
		if p.RecordsReturned != p.HistoryDepth {
			t.Errorf("ledger %d depth %d returned %d records, want %d",
				p.LedgerSize, p.HistoryDepth, p.RecordsReturned, p.HistoryDepth)
		}
		// Timed only where the host can resolve it. Phase 6 Step 1 is a
		// Schnorr sign and verify — a couple of hundred microseconds, which is
		// inside a single tick on a Windows developer clock (~500us here) and
		// correctly reports zero. That the step RAN is already established by
		// Verified: an unauthorized query returns before retrieval with no
		// history at all, so a verified result with records could not have
		// skipped it.
		if clockUsable && p.AuthorizationTime <= 0 {
			t.Errorf("ledger %d depth %d: auditor authorization was not timed",
				p.LedgerSize, p.HistoryDepth)
		}
	}

	// Blocks traversed is the claim Exp 3 exists to test. A tenfold ledger must
	// not move it.
	byLedger := map[int]int{}
	for _, p := range res.Points {
		if p.HistoryDepth != depths[0] {
			continue
		}
		byLedger[p.LedgerSize] = p.BlocksTraversed
	}
	if byLedger[4] != byLedger[40] {
		t.Errorf("audit read %d blocks at ledger 4 and %d at ledger 40; the "+
			"ledger-independence claim does not hold", byLedger[4], byLedger[40])
	}

	sc := res.LedgerScaling["zkredact"]
	t.Logf("scaling: %s (cost x%.2f over ledger x%.0f), claim holds: %v",
		sc.Class, sc.CostRatio, sc.SizeRatio, sc.ClaimHolds)
	if !sc.ClaimHolds {
		t.Error("zkredact declares LedgerIndependentAudit but scaled linearly")
	}
}
