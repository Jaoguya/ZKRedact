package ref13

import (
	"context"
	"fmt"
	"testing"

	"zkredact/pkg/scheme"
)

// TestRedactTwoDifferentBlocks is the failure Exp 2 and Exp 3 hit.
//
// TestSchemeRunsEndToEnd redacts ONE block and passes, which is why this went
// unnoticed: the first redaction after Setup always works. Exp 2 redacted 20
// blocks and recorded succeeded=1, failed=19; Exp 3 could not build a history
// at all. Both reduce to this — a second redaction against a DIFFERENT block.
func TestRedactTwoDifferentBlocks(t *testing.T) {
	s := setupScheme(t, 5, 60, 8)
	ctx := context.Background()

	for i, target := range []string{"tx-10", "tx-20"} {
		auth, err := s.Authorize(ctx, &scheme.Request{
			ID:         fmt.Sprintf("r%d", i),
			TargetTxID: target,
			NewContent: []byte(fmt.Sprintf("replacement %d", i)),
		})
		if err != nil {
			t.Fatalf("Authorize %s: %v", target, err)
		}
		if !auth.Granted {
			t.Fatalf("Authorize %s denied: %s", target, auth.Reason)
		}

		res, err := s.Redact(ctx, []*scheme.Authorization{auth})
		if err != nil {
			t.Fatalf("Redact %s: %v", target, err)
		}
		if res.Succeeded != 1 {
			t.Fatalf("redaction %d of %s: Succeeded = %d, want 1 (failed %d, stale %d)",
				i+1, target, res.Succeeded, res.Failed, res.StaleExcluded)
		}
	}
}

// TestAdaptErrorIsReported names the error Redact currently swallows.
//
// Redact counts a failed adapt into res.Failed and moves on, so a caller sees a
// number with no cause. This drives the adapt directly to put the reason in the
// test log.
func TestAdaptErrorIsReported(t *testing.T) {
	s := setupScheme(t, 5, 60, 8)
	ctx := context.Background()

	redact := func(target string, content string) error {
		auth, err := s.Authorize(ctx, &scheme.Request{
			ID: "r", TargetTxID: target, NewContent: []byte(content),
		})
		if err != nil {
			return err
		}
		seq := s.blockOf[target]
		b := s.blocks[seq-1]
		blockCtx := blockContext(seq, b.prevHash)
		newDigest := blockDigest(b.core, []byte(content))
		_, err = s.key.EphemeralAdapt(blockCtx, b.digest, b.randomness, newDigest)
		if err != nil {
			return err
		}
		res, err := s.Redact(ctx, []*scheme.Authorization{auth})
		if err != nil {
			return err
		}
		if res.Succeeded != 1 {
			return fmt.Errorf("succeeded=%d failed=%d stale=%d",
				res.Succeeded, res.Failed, res.StaleExcluded)
		}
		return nil
	}

	if err := redact("tx-10", "first"); err != nil {
		t.Fatalf("first redaction: %v", err)
	}
	if err := redact("tx-20", "second"); err != nil {
		t.Fatalf("second redaction on a different block: %v", err)
	}
}
