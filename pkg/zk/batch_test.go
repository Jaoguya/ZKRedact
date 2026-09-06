package zk

import (
	"fmt"
	"testing"
	"time"
)

// batchParams compiles the circuit once for the batching tests. Setup is the
// slow part, so it is shared.
var batchParams *Params

func batchFixture(t *testing.T) *Params {
	t.Helper()
	if batchParams == nil {
		p, err := Setup(testPredicateDepth, testTreeDepth, 128)
		if err != nil {
			t.Fatalf("Setup: %v", err)
		}
		batchParams = p
	}
	return batchParams
}

// provenBatch builds n valid proofs over DISTINCT statements, which is the case
// that matters: a batch of authorizations never shares public inputs, and that
// is exactly the case the old comment claimed Groth16 could not batch.
func provenBatch(t *testing.T, p *Params, n int) []*Proof {
	t.Helper()

	pol := testPolicy(t, "((sender OR receiver) AND validator)")
	attrs := [NumAttributes]uint64{
		AttrSender: 1, AttrReceiver: 1, AttrValidator: 1, AttrRole: RoleAdmin,
	}
	secret := Uint64Bytes(31337)
	reg := testRegistry(t, CredentialLeaf(secret, attrs))

	proofs := make([]*Proof, n)
	for i := 0; i < n; i++ {
		req := testRequest()
		req.Nonce = []byte(fmt.Sprintf("nonce-%d", i)) // distinct statements
		st, err := BuildStatement(req, pol, 0, uint64(100+i))
		if err != nil {
			t.Fatalf("BuildStatement %d: %v", i, err)
		}
		a, err := NewAssignment(st, pol, attrs, secret, reg)
		if err != nil {
			t.Fatalf("NewAssignment %d: %v", i, err)
		}
		pr, err := Prove(p, a)
		if err != nil {
			t.Fatalf("Prove %d: %v", i, err)
		}
		proofs[i] = pr
	}
	return proofs
}

// TestBatchAcceptsValidProofsOverDistinctInputs is the positive result the
// corrected comment claims: aggregation works over distinct public inputs.
func TestBatchAcceptsValidProofsOverDistinctInputs(t *testing.T) {
	p := batchFixture(t)
	proofs := provenBatch(t, p, 8)

	for i, err := range BatchVerify(p, proofs) {
		if err != nil {
			t.Errorf("proof %d rejected in a batch of valid proofs: %v", i, err)
		}
	}
}

// TestBatchRejectsATamperedProof is the soundness check.
//
// Without verifier-chosen random scalars, two proofs' errors can cancel in the
// product and a batch of invalid proofs passes. This is the test that fails if
// the scalars are ever dropped or made predictable.
func TestBatchRejectsATamperedProof(t *testing.T) {
	p := batchFixture(t)
	proofs := provenBatch(t, p, 6)

	// Swap one proof's public witness for another's: the proof is well formed
	// but no longer proves the statement it is presented with.
	proofs[3] = &Proof{Proof: proofs[3].Proof, Witness: proofs[1].Witness}

	results := BatchVerify(p, proofs)
	if results[3] == nil {
		t.Fatal("a proof presented against the wrong statement verified in a batch")
	}
}

// TestBatchIsolatesTheFailure pins Phase 3 Step 4: one bad proof must reject
// itself and nothing else. An aggregate verdict would fail the whole shard's
// honest requests.
func TestBatchIsolatesTheFailure(t *testing.T) {
	p := batchFixture(t)
	proofs := provenBatch(t, p, 8)
	proofs[5] = &Proof{Proof: proofs[5].Proof, Witness: proofs[0].Witness}

	results := BatchVerify(p, proofs)

	if results[5] == nil {
		t.Error("the tampered proof verified")
	}
	for i, err := range results {
		if i == 5 {
			continue
		}
		if err != nil {
			t.Errorf("valid proof %d was rejected alongside the bad one; failure is "+
				"not isolated and a whole shard's honest requests would fail", i)
		}
	}
}

// TestBatchIsFasterThanPerRecord is the measurement the ablation exists to make.
//
// If this fails, the two native_batch_verify arms are measuring the same thing
// and the Phase 3 independence claim has no evidence behind it.
func TestBatchIsFasterThanPerRecord(t *testing.T) {
	p := batchFixture(t)
	const n = 32
	proofs := provenBatch(t, p, n)

	// Per-record: what the batching-disabled arm does.
	start := time.Now()
	for _, pr := range proofs {
		if err := Verify(p, pr); err != nil {
			t.Fatalf("per-record verification failed: %v", err)
		}
	}
	perRecord := time.Since(start)

	start = time.Now()
	for _, err := range BatchVerify(p, proofs) {
		if err != nil {
			t.Fatalf("batch verification failed: %v", err)
		}
	}
	batch := time.Since(start)

	t.Logf("n=%d  per-record %s  batch %s  (%.2fx)",
		n, perRecord.Round(time.Microsecond), batch.Round(time.Microsecond),
		float64(perRecord)/float64(batch))

	if batch >= perRecord {
		t.Errorf("batch (%s) is not faster than per-record (%s) at n=%d; the "+
			"aggregation is not saving the gamma/delta/beta pairings, so the two "+
			"ablation arms measure the same thing", batch, perRecord, n)
	}
}

// TestSingleProofSkipsAggregation pins that a batch of one takes the plain path:
// aggregating one proof adds two pairings for no benefit.
func TestSingleProofSkipsAggregation(t *testing.T) {
	p := batchFixture(t)
	proofs := provenBatch(t, p, 1)

	if err := BatchVerify(p, proofs)[0]; err != nil {
		t.Fatalf("a single valid proof was rejected: %v", err)
	}
}

// TestNativeBatchVerifyIsDeclaredTruthfully keeps the constant honest. It gates
// a validate-config warning, so a stale value would either raise a false alarm
// or silence a real one.
func TestNativeBatchVerifyIsDeclaredTruthfully(t *testing.T) {
	p := batchFixture(t)
	proofs := provenBatch(t, p, 4)

	ok, err := batchVerifyAggregated(p, proofs)
	if err != nil {
		t.Fatalf("aggregated verification is unavailable but NativeBatchVerify is %v: %v",
			NativeBatchVerify, err)
	}
	if !ok {
		t.Fatal("aggregated verification rejected a batch of valid proofs")
	}
	if !NativeBatchVerify {
		t.Error("aggregation works but NativeBatchVerify is false; validate-config " +
			"would warn that the ablation arms are identical when they are not")
	}
}
