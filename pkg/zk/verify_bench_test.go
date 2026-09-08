package zk

import "testing"

// BenchmarkVerifyOne is one ZK-Redact authorization check: the Groth16
// verification a proof shard performs per request.
//
// It exists to cost the Exp 1 comparison before the run rather than after.
// Ref[10]'s in-process arm is a committee round of Schnorr signatures
// (BenchmarkCommitteeRound in pkg/crypto), and whether that is cheaper or
// dearer than a proof verification decides how the Exp 1 figure reads at low
// concurrency — where sharding cannot help either scheme.
func BenchmarkVerifyOne(b *testing.B) {
	if batchParams == nil {
		p, err := Setup(testPredicateDepth, testTreeDepth, 128)
		if err != nil {
			b.Fatalf("Setup: %v", err)
		}
		batchParams = p
	}
	proofs := provenBatch(b, batchParams, 1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := Verify(batchParams, proofs[0]); err != nil {
			b.Fatalf("Verify: %v", err)
		}
	}
}
