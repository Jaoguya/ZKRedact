package zk

import "testing"

// TestBatchReallyDoesNPlus3Pairings counts the actual pairing inputs.
//
// "n+3" must be a description of what the code does, not an arithmetic claim in
// a comment. This reads the slices handed to gnark-crypto's PairingCheck.
func TestBatchReallyDoesNPlus3Pairings(t *testing.T) {
	p := batchFixture(t)

	for _, n := range []int{2, 4, 8, 16} {
		proofs := provenBatch(t, p, n)
		g1, g2, err := batchPairingInputs(p, proofs)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		if len(g1) != n+3 || len(g2) != n+3 {
			t.Errorf("n=%d: PairingCheck got %d G1 and %d G2 points, want %d",
				n, len(g1), len(g2), n+3)
		}
		t.Logf("n=%-3d -> PairingCheck over %d pairs (per-record would be %d)",
			n, len(g1), 3*n)
	}
}
