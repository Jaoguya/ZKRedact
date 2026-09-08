package crypto

import (
	"crypto/rand"
	"testing"
)

// BenchmarkCommitteeRound is one Ref[10] authorization: every committee member
// signs the request, and the verifier checks every ballot.
//
// It exists to answer a question the Exp 1 figure will otherwise only answer
// after a paid run — whether ZK-Redact's Groth16 verification is competitive
// with a committee vote once consensus is taken out of it. The in-process arm
// is the like-for-like control, and a control nobody has costed is a control
// nobody can interpret.
func BenchmarkCommitteeRound(b *testing.B) {
	const committee = 7 // config/experiment.yaml: baselines.ref10_emt.committee_size

	curve, err := SignatureCurve("P-256", 128)
	if err != nil {
		b.Fatal(err)
	}
	keys := make([]*SchnorrPrivateKey, committee)
	for i := range keys {
		if keys[i], err = SchnorrKeyGen(curve, rand.Reader); err != nil {
			b.Fatal(err)
		}
	}
	msg := []byte("redaction request: tx-000042 v3 loc-7")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		votes := make([]Vote, 0, committee)
		for _, k := range keys {
			sig, err := k.Sign(msg, rand.Reader)
			if err != nil {
				b.Fatal(err)
			}
			votes = append(votes, Vote{Key: &k.SchnorrPublicKey, Signature: sig})
		}
		if n := VerifyVotes(msg, votes); n != committee {
			b.Fatalf("verified %d of %d", n, committee)
		}
	}
}
