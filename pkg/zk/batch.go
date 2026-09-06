package zk

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	groth16bls "github.com/consensys/gnark/backend/groth16/bls12-381"
)

// batchVerifyAggregated checks n proofs with one aggregated pairing check.
//
// THE EQUATION. gnark's single verification is
//
//	e(Ar, Bs) * e(-Krs, delta) * e(-kSum, gamma) * e(-alpha, beta) = 1
//
// where kSum = K[0] + SUM_j w_j * K[j+1] over the proof's public inputs. Three
// pairings per proof, so 3n for a batch.
//
// With verifier-chosen random scalars r_i the same identity batches to
//
//	PROD_i e(r_i * Ar_i, Bs_i)
//	  * e(-(SUM r_i Krs_i), delta)
//	  * e(-(SUM r_i kSum_i), gamma)
//	  * e(-(SUM r_i) * alpha, beta)  =  1
//
// Only e(Ar_i, Bs_i) stays per-proof, because both arguments vary with the
// proof. delta, gamma and beta are fixed by the verifying key, so those three
// pairings aggregate across the whole batch: n+3 pairings instead of 3n, about
// 2.7x at n=32. It is NOT sublinear, and it works fine over distinct public
// inputs — which is what a batch of authorizations is.
//
// WHY THE SCALARS MUST BE THE VERIFIER'S AND UNPREDICTABLE. Without them a
// prover could submit two proofs whose errors cancel in the product: the batch
// would pass while neither proof verifies alone. Sampled here from crypto/rand,
// after the proofs are in hand.
//
// Returns (true, nil) when the whole batch verifies. A false result says only
// that SOMETHING in the batch is wrong, never which — the caller isolates.
func batchVerifyAggregated(p *Params, proofs []*Proof) (bool, error) {
	vk, ok := p.VK.(*groth16bls.VerifyingKey)
	if !ok {
		return false, fmt.Errorf("zk: verifying key is %T, not BLS12-381 Groth16", p.VK)
	}
	if len(vk.PublicAndCommitmentCommitted) != 0 || len(vk.CommitmentKeys) != 0 {
		// Pedersen commitments change the verification identity, and the circuit
		// here has none. Refusing beats silently checking the wrong equation.
		return false, fmt.Errorf("zk: batch verification does not cover Pedersen commitments")
	}

	n := len(proofs)
	scalars := make([]fr.Element, n)
	arPoints := make([]curve.G1Affine, n)
	bsPoints := make([]curve.G2Affine, n)
	krs := make([]curve.G1Affine, n)
	kSums := make([]curve.G1Affine, n)

	var rSum fr.Element

	for i, pr := range proofs {
		gp, ok := pr.Proof.(*groth16bls.Proof)
		if !ok {
			return false, fmt.Errorf("zk: proof %d is %T, not BLS12-381 Groth16", i, pr.Proof)
		}
		if len(gp.Commitments) != 0 {
			return false, fmt.Errorf("zk: proof %d carries Pedersen commitments", i)
		}

		// Subgroup checks. gnark's single Verify does these internally; a batch
		// that skipped them could be satisfied with small-order points, so the
		// aggregation would accept proofs the individual path rejects.
		if !gp.Ar.IsInSubGroup() || !gp.Krs.IsInSubGroup() || !gp.Bs.IsInSubGroup() {
			return false, nil
		}

		pub, err := publicVector(pr)
		if err != nil {
			return false, err
		}
		if len(pub) != len(vk.G1.K)-1 {
			return false, fmt.Errorf(
				"zk: proof %d has %d public inputs, verifying key expects %d",
				i, len(pub), len(vk.G1.K)-1)
		}

		// kSum_i = K[0] + SUM_j w_j * K[j+1]
		var kJac curve.G1Jac
		if _, err := kJac.MultiExp(vk.G1.K[1:], pub, ecc.MultiExpConfig{}); err != nil {
			return false, fmt.Errorf("zk: public input MSM for proof %d: %w", i, err)
		}
		kJac.AddMixed(&vk.G1.K[0])
		kSums[i].FromJacobian(&kJac)

		if _, err := scalars[i].SetRandom(); err != nil {
			return false, fmt.Errorf("zk: batch randomness: %w", err)
		}
		rSum.Add(&rSum, &scalars[i])

		arPoints[i].ScalarMultiplication(&gp.Ar, scalars[i].BigInt(new(big.Int)))
		bsPoints[i] = gp.Bs
		krs[i] = gp.Krs
	}

	// SUM r_i * Krs_i and SUM r_i * kSum_i, each one multi-exponentiation.
	var krsAgg, kAgg curve.G1Jac
	if _, err := krsAgg.MultiExp(krs, scalars, ecc.MultiExpConfig{}); err != nil {
		return false, fmt.Errorf("zk: Krs aggregation: %w", err)
	}
	if _, err := kAgg.MultiExp(kSums, scalars, ecc.MultiExpConfig{}); err != nil {
		return false, fmt.Errorf("zk: public input aggregation: %w", err)
	}

	var krsAff, kAff, alphaAgg curve.G1Affine
	krsAff.FromJacobian(&krsAgg)
	kAff.FromJacobian(&kAgg)
	alphaAgg.ScalarMultiplication(&vk.G1.Alpha, rSum.BigInt(new(big.Int)))

	// The three aggregated terms enter negated, so the whole product is 1.
	krsAff.Neg(&krsAff)
	kAff.Neg(&kAff)
	alphaAgg.Neg(&alphaAgg)

	g1 := append(arPoints, krsAff, kAff, alphaAgg)
	g2 := append(bsPoints, vk.G2.Delta, vk.G2.Gamma, vk.G2.Beta)

	lastG1, lastG2 = g1, g2

	ok, err := curve.PairingCheck(g1, g2)
	if err != nil {
		return false, fmt.Errorf("zk: batch pairing check: %w", err)
	}
	return ok, nil
}

// publicVector extracts a proof's public inputs as field elements.
func publicVector(pr *Proof) (fr.Vector, error) {
	if pr.Witness == nil {
		return nil, fmt.Errorf("zk: proof carries no public witness")
	}
	v, ok := pr.Witness.Vector().(fr.Vector)
	if !ok {
		return nil, fmt.Errorf("zk: public witness is %T, not a BLS12-381 vector", pr.Witness.Vector())
	}
	return v, nil
}

// lastG1/lastG2 retain the most recent PairingCheck inputs so a test can count
// them. Test scaffolding only: nothing reads them in a measured run.
var lastG1 []curve.G1Affine
var lastG2 []curve.G2Affine

// batchPairingInputs runs the aggregation and returns the points that were
// actually paired.
func batchPairingInputs(p *Params, proofs []*Proof) ([]curve.G1Affine, []curve.G2Affine, error) {
	if _, err := batchVerifyAggregated(p, proofs); err != nil {
		return nil, nil, err
	}
	return lastG1, lastG2, nil
}
