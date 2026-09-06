package vc

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// Cross-commitment aggregation — Ref[13] Eq. 11, the check both Algorithm 2
// (block query) and Algorithm 3 (blockchain auditing) reduce to.
//
// THE POINT OF IT. A single opening costs a pairing per commitment. A BAT path
// from a redacted block to the root has one commitment per level, and an audit
// challenges z of them at once. Verifying those one at a time makes Exp 3's cost
// linear in the number of pairings; aggregation collapses the whole set into ONE
// Miller loop and ONE final exponentiation, which is the property Ref[13] claims
// and therefore the property this baseline has to actually have.
//
// THE EQUATION. For a set of openings (C_i, c_i, v_{i,c}) with coefficients t_i:
//
//	PROD_i e(C_i^{t_i}, g2^{a^{N+1-c_i}}) = e(pi_hat, g2) * gT_{N+1}^{mu_hat}
//
// where pi_hat = PROD_i pi_i^{t_i} and mu_hat = SUM_i v_{i,c} * t_i, matching
// Algorithm 2 lines 13 and Algorithm 3 line 8.
//
// Scaling C_i in G1 rather than exponentiating the pairing result in GT is
// deliberate: a G1 scalar multiplication is far cheaper than a GT
// exponentiation, and the two are equal by bilinearity.
//
// WHY THE COEFFICIENTS MUST NOT BE THE PROVER'S CHOICE. With freely chosen t_i
// a prover can cancel one opening's error against another's, so the aggregate
// verifies while no individual opening does — the same cancellation that makes
// zk.batchVerifyAggregated insist on verifier-sampled randomness. Ref[13] binds
// them instead of sampling them: t = H2(c, C, v[c]) in Algorithm 2 line 3 and
// Algorithm 3 line 6, which is a hash over the very values being proved, so a
// prover cannot move one without changing it. DeriveCoefficient implements that
// binding, and TestAggregateRejectsCancellingErrors is the test that a
// free-coefficient version would fail.

// Opening is one position of one commitment, with the coefficient it enters the
// aggregate under.
type Opening struct {
	// C is the commitment being opened.
	C curve.G1Affine

	// Pos is c, the 1-indexed position within the committed vector.
	Pos int

	// Value is v_{i,c}, the value claimed at that position.
	Value fr.Element

	// Coeff is t_i. Use DeriveCoefficient unless the caller has its own
	// binding: an unbound coefficient makes the aggregate forgeable.
	Coeff fr.Element
}

// DeriveCoefficient computes t = H2(c || C || value), Ref[13]'s binding for the
// aggregation coefficient.
//
// H2 is SHA-256 because security.hash is, and a scheme that reached for a
// different primitive would be running at a security level the config does not
// describe. The ref13 scheme's Setup calls crypto.RequireHash for the same
// reason pkg/crypto's Schnorr path does: the config field can be changed, and
// nothing else would notice.
//
// Two domain-separated blocks are read and reduced together rather than one.
// A single 256-bit digest reduced modulo a 255-bit field order is biased, and
// while the bias is far too small to matter here, an aggregation coefficient is
// exactly the value an attacker would like to predict. The extra block costs one
// compression function call, against the pairing this coefficient sits in front
// of.
func DeriveCoefficient(pos int, c curve.G1Affine, value fr.Element) fr.Element {
	cb := c.Bytes()
	vb := value.Bytes()

	var posBytes [8]byte
	binary.BigEndian.PutUint64(posBytes[:], uint64(pos))

	block := func(counter byte) []byte {
		h := sha256.New()
		h.Write([]byte("ref13/vc/coefficient"))
		h.Write([]byte{counter})
		h.Write(posBytes[:])
		h.Write(cb[:])
		h.Write(vb[:])
		return h.Sum(nil)
	}

	wide := append(block(0), block(1)...)

	var out fr.Element
	out.SetBigInt(new(big.Int).SetBytes(wide))
	return out
}

// AggregateOpen produces (pi_hat, mu_hat) for a set of openings.
//
// vectors[i] is the full committed vector behind openings[i], which the prover
// holds and the verifier does not. Algorithm 2 lines 4-13.
func (p *Params) AggregateOpen(vectors [][]fr.Element, openings []Opening) (curve.G1Affine, fr.Element, error) {
	var piHat curve.G1Affine
	var muHat fr.Element

	if len(vectors) != len(openings) {
		return piHat, muHat, fmt.Errorf(
			"vc: %d vectors for %d openings", len(vectors), len(openings))
	}
	if len(openings) == 0 {
		return piHat, muHat, fmt.Errorf("vc: nothing to aggregate")
	}

	var acc curve.G1Jac
	for i, o := range openings {
		pi, err := p.Open(vectors[i], o.Pos)
		if err != nil {
			return piHat, muHat, fmt.Errorf("vc: opening %d: %w", i, err)
		}

		var scaled curve.G1Affine
		scaled.ScalarMultiplication(&pi, o.Coeff.BigInt(new(big.Int)))
		acc.AddMixed(&scaled)

		// mu_hat = SUM v_{i,c} * t_i
		var term fr.Element
		term.Mul(&o.Value, &o.Coeff)
		muHat.Add(&muHat, &term)
	}

	piHat.FromJacobian(&acc)
	return piHat, muHat, nil
}

// AggregateVerify checks a whole set of openings with one pairing check.
//
//	PROD_i e(C_i^{t_i}, g2^{a^{N+1-c_i}}) * e(-pi_hat, g2) == gT_{N+1}^{mu_hat}
//
// n+1 pairings in one Miller loop, against 2n for verifying the openings
// individually — and one final exponentiation rather than n.
func (p *Params) AggregateVerify(openings []Opening, piHat curve.G1Affine, muHat fr.Element) (bool, error) {
	if len(openings) == 0 {
		return false, fmt.Errorf("vc: nothing to verify")
	}
	if !piHat.IsInSubGroup() {
		return false, nil
	}

	g1s := make([]curve.G1Affine, 0, len(openings)+1)
	g2s := make([]curve.G2Affine, 0, len(openings)+1)

	for i, o := range openings {
		if o.Pos < 1 || o.Pos > p.N {
			return false, fmt.Errorf(
				"vc: opening %d has position %d, outside [1, %d]", i, o.Pos, p.N)
		}
		if !o.C.IsInSubGroup() {
			return false, nil
		}

		var scaled curve.G1Affine
		scaled.ScalarMultiplication(&o.C, o.Coeff.BigInt(new(big.Int)))

		g1s = append(g1s, scaled)
		g2s = append(g2s, p.g2Pow[p.N+1-o.Pos])
	}

	var negPi curve.G1Affine
	negPi.Neg(&piHat)
	g1s = append(g1s, negPi)
	_, _, _, g2 := curve.Generators()
	g2s = append(g2s, g2)

	lhs, err := curve.Pair(g1s, g2s)
	if err != nil {
		return false, fmt.Errorf("vc: aggregated pairing check: %w", err)
	}

	var rhs curve.GT
	rhs.Exp(p.gtNPlus1, muHat.BigInt(new(big.Int)))

	return lhs.Equal(&rhs), nil
}

// aggregatePairingCount reports how many pairs an AggregateVerify of n openings
// hands to the pairing engine. Test scaffolding for the cost claim; it computes
// nothing cryptographic.
func aggregatePairingCount(n int) int { return n + 1 }
