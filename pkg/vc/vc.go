// Package vc implements the Pointproofs-style aggregatable vector commitment
// that Ref[13]'s blockchain authentication tree is built on.
//
// SCOPE: THIS IS THE TASK 7 SPIKE. It covers the commitment and a single
// position opening — the core Ref[13] §3.2.1-§3.2.2 needs — so the construction
// can be checked against the paper's equations before the BAT, aggregation and
// redaction path are built on top of it. It is deliberately not the whole
// scheme; see docs/baselines/ref13-vrbc.md §1.2.
//
// THE CONSTRUCTION (Ref[13] Eq. 3, 4, 6; Gorbunov et al., CCS 2020).
//
// Public parameters over a bilinear group with e : G1 x G2 -> GT:
//
//	g1^{a^j}   for j in [1, N] and [N+2, 2N]     <- note the omission
//	g2^{a^j}   for j in [1, N]
//	gT_{N+1} = e(g1, g2)^{a^{N+1}}
//
// Commit to v = (v_1, ..., v_N):     C = g1^{SUM_j v_j a^j}
// Open position i:                   pi_i = PROD_{j != i} (g1^{a^{N+1-i+j}})^{v_j}
// Verify:                            e(C, g2^{a^{N+1-i}}) = e(pi_i, g2) * gT_{N+1}^{v_i}
//
// The verification identity is why the opening works: expanding the left side
// separates into the j = i term, which is exactly gT_{N+1}^{v_i}, and every
// other term, which is what pi_i aggregates.
//
// WHY g1^{a^{N+1}} IS ABSENT, AND WHY THAT IS NOT A TRANSCRIPTION SLIP.
// Ref[13] Eq. 3 as printed gives the second parameter vector as
// (g1^{a^{N+1}}, ..., g1^{a^{2N}}), which would publish g1^{a^{N+1}}. That
// cannot be what the scheme intends, and the paper's own soundness proof is the
// evidence: Eq. 20 reduces a forgery to computing g1^{a^{N+1}(mu' - mu)} and
// calls that a solution to the l-wBDHE problem. If pp contained g1^{a^{N+1}}
// the reduction would be vacuous — an adversary could forge an opening for any
// claimed value by scaling it directly, with no hard problem in the way.
//
// So the exponent runs [N+2, 2N] here. An implementation that followed Eq. 3
// literally would produce a construction that PASSES every correctness test
// and is trivially forgeable, which is this project's core failure mode in its
// worst form. Pinned by TestForgeryNeedsTheOmittedParameter.
//
// The prover never needs the omitted element: for j != i the exponent
// N+1-i+j lands in [2, 2N] and equals N+1 only when j = i.
//
// TRAPDOOR. alpha is sampled here and discarded, exactly as
// accumulator.GenerateUntrusted does for the RSA modulus, and for the same
// reason: this measures COST, and every operation's cost depends on N and the
// group, not on who knew alpha. A deployment needs a ceremony. Recorded as a
// deviation in docs/baselines/ref13-vrbc.md.
package vc

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// Params is the structured reference string.
type Params struct {
	// N is the vector length, q+1 in Ref[13]'s q-ary BAT.
	N int

	// g1Pow holds g1^{a^j} indexed by j, for j in [1, N] and [N+2, 2N].
	// Index N+1 is present in the slice but never populated; see the package
	// comment. g1Pow[0] is unused so the index matches the exponent.
	g1Pow []curve.G1Affine

	// g1HasPow reports which exponents were actually published. Consulted on
	// every access so a coding error reads as an error rather than as a
	// silently wrong point at infinity.
	g1HasPow []bool

	// g2Pow holds g2^{a^j} for j in [1, N], same indexing.
	g2Pow []curve.G2Affine

	// gtNPlus1 is e(g1, g2)^{a^{N+1}}. Public: it lives in GT, and publishing
	// it does not reveal g1^{a^{N+1}}.
	gtNPlus1 curve.GT
}

// Setup samples alpha and builds the reference string for vectors of length N.
//
// The trapdoor is discarded on return. Cost is 3N scalar multiplications plus
// one pairing, and it is not on any measured path — Ref[13]'s Setup is
// untimed, like every other scheme's.
func Setup(n int) (*Params, error) {
	if n < 1 {
		return nil, fmt.Errorf("vc: vector length must be >= 1, got %d", n)
	}

	var alpha fr.Element
	if _, err := alpha.SetRandom(); err != nil {
		return nil, fmt.Errorf("vc: sample alpha: %w", err)
	}

	_, _, g1, g2 := curve.Generators()

	// alpha^j for j in [1, 2N], as field elements first.
	powers := make([]fr.Element, 2*n+1)
	powers[0].SetOne()
	for j := 1; j <= 2*n; j++ {
		powers[j].Mul(&powers[j-1], &alpha)
	}

	p := &Params{
		N:        n,
		g1Pow:    make([]curve.G1Affine, 2*n+1),
		g1HasPow: make([]bool, 2*n+1),
		g2Pow:    make([]curve.G2Affine, n+1),
	}

	for j := 1; j <= 2*n; j++ {
		if j == n+1 {
			// Withheld. See the package comment: publishing this breaks the
			// soundness reduction the paper's Eq. 20 relies on.
			continue
		}
		p.g1Pow[j].ScalarMultiplication(&g1, powers[j].BigInt(new(big.Int)))
		p.g1HasPow[j] = true
	}
	for j := 1; j <= n; j++ {
		p.g2Pow[j].ScalarMultiplication(&g2, powers[j].BigInt(new(big.Int)))
	}

	// gT_{N+1} = e(g1^{a^{N+1}}, g2), computed here while alpha is still in
	// scope and the G1 point can be formed transiently.
	var g1NPlus1 curve.G1Affine
	g1NPlus1.ScalarMultiplication(&g1, powers[n+1].BigInt(new(big.Int)))
	gt, err := curve.Pair([]curve.G1Affine{g1NPlus1}, []curve.G2Affine{g2})
	if err != nil {
		return nil, fmt.Errorf("vc: precompute gT^{a^{N+1}}: %w", err)
	}
	p.gtNPlus1 = gt

	return p, nil
}

// Commit produces C = g1^{SUM_j v_j a^j} for a vector of length N.
//
// One multi-exponentiation, which is where the cost is: Ref[13] pays this on
// every block append, and again on every node along the path from a redacted
// block to the root.
func (p *Params) Commit(v []fr.Element) (curve.G1Affine, error) {
	var c curve.G1Affine
	if len(v) != p.N {
		return c, fmt.Errorf("vc: vector has %d entries, parameters are for %d", len(v), p.N)
	}

	points := make([]curve.G1Affine, p.N)
	for j := 1; j <= p.N; j++ {
		if !p.g1HasPow[j] {
			return c, fmt.Errorf("vc: parameter g1^{a^%d} is not published", j)
		}
		points[j-1] = p.g1Pow[j]
	}

	var jac curve.G1Jac
	if _, err := jac.MultiExp(points, v, ecc.MultiExpConfig{}); err != nil {
		return c, fmt.Errorf("vc: commitment MSM: %w", err)
	}
	c.FromJacobian(&jac)
	return c, nil
}

// Open produces the proof for position i (1-indexed, matching the paper).
//
//	pi_i = PROD_{j != i} (g1^{a^{N+1-i+j}})^{v_j}
//
// The j = i term is skipped, which is the only reason the omitted parameter is
// never required.
func (p *Params) Open(v []fr.Element, i int) (curve.G1Affine, error) {
	var pi curve.G1Affine
	if len(v) != p.N {
		return pi, fmt.Errorf("vc: vector has %d entries, parameters are for %d", len(v), p.N)
	}
	if i < 1 || i > p.N {
		return pi, fmt.Errorf("vc: position %d out of range [1, %d]", i, p.N)
	}

	points := make([]curve.G1Affine, 0, p.N-1)
	scalars := make([]fr.Element, 0, p.N-1)
	for j := 1; j <= p.N; j++ {
		if j == i {
			continue
		}
		e := p.N + 1 - i + j
		if !p.g1HasPow[e] {
			// Reachable only if the j == i skip above is ever removed, which
			// would silently need the withheld parameter.
			return pi, fmt.Errorf(
				"vc: opening position %d needs the withheld parameter g1^{a^%d}", i, e)
		}
		points = append(points, p.g1Pow[e])
		scalars = append(scalars, v[j-1])
	}

	if len(points) == 0 {
		// N = 1: the proof is the identity, and verification reduces to
		// checking the commitment against gT_{N+1}^{v_1} alone.
		pi.X.SetZero()
		pi.Y.SetZero()
		return pi, nil
	}

	var jac curve.G1Jac
	if _, err := jac.MultiExp(points, scalars, ecc.MultiExpConfig{}); err != nil {
		return pi, fmt.Errorf("vc: opening MSM: %w", err)
	}
	pi.FromJacobian(&jac)
	return pi, nil
}

// Verify checks that C opens to value at position i with proof pi.
//
//	e(C, g2^{a^{N+1-i}}) == e(pi, g2) * gT_{N+1}^{value}
//
// Two pairings and one GT exponentiation. Ref[13]'s Eq. 11 aggregates this
// across a path; the aggregate form is not part of this spike.
func (p *Params) Verify(c curve.G1Affine, i int, value fr.Element, pi curve.G1Affine) (bool, error) {
	if i < 1 || i > p.N {
		return false, fmt.Errorf("vc: position %d out of range [1, %d]", i, p.N)
	}

	// Subgroup checks, for the reason zk.batchVerifyAggregated does them: a
	// verifier that skips them accepts points a conforming one rejects.
	if !c.IsInSubGroup() || !pi.IsInSubGroup() {
		return false, nil
	}

	_, _, _, g2 := curve.Generators()

	// Rearranged to one pairing call:
	//
	//	e(C, g2^{a^{N+1-i}}) * e(-pi, g2) == gT_{N+1}^{value}
	//
	// Two Pair calls would run two Miller loops and two final exponentiations
	// for the same answer, and the final exponentiation is the expensive half.
	// The GT exponentiation on the right cannot be folded in the same way: the
	// element that would let it become a pairing is g1^{a^{N+1}}, which is
	// exactly what the reference string withholds.
	var negPi curve.G1Affine
	negPi.Neg(&pi)

	lhs, err := curve.Pair(
		[]curve.G1Affine{c, negPi},
		[]curve.G2Affine{p.g2Pow[p.N+1-i], g2},
	)
	if err != nil {
		return false, fmt.Errorf("vc: batched pairing check: %w", err)
	}

	var rhs curve.GT
	rhs.Exp(p.gtNPlus1, value.BigInt(new(big.Int)))

	return lhs.Equal(&rhs), nil
}

// HasParameter reports whether g1^{a^j} was published. Exported for the test
// that pins the omission.
func (p *Params) HasParameter(j int) bool {
	if j < 0 || j >= len(p.g1HasPow) {
		return false
	}
	return p.g1HasPow[j]
}

// RandomVector builds a random vector of length N, for tests and benchmarks.
func RandomVector(n int) ([]fr.Element, error) {
	v := make([]fr.Element, n)
	for i := range v {
		if _, err := v[i].SetRandom(); err != nil {
			return nil, fmt.Errorf("vc: sample vector: %w", err)
		}
	}
	return v, nil
}
