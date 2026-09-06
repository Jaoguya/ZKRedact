package vc

import (
	"fmt"
	"math/big"
	"testing"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// THE TESTING PROBLEM THIS FILE EXISTS TO SOLVE.
//
// There is no reference implementation of Ref[13]'s vector commitment to check
// against, and no published test vectors. A construction that is wrong but
// internally consistent — Commit, Open and Verify all agreeing on the same
// mistaken algebra — passes every round-trip test while producing numbers that
// mean nothing. docs/baselines/ref13-vrbc.md calls this the main implementation
// risk, and it is.
//
// So round-trip tests are necessary but not sufficient, and the tests below are
// built on two things that are not round trips:
//
//  1. The exponents are recomputed DIRECTLY from the algebraic definition, with
//     alpha known to the test, using single scalar multiplications rather than
//     the production path's MSM over the reference string. Two independent
//     routes to the same point is evidence; one route agreeing with itself is
//     not.
//
//  2. The soundness property is tested by actually forging, using the parameter
//     the reference string withholds. That test fails if the omission is ever
//     "fixed" to match Eq. 3 as printed.

// directSRS builds the reference string from a KNOWN alpha, including the
// element production withholds. Deliberately naive: no MSM, no shared helpers.
type directSRS struct {
	alpha  fr.Element
	n      int
	params *Params
}

func newDirectSRS(t *testing.T, n int) *directSRS {
	t.Helper()

	var alpha fr.Element
	if _, err := alpha.SetRandom(); err != nil {
		t.Fatalf("sample alpha: %v", err)
	}

	_, _, g1, g2 := curve.Generators()

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
			continue
		}
		p.g1Pow[j].ScalarMultiplication(&g1, powers[j].BigInt(new(big.Int)))
		p.g1HasPow[j] = true
	}
	for j := 1; j <= n; j++ {
		p.g2Pow[j].ScalarMultiplication(&g2, powers[j].BigInt(new(big.Int)))
	}

	var g1NPlus1 curve.G1Affine
	g1NPlus1.ScalarMultiplication(&g1, powers[n+1].BigInt(new(big.Int)))
	gt, err := curve.Pair([]curve.G1Affine{g1NPlus1}, []curve.G2Affine{g2})
	if err != nil {
		t.Fatalf("precompute gT: %v", err)
	}
	p.gtNPlus1 = gt

	return &directSRS{alpha: alpha, n: n, params: p}
}

// alphaPow returns alpha^j as a field element.
func (d *directSRS) alphaPow(j int) fr.Element {
	var out fr.Element
	out.SetOne()
	for k := 0; k < j; k++ {
		out.Mul(&out, &d.alpha)
	}
	return out
}

// withheldG1 returns g1^{alpha^{N+1}} — the element the reference string does
// NOT publish. Only a test that knows alpha can form it.
func (d *directSRS) withheldG1() curve.G1Affine {
	_, _, g1, _ := curve.Generators()
	e := d.alphaPow(d.n + 1)
	var out curve.G1Affine
	out.ScalarMultiplication(&g1, e.BigInt(new(big.Int)))
	return out
}

// directCommit computes g1^{SUM_j v_j alpha^j} as ONE scalar multiplication by
// a directly evaluated exponent — no reference string, no MSM.
func (d *directSRS) directCommit(v []fr.Element) curve.G1Affine {
	var exp fr.Element
	for j := 1; j <= d.n; j++ {
		a := d.alphaPow(j)
		var term fr.Element
		term.Mul(&v[j-1], &a)
		exp.Add(&exp, &term)
	}
	_, _, g1, _ := curve.Generators()
	var out curve.G1Affine
	out.ScalarMultiplication(&g1, exp.BigInt(new(big.Int)))
	return out
}

// directOpen computes pi_i = g1^{SUM_{j != i} v_j alpha^{N+1-i+j}} the same way.
func (d *directSRS) directOpen(v []fr.Element, i int) curve.G1Affine {
	var exp fr.Element
	for j := 1; j <= d.n; j++ {
		if j == i {
			continue
		}
		a := d.alphaPow(d.n + 1 - i + j)
		var term fr.Element
		term.Mul(&v[j-1], &a)
		exp.Add(&exp, &term)
	}
	_, _, g1, _ := curve.Generators()
	var out curve.G1Affine
	out.ScalarMultiplication(&g1, exp.BigInt(new(big.Int)))
	return out
}

// TestCommitMatchesDirectlyComputedExponent is check (1) for the commitment:
// the MSM over the reference string must land on the same point as evaluating
// the exponent directly.
func TestCommitMatchesDirectlyComputedExponent(t *testing.T) {
	d := newDirectSRS(t, 8)
	v, err := RandomVector(d.n)
	if err != nil {
		t.Fatalf("RandomVector: %v", err)
	}

	got, err := d.params.Commit(v)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	want := d.directCommit(v)

	if !got.Equal(&want) {
		t.Error("Commit disagrees with the directly evaluated exponent; the MSM " +
			"over the reference string is not computing g1^{SUM v_j a^j}")
	}
}

// TestOpenMatchesDirectlyComputedExponent is the same check for the opening,
// at every position — the exponent N+1-i+j shifts with i, and an off-by-one
// there would still round-trip against a matching verifier.
func TestOpenMatchesDirectlyComputedExponent(t *testing.T) {
	d := newDirectSRS(t, 8)
	v, err := RandomVector(d.n)
	if err != nil {
		t.Fatalf("RandomVector: %v", err)
	}

	for i := 1; i <= d.n; i++ {
		got, err := d.params.Open(v, i)
		if err != nil {
			t.Fatalf("Open(%d): %v", i, err)
		}
		want := d.directOpen(v, i)
		if !got.Equal(&want) {
			t.Errorf("Open(%d) disagrees with the directly evaluated exponent", i)
		}
	}
}

// TestRoundTripAtEveryPosition is the correctness property, run against
// production Setup rather than the test's own SRS.
func TestRoundTripAtEveryPosition(t *testing.T) {
	const n = 8
	p, err := Setup(n)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	v, err := RandomVector(n)
	if err != nil {
		t.Fatalf("RandomVector: %v", err)
	}
	c, err := p.Commit(v)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	for i := 1; i <= n; i++ {
		pi, err := p.Open(v, i)
		if err != nil {
			t.Fatalf("Open(%d): %v", i, err)
		}
		ok, err := p.Verify(c, i, v[i-1], pi)
		if err != nil {
			t.Fatalf("Verify(%d): %v", i, err)
		}
		if !ok {
			t.Errorf("position %d: valid opening rejected", i)
		}
	}
}

// TestVerifyRejectsAWrongValue is the negative that a broken verifier would
// fail: an always-accept Verify passes every test above.
func TestVerifyRejectsAWrongValue(t *testing.T) {
	const n = 4
	p, err := Setup(n)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	v, err := RandomVector(n)
	if err != nil {
		t.Fatalf("RandomVector: %v", err)
	}
	c, err := p.Commit(v)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	pi, err := p.Open(v, 2)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	var wrong fr.Element
	wrong.Add(&v[1], new(fr.Element).SetOne())

	ok, err := p.Verify(c, 2, wrong, pi)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Error("a value one greater than the committed one was accepted")
	}
}

// TestVerifyRejectsAProofForAnotherPosition catches the shift error that the
// direct-exponent tests are aimed at, from the verifier's side.
func TestVerifyRejectsAProofForAnotherPosition(t *testing.T) {
	const n = 4
	p, err := Setup(n)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	v, err := RandomVector(n)
	if err != nil {
		t.Fatalf("RandomVector: %v", err)
	}
	c, err := p.Commit(v)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	pi3, err := p.Open(v, 3)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Present position 3's proof as though it opened position 2.
	ok, err := p.Verify(c, 2, v[1], pi3)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Error("a proof for position 3 verified at position 2")
	}
}

// TestForgeryNeedsTheOmittedParameter is the soundness test, and the reason the
// reference string departs from Eq. 3 as printed.
//
// Knowing g1^{a^{N+1}}, a forger takes a valid opening and shifts it to ANY
// claimed value:
//
//	pi' = pi * (g1^{a^{N+1}})^{(v_i - v')}
//
// which satisfies the verification equation exactly. The test performs that
// forgery with the withheld element to show it works, then confirms the element
// is genuinely absent from published parameters — so a forger holding only pp
// cannot take this route.
func TestForgeryNeedsTheOmittedParameter(t *testing.T) {
	d := newDirectSRS(t, 4)
	p := d.params

	v, err := RandomVector(d.n)
	if err != nil {
		t.Fatalf("RandomVector: %v", err)
	}
	c, err := p.Commit(v)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	const pos = 2
	pi, err := p.Open(v, pos)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Any value at all — the point is that the forger picks it freely.
	var claimed fr.Element
	claimed.SetUint64(999999)

	var delta fr.Element
	delta.Sub(&v[pos-1], &claimed)

	var shift, forged curve.G1Affine
	withheld := d.withheldG1()
	shift.ScalarMultiplication(&withheld, delta.BigInt(new(big.Int)))
	forged.Add(&pi, &shift)

	ok, err := p.Verify(c, pos, claimed, forged)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("the forgery did not verify — either the verification equation " +
			"is not the one this construction implements, or the shift is wrong; " +
			"both mean the soundness argument here is not being tested")
	}

	// The forgery works, so everything rests on the element being unpublished.
	if p.HasParameter(d.n + 1) {
		t.Errorf("g1^{a^%d} is published, so the forgery above is available to "+
			"anyone holding pp; Eq. 3 as printed includes it, and following that "+
			"literally makes the commitment trivially forgeable", d.n+1)
	}
}

// TestSetupWithholdsExactlyOneParameter pins the shape of the reference string:
// every exponent in [1, 2N] except N+1, and nothing else.
func TestSetupWithholdsExactlyOneParameter(t *testing.T) {
	const n = 6
	p, err := Setup(n)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}

	for j := 1; j <= 2*n; j++ {
		want := j != n+1
		if got := p.HasParameter(j); got != want {
			t.Errorf("HasParameter(%d) = %v, want %v", j, got, want)
		}
	}
}

// TestOpenNeverRequestsTheWithheldParameter states the prover-side reason the
// omission costs nothing: no opening's exponents include N+1.
func TestOpenNeverRequestsTheWithheldParameter(t *testing.T) {
	const n = 16
	p, err := Setup(n)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	v, err := RandomVector(n)
	if err != nil {
		t.Fatalf("RandomVector: %v", err)
	}
	for i := 1; i <= n; i++ {
		if _, err := p.Open(v, i); err != nil {
			t.Errorf("Open(%d) needed a withheld parameter: %v", i, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Cost, for re-estimating task 7 from measured ground rather than from the
// paper's asymptotics.
//
// N = q+1, and config/experiment.yaml sweeps arity_q over [2, 5, 10], so the
// vectors this scheme actually commits to are tiny. That is the number that
// matters for the estimate: the BAT's cost is dominated by the number of NODES
// on a path, not by the width of any one commitment.
// ---------------------------------------------------------------------------

func benchN(b *testing.B, n int, fn func(*testing.B, *Params, []fr.Element)) {
	b.Helper()
	p, err := Setup(n)
	if err != nil {
		b.Fatalf("Setup: %v", err)
	}
	v, err := RandomVector(n)
	if err != nil {
		b.Fatalf("RandomVector: %v", err)
	}
	b.ResetTimer()
	fn(b, p, v)
}

func BenchmarkCommit(b *testing.B) {
	for _, n := range []int{3, 6, 11, 64} {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			benchN(b, n, func(b *testing.B, p *Params, v []fr.Element) {
				for i := 0; i < b.N; i++ {
					if _, err := p.Commit(v); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

func BenchmarkOpen(b *testing.B) {
	for _, n := range []int{3, 6, 11, 64} {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			benchN(b, n, func(b *testing.B, p *Params, v []fr.Element) {
				for i := 0; i < b.N; i++ {
					if _, err := p.Open(v, 1); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	for _, n := range []int{3, 6, 11, 64} {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			benchN(b, n, func(b *testing.B, p *Params, v []fr.Element) {
				c, err := p.Commit(v)
				if err != nil {
					b.Fatal(err)
				}
				pi, err := p.Open(v, 1)
				if err != nil {
					b.Fatal(err)
				}
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := p.Verify(c, 1, v[0], pi); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}
