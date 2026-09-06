package vc

import (
	"fmt"
	"testing"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// buildOpenings makes k vectors, commits each, and opens one position of each
// with the paper's bound coefficient.
func buildOpenings(t *testing.T, p *Params, k int) ([][]fr.Element, []Opening) {
	t.Helper()

	vectors := make([][]fr.Element, k)
	openings := make([]Opening, k)
	for i := 0; i < k; i++ {
		v, err := RandomVector(p.N)
		if err != nil {
			t.Fatalf("RandomVector: %v", err)
		}
		c, err := p.Commit(v)
		if err != nil {
			t.Fatalf("Commit: %v", err)
		}
		pos := (i % p.N) + 1
		vectors[i] = v
		openings[i] = Opening{
			C:     c,
			Pos:   pos,
			Value: v[pos-1],
			Coeff: DeriveCoefficient(pos, c, v[pos-1]),
		}
	}
	return vectors, openings
}

// TestAggregateVerifiesAWholePath is the correctness property Eq. 11 states,
// at the sizes a BAT path actually reaches.
func TestAggregateVerifiesAWholePath(t *testing.T) {
	p, err := Setup(6)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}

	for _, k := range []int{1, 2, 5, 12} {
		t.Run(fmt.Sprintf("k=%d", k), func(t *testing.T) {
			vectors, openings := buildOpenings(t, p, k)

			piHat, muHat, err := p.AggregateOpen(vectors, openings)
			if err != nil {
				t.Fatalf("AggregateOpen: %v", err)
			}
			ok, err := p.AggregateVerify(openings, piHat, muHat)
			if err != nil {
				t.Fatalf("AggregateVerify: %v", err)
			}
			if !ok {
				t.Error("a valid aggregated proof was rejected")
			}
		})
	}
}

// TestAggregateOfOneMatchesTheSingleOpening ties the aggregate path to the
// single-opening path that was checked against directly evaluated exponents.
// Without this the two could drift apart and each still look self-consistent.
func TestAggregateOfOneMatchesTheSingleOpening(t *testing.T) {
	p, err := Setup(6)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	v, err := RandomVector(p.N)
	if err != nil {
		t.Fatalf("RandomVector: %v", err)
	}
	c, err := p.Commit(v)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	const pos = 3

	// Coefficient 1 makes the aggregate reduce to the plain opening.
	var one fr.Element
	one.SetOne()
	o := Opening{C: c, Pos: pos, Value: v[pos-1], Coeff: one}

	piHat, muHat, err := p.AggregateOpen([][]fr.Element{v}, []Opening{o})
	if err != nil {
		t.Fatalf("AggregateOpen: %v", err)
	}

	single, err := p.Open(v, pos)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !piHat.Equal(&single) {
		t.Error("aggregate of one differs from the single opening it should equal")
	}
	if !muHat.Equal(&v[pos-1]) {
		t.Error("mu_hat at coefficient 1 is not the opened value")
	}

	ok, err := p.AggregateVerify([]Opening{o}, piHat, muHat)
	if err != nil {
		t.Fatalf("AggregateVerify: %v", err)
	}
	if !ok {
		t.Error("aggregate verifier rejected what the single verifier accepts")
	}
}

// TestAggregateRejectsATamperedValue is the negative: an always-accept
// aggregate verifier passes every test above.
func TestAggregateRejectsATamperedValue(t *testing.T) {
	p, err := Setup(6)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	vectors, openings := buildOpenings(t, p, 4)

	piHat, muHat, err := p.AggregateOpen(vectors, openings)
	if err != nil {
		t.Fatalf("AggregateOpen: %v", err)
	}

	// Claim a different value for one opening, and adjust mu_hat to match, so
	// the arithmetic is consistent and only the pairing can catch it.
	var delta fr.Element
	delta.SetUint64(1)
	tampered := make([]Opening, len(openings))
	copy(tampered, openings)
	tampered[2].Value.Add(&tampered[2].Value, &delta)

	var shift fr.Element
	shift.Mul(&delta, &tampered[2].Coeff)
	var muTampered fr.Element
	muTampered.Add(&muHat, &shift)

	ok, err := p.AggregateVerify(tampered, piHat, muTampered)
	if err != nil {
		t.Fatalf("AggregateVerify: %v", err)
	}
	if ok {
		t.Error("an aggregate with a tampered value verified")
	}
}

// TestAggregateRejectsAnExtraOpening pins that the aggregate binds the SET, not
// just the values: a verifier given one more opening than the prover aggregated
// must reject.
func TestAggregateRejectsAnExtraOpening(t *testing.T) {
	p, err := Setup(6)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	vectors, openings := buildOpenings(t, p, 4)

	piHat, muHat, err := p.AggregateOpen(vectors[:3], openings[:3])
	if err != nil {
		t.Fatalf("AggregateOpen: %v", err)
	}

	ok, err := p.AggregateVerify(openings, piHat, muHat)
	if err != nil {
		t.Fatalf("AggregateVerify: %v", err)
	}
	if ok {
		t.Error("a proof over 3 openings verified against 4")
	}
}

// TestAggregateRejectsCancellingErrors is the security property that makes the
// coefficients matter, and the test a free-coefficient implementation fails.
//
// Two openings, both wrong, with errors chosen to cancel in the sum: raise one
// claimed value by d and lower the other by d. mu_hat is unchanged, so a
// verifier that only checked the aggregate arithmetic would accept. It is the
// COEFFICIENTS that stop it — t_i is a hash over (position, commitment, value),
// so changing a value changes its coefficient, and the errors no longer cancel.
func TestAggregateRejectsCancellingErrors(t *testing.T) {
	p, err := Setup(6)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	vectors, openings := buildOpenings(t, p, 2)

	piHat, muHat, err := p.AggregateOpen(vectors, openings)
	if err != nil {
		t.Fatalf("AggregateOpen: %v", err)
	}

	var d fr.Element
	d.SetUint64(7)

	forged := make([]Opening, 2)
	copy(forged, openings)
	forged[0].Value.Add(&forged[0].Value, &d)
	forged[1].Value.Sub(&forged[1].Value, &d)

	// Rebind the coefficients, as an honest verifier does — this is what
	// breaks the cancellation.
	forged[0].Coeff = DeriveCoefficient(forged[0].Pos, forged[0].C, forged[0].Value)
	forged[1].Coeff = DeriveCoefficient(forged[1].Pos, forged[1].C, forged[1].Value)

	ok, err := p.AggregateVerify(forged, piHat, muHat)
	if err != nil {
		t.Fatalf("AggregateVerify: %v", err)
	}
	if ok {
		t.Error("two cancelling errors verified; the aggregation is not binding " +
			"each opening individually")
	}
}

// TestDeriveCoefficientBindsEveryInput pins that the coefficient moves when any
// of the three values it covers moves. A coefficient that ignored one of them
// would leave that field unbound in the aggregate.
func TestDeriveCoefficientBindsEveryInput(t *testing.T) {
	p, err := Setup(4)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	v, err := RandomVector(p.N)
	if err != nil {
		t.Fatalf("RandomVector: %v", err)
	}
	c1, err := p.Commit(v)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	w, err := RandomVector(p.N)
	if err != nil {
		t.Fatalf("RandomVector: %v", err)
	}
	c2, err := p.Commit(w)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	base := DeriveCoefficient(2, c1, v[1])

	var other fr.Element
	other.Add(&v[1], new(fr.Element).SetOne())

	cases := map[string]fr.Element{
		"position":   DeriveCoefficient(3, c1, v[1]),
		"commitment": DeriveCoefficient(2, c2, v[1]),
		"value":      DeriveCoefficient(2, c1, other),
	}
	for name, got := range cases {
		if got.Equal(&base) {
			t.Errorf("changing the %s did not change the coefficient", name)
		}
	}
}

// TestAggregateUsesOnePairingPerOpeningPlusOne is the cost claim, counted rather
// than asserted. Verifying k openings individually costs 2k pairings and k final
// exponentiations; the aggregate is k+1 pairings in one Miller loop.
func TestAggregateUsesOnePairingPerOpeningPlusOne(t *testing.T) {
	for _, k := range []int{1, 4, 16} {
		if got, want := aggregatePairingCount(k), k+1; got != want {
			t.Errorf("k=%d: %d pairs, want %d", k, got, want)
		}
		if individual := 2 * k; k > 1 && aggregatePairingCount(k) >= individual {
			t.Errorf("k=%d: aggregation (%d pairs) is not cheaper than %d individual",
				k, aggregatePairingCount(k), individual)
		}
	}
}

// TestAggregateRejectsAPositionOutsideTheVector keeps a malformed opening from
// indexing into the reference string.
func TestAggregateRejectsAPositionOutsideTheVector(t *testing.T) {
	p, err := Setup(4)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	_, openings := buildOpenings(t, p, 1)
	openings[0].Pos = p.N + 1

	var pi curve.G1Affine
	var mu fr.Element
	if _, err := p.AggregateVerify(openings, pi, mu); err == nil {
		t.Error("a position outside the vector was accepted")
	}
}

func BenchmarkAggregateVerify(b *testing.B) {
	p, err := Setup(11)
	if err != nil {
		b.Fatalf("Setup: %v", err)
	}
	for _, k := range []int{1, 4, 16, 64} {
		b.Run(fmt.Sprintf("k=%d", k), func(b *testing.B) {
			vectors := make([][]fr.Element, k)
			openings := make([]Opening, k)
			for i := 0; i < k; i++ {
				v, err := RandomVector(p.N)
				if err != nil {
					b.Fatal(err)
				}
				c, err := p.Commit(v)
				if err != nil {
					b.Fatal(err)
				}
				pos := (i % p.N) + 1
				vectors[i] = v
				openings[i] = Opening{C: c, Pos: pos, Value: v[pos-1],
					Coeff: DeriveCoefficient(pos, c, v[pos-1])}
			}
			piHat, muHat, err := p.AggregateOpen(vectors, openings)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := p.AggregateVerify(openings, piHat, muHat); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// TestUnboundCoefficientsWouldBeForgeable is the offensive half of the test
// above, and the reason DeriveCoefficient exists.
//
// The left side of the verification equation does not involve the claimed
// values at all — they enter ONLY through mu_hat. So if the coefficients were
// fixed and equal, a prover could claim anything whose weighted sum still came
// to mu_hat: raise one value by d, lower the other by d, and the aggregate
// verifies with the honest pi_hat untouched.
//
// This test performs exactly that and asserts it SUCCEEDS, which is what makes
// the binding load-bearing rather than decorative. If this ever starts failing,
// the verification equation has changed and the security argument for the
// coefficients needs redoing.
func TestUnboundCoefficientsWouldBeForgeable(t *testing.T) {
	p, err := Setup(6)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	vectors, openings := buildOpenings(t, p, 2)

	// Fix both coefficients to the same value — what an implementation that
	// took coefficients from the prover, or used a constant, would do.
	var fixed fr.Element
	fixed.SetUint64(3)
	openings[0].Coeff = fixed
	openings[1].Coeff = fixed

	piHat, muHat, err := p.AggregateOpen(vectors, openings)
	if err != nil {
		t.Fatalf("AggregateOpen: %v", err)
	}

	// Sanity: the honest aggregate verifies.
	ok, err := p.AggregateVerify(openings, piHat, muHat)
	if err != nil {
		t.Fatalf("AggregateVerify: %v", err)
	}
	if !ok {
		t.Fatal("the honest aggregate did not verify; the rest of this test proves nothing")
	}

	// Now lie about both values, cancelling in the sum.
	var d fr.Element
	d.SetUint64(7)
	forged := make([]Opening, 2)
	copy(forged, openings)
	forged[0].Value.Add(&forged[0].Value, &d)
	forged[1].Value.Sub(&forged[1].Value, &d)

	ok, err = p.AggregateVerify(forged, piHat, muHat)
	if err != nil {
		t.Fatalf("AggregateVerify: %v", err)
	}
	if !ok {
		t.Fatal("the cancellation did not verify — the attack this construction " +
			"defends against is not the attack being modelled here, so " +
			"TestAggregateRejectsCancellingErrors is not evidence of anything")
	}

	// And the defence: rebinding the coefficients to the claimed values breaks it.
	forged[0].Coeff = DeriveCoefficient(forged[0].Pos, forged[0].C, forged[0].Value)
	forged[1].Coeff = DeriveCoefficient(forged[1].Pos, forged[1].C, forged[1].Value)

	ok, err = p.AggregateVerify(forged, piHat, muHat)
	if err != nil {
		t.Fatalf("AggregateVerify: %v", err)
	}
	if ok {
		t.Error("bound coefficients did not stop the cancellation")
	}
}
