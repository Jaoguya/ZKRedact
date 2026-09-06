package accumulator

import (
	"math/big"
	"testing"
)

const proofBits = 1024

func proofGroup(t *testing.T) (n, g *big.Int) {
	t.Helper()
	n, err := GenerateUntrusted(proofBits)
	if err != nil {
		t.Fatalf("GenerateUntrusted: %v", err)
	}
	return n, big.NewInt(2)
}

// -----------------------------------------------------------------------------
// PoE
// -----------------------------------------------------------------------------

func TestPoERoundTrip(t *testing.T) {
	n, g := proofGroup(t)
	for _, name := range []string{"a", "block-42", "some longer element label"} {
		x, err := HashToPrime([]byte(name))
		if err != nil {
			t.Fatalf("HashToPrime: %v", err)
		}
		p, w, err := ProvePoE(g, x, n)
		if err != nil {
			t.Fatalf("ProvePoE: %v", err)
		}
		ok, err := VerifyPoE(p, g, w, x, n)
		if err != nil || !ok {
			t.Errorf("%s: honest PoE rejected (ok=%v err=%v)", name, ok, err)
		}
	}
}

// The exponent Ref[22] proves over is a PRODUCT across the delete set, not a
// single prime — that is the case the proof exists to make cheap.
func TestPoEOverAProductOfElements(t *testing.T) {
	n, g := proofGroup(t)
	product := big.NewInt(1)
	for _, name := range []string{"b1", "b2", "b3", "b4", "b5"} {
		e, err := HashToPrime([]byte(name))
		if err != nil {
			t.Fatalf("HashToPrime: %v", err)
		}
		product.Mul(product, e)
	}
	p, w, err := ProvePoE(g, product, n)
	if err != nil {
		t.Fatalf("ProvePoE: %v", err)
	}
	ok, err := VerifyPoE(p, g, w, product, n)
	if err != nil || !ok {
		t.Errorf("PoE over a product was rejected (ok=%v err=%v)", ok, err)
	}
}

func TestPoERejectsForgeries(t *testing.T) {
	n, g := proofGroup(t)
	// A PRODUCT, so the exponent exceeds the 256-bit challenge prime and the
	// proof is genuinely succinct. See TestSmallExponentDegeneratesToTheDirect
	// Check for why a single element is the wrong fixture here.
	x := bigProduct(t, "r1", "r2", "r3", "r4", "r5")
	p, w, err := ProvePoE(g, x, n)
	if err != nil {
		t.Fatalf("ProvePoE: %v", err)
	}

	other := bigProduct(t, "d1", "d2", "d3", "d4", "d5")
	wrongW := new(big.Int).Exp(g, other, n)

	for _, tc := range []struct {
		name string
		p    *PoE
		u    *big.Int
		w    *big.Int
		x    *big.Int
	}{
		{"claimed result altered", p, g, wrongW, x},
		{"claimed exponent altered", p, g, w, other},
		{"base altered", p, big.NewInt(3), w, x},
		{"Q set to 1", &PoE{Q: big.NewInt(1)}, g, w, x},
		{"Q incremented", &PoE{Q: new(big.Int).Add(p.Q, big.NewInt(1))}, g, w, x},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := VerifyPoE(tc.p, tc.u, tc.w, tc.x, n)
			if err == nil && ok {
				t.Errorf("accepted a forged PoE")
			}
		})
	}
}

func TestPoERejectsMalformed(t *testing.T) {
	n, g := proofGroup(t)
	x, _ := HashToPrime([]byte("real"))
	_, w, _ := ProvePoE(g, x, n)

	for _, tc := range []struct {
		name string
		p    *PoE
	}{
		{"nil proof", nil},
		{"nil Q", &PoE{}},
		{"Q zero", &PoE{Q: big.NewInt(0)}},
		{"Q equal to n", &PoE{Q: new(big.Int).Set(n)}},
		{"Q negative", &PoE{Q: big.NewInt(-1)}},
	} {
		if ok, _ := VerifyPoE(tc.p, g, w, x, n); ok {
			t.Errorf("accepted %s", tc.name)
		}
	}
}

// -----------------------------------------------------------------------------
// PoKE
// -----------------------------------------------------------------------------

func TestPoKERoundTrip(t *testing.T) {
	n, g := proofGroup(t)
	u := new(big.Int).Exp(g, big.NewInt(7), n)

	for _, x := range []*big.Int{
		big.NewInt(123456789),
		new(big.Int).Lsh(big.NewInt(1), 300),
		bigProduct(t, "p1", "p2", "p3"),
	} {
		p, w, err := ProvePoKE(u, x, g, n)
		if err != nil {
			t.Fatalf("ProvePoKE: %v", err)
		}
		ok, err := VerifyPoKE(p, u, w, g, n)
		if err != nil || !ok {
			t.Errorf("honest PoKE rejected for x=%v (ok=%v err=%v)", x, ok, err)
		}
	}
}

// Ref[22] Algorithm 7 line 22 proves knowledge of a Bezout coefficient, which
// Exgcd can return negative. If negative exponents were mishandled the proof
// would fail on roughly half of all real inputs.
func TestPoKEHandlesNegativeExponents(t *testing.T) {
	n, g := proofGroup(t)
	u := new(big.Int).Exp(g, big.NewInt(11), n)
	x := new(big.Int).Neg(bigProduct(t, "n1", "n2", "n3"))

	p, w, err := ProvePoKE(u, x, g, n)
	if err != nil {
		t.Fatalf("ProvePoKE: %v", err)
	}
	ok, err := VerifyPoKE(p, u, w, g, n)
	if err != nil || !ok {
		t.Errorf("honest PoKE with a negative exponent rejected (ok=%v err=%v)", ok, err)
	}
}

func TestPoKERejectsForgeries(t *testing.T) {
	n, g := proofGroup(t)
	u := new(big.Int).Exp(g, big.NewInt(7), n)
	x := bigProduct(t, "k1", "k2", "k3", "k4", "k5")
	p, w, err := ProvePoKE(u, x, g, n)
	if err != nil {
		t.Fatalf("ProvePoKE: %v", err)
	}

	otherP, otherW, _ := ProvePoKE(u, bigProduct(t, "o1", "o2", "o3", "o4", "o5"), g, n)

	for _, tc := range []struct {
		name string
		p    *PoKE
		w    *big.Int
	}{
		{"claimed result altered", p, otherW},
		{"Z from a different exponent", &PoKE{Z: otherP.Z, Q: p.Q, R: p.R}, w},
		{"Q from a different statement", &PoKE{Z: p.Z, Q: otherP.Q, R: p.R}, w},
		{"R altered", &PoKE{Z: p.Z, Q: p.Q, R: new(big.Int).Add(p.R, big.NewInt(1))}, w},
		{"Q set to 1", &PoKE{Z: p.Z, Q: big.NewInt(1), R: p.R}, w},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := VerifyPoKE(tc.p, u, tc.w, g, n)
			if err == nil && ok {
				t.Errorf("accepted a forged PoKE")
			}
		})
	}
}

// R must be a genuine residue below the challenge prime. Without the range
// check a prover could submit Q = 1 and R = x, which satisfies the equation
// while proving nothing succinct — the proof would degenerate into the direct
// exponentiation it exists to replace.
func TestPoKERejectsAnOutOfRangeResidue(t *testing.T) {
	n, g := proofGroup(t)
	u := new(big.Int).Exp(g, big.NewInt(7), n)
	x := bigProduct(t, "z1", "z2", "z3", "z4", "z5")

	p, w, err := ProvePoKE(u, x, g, n)
	if err != nil {
		t.Fatalf("ProvePoKE: %v", err)
	}
	degenerate := &PoKE{Z: p.Z, Q: big.NewInt(1), R: x}
	if ok, _ := VerifyPoKE(degenerate, u, w, g, n); ok {
		t.Errorf("accepted Q=1 with R=x; the residue range is not enforced")
	}
}

func TestPoKERejectsMalformed(t *testing.T) {
	n, g := proofGroup(t)
	u := new(big.Int).Exp(g, big.NewInt(7), n)
	_, w, _ := ProvePoKE(u, big.NewInt(5), g, n)

	for _, tc := range []struct {
		name string
		p    *PoKE
	}{
		{"nil proof", nil},
		{"nil components", &PoKE{}},
		{"Z zero", &PoKE{Z: big.NewInt(0), Q: big.NewInt(2), R: big.NewInt(1)}},
		{"Q equal to n", &PoKE{Z: big.NewInt(2), Q: new(big.Int).Set(n), R: big.NewInt(1)}},
	} {
		if ok, _ := VerifyPoKE(tc.p, u, w, g, n); ok {
			t.Errorf("accepted %s", tc.name)
		}
	}
}

// The challenge must depend on the statement, or a proof for one statement
// would verify for another.
func TestChallengeBindsTheStatement(t *testing.T) {
	n, g := proofGroup(t)
	x1, _ := HashToPrime([]byte("one"))
	x2, _ := HashToPrime([]byte("two"))

	w1 := new(big.Int).Exp(g, x1, n)
	w2 := new(big.Int).Exp(g, x2, n)

	l1, err := poeChallenge(g, w1, x1)
	if err != nil {
		t.Fatalf("poeChallenge: %v", err)
	}
	l2, err := poeChallenge(g, w2, x2)
	if err != nil {
		t.Fatalf("poeChallenge: %v", err)
	}
	if l1.Cmp(l2) == 0 {
		t.Errorf("two different statements produced the same challenge prime")
	}
}

// Length-prefixing must stop (a, bc) and (ab, c) hashing alike.
func TestOperandEncodingIsUnambiguous(t *testing.T) {
	a := big.NewInt(0x01)
	bc := big.NewInt(0x0203)
	ab := big.NewInt(0x0102)
	c := big.NewInt(0x03)

	if string(concatOperands(a, bc)) == string(concatOperands(ab, c)) {
		t.Errorf("operand encoding is ambiguous; a concatenation collision is possible")
	}
}

// bigProduct builds an exponent from several prime representatives, which is
// the shape Ref[22] actually proves over: Algorithm 7 line 12 accumulates
// H_prime across the delete set.
func bigProduct(t *testing.T, names ...string) *big.Int {
	t.Helper()
	out := big.NewInt(1)
	for _, name := range names {
		e, err := HashToPrime([]byte(name))
		if err != nil {
			t.Fatalf("HashToPrime: %v", err)
		}
		out.Mul(out, e)
	}
	return out
}

// An exponent smaller than the challenge prime makes the proof degenerate: the
// quotient is zero, Q is 1, the residue is the whole exponent, and verification
// reduces to the direct check u^x == w.
//
// Still sound — that IS the statement — but it buys nothing, so it is recorded
// rather than left to surprise someone reading a flat timing. Ref[22] proves
// over products across the delete set (Algorithm 7 line 12), which exceed the
// 256-bit challenge and are the case the proof exists for.
func TestSmallExponentDegeneratesToTheDirectCheck(t *testing.T) {
	n, g := proofGroup(t)
	small := big.NewInt(65537)

	p, w, err := ProvePoE(g, small, n)
	if err != nil {
		t.Fatalf("ProvePoE: %v", err)
	}
	if p.Q.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("expected the degenerate Q=1 for an exponent below the challenge, got %v", p.Q)
	}
	ok, err := VerifyPoE(p, g, w, small, n)
	if err != nil || !ok {
		t.Errorf("the degenerate proof must still verify (ok=%v err=%v)", ok, err)
	}

	// And it must remain sound: a wrong claimed result is still rejected.
	if ok, _ := VerifyPoE(p, g, new(big.Int).Add(w, big.NewInt(1)), small, n); ok {
		t.Errorf("degenerate proof accepted a wrong result")
	}

	// The product case is the one that is genuinely succinct.
	large := bigProduct(t, "s1", "s2", "s3", "s4", "s5")
	lp, lw, err := ProvePoE(g, large, n)
	if err != nil {
		t.Fatalf("ProvePoE: %v", err)
	}
	if lp.Q.Cmp(big.NewInt(1)) == 0 {
		t.Errorf("a product exponent should produce a non-trivial quotient")
	}
	if ok, _ := VerifyPoE(lp, g, lw, large, n); !ok {
		t.Errorf("succinct proof over a product was rejected")
	}
}
