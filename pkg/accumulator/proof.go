package accumulator

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

// Non-interactive succinct proofs over the accumulator's group (Ref[22] §II-B).
//
// These are not optional extras. Ref[22] builds four of them inside Delete —
// Algorithm 7 lines 17, 19, 22 and 23 — and Algorithm 8's ValDel returns
// nothing but their conjunction. UA.MWit and UA.N-MWit in §II-C likewise return
// proofs rather than bare witnesses. Omitting them makes Delete cheaper than
// the scheme specifies, on exactly the metric Exp 2 reports for this baseline.
//
// WHAT THEY BUY, AND WHY THAT MATTERS FOR THE MEASUREMENT. A membership witness
// w for x satisfies w^x = A. Checking that directly costs an exponentiation
// whose exponent is the whole element — fine for one element, but Ref[22]
// verifies against products over the entire delete set, where the exponent
// grows with |L|. A PoE replaces it with a check whose exponent is a fixed
// 256-bit prime, so verification stops scaling with the exponent's size. The
// prover pays for that: it computes the quotient and one extra exponentiation.
// Both sides of that trade are on measured paths, which is why implementing
// only the cheap half would misreport this scheme in both directions at once.
//
// Wesolowski's PoE and the PoKE* of Boneh, Bunz and Fisch (Batching Techniques
// for Accumulators, CRYPTO 2019), which is what Ref[22] cites as NI-PoE and
// NI-PoKE. Fiat-Shamir makes them non-interactive: the challenge prime comes
// from hashing the statement, so a prover cannot choose it.

var (
	// ErrProofMalformed reports a proof whose components are missing or outside
	// the group.
	ErrProofMalformed = errors.New("accumulator: proof is malformed")

	// ErrNilStatement reports a proof or verification over missing operands.
	ErrNilStatement = errors.New("accumulator: proof requires u, w and x")
)

// PoE proves that u^x = w without the verifier exponentiating by x.
type PoE struct {
	// Q is u^{floor(x/l)}, where l is the challenge prime.
	Q *big.Int
}

// PoKE proves knowledge of x with u^x = w, and additionally binds x to the
// fixed generator g so the prover cannot swap in a different exponent.
type PoKE struct {
	// Z is g^x, the commitment to the exponent under the fixed generator.
	Z *big.Int

	// Q is (u * g^alpha)^{floor(x/l)}.
	Q *big.Int

	// R is x mod l, which is small: below the challenge prime.
	R *big.Int
}

// poeChallenge derives the challenge prime l = H_prime(u || w || x).
//
// Fiat-Shamir. The prover cannot pick l, because it is fixed by the statement
// it is proving — which is the whole reason the proof is sound non-interactively.
func poeChallenge(u, w, x *big.Int) (*big.Int, error) {
	return HashToPrime(concatOperands(u, w, x))
}

// pokeAlpha derives the second challenge, binding z into the statement.
func pokeAlpha(u, w, z, l *big.Int) *big.Int {
	h := hashOperands(u, w, z, l)
	return new(big.Int).SetBytes(h)
}

// ProvePoE produces a proof that u^x = w mod n.
//
// The prover's cost is one exponentiation with exponent floor(x/l). For the
// products Ref[22] forms over a delete set that is genuinely cheaper than
// re-deriving the statement, but it is not free, and Exp 2 measures it.
func ProvePoE(u, x, n *big.Int) (*PoE, *big.Int, error) {
	if u == nil || x == nil || n == nil {
		return nil, nil, ErrNilStatement
	}
	w := new(big.Int).Exp(u, x, n)

	l, err := poeChallenge(u, w, x)
	if err != nil {
		return nil, nil, fmt.Errorf("accumulator: PoE challenge: %w", err)
	}
	q := new(big.Int).Div(x, l)
	return &PoE{Q: new(big.Int).Exp(u, q, n)}, w, nil
}

// VerifyPoE checks Q^l * u^{x mod l} == w mod n.
//
// Correctness: x = q*l + r, so u^x = (u^q)^l * u^r = Q^l * u^r.
func VerifyPoE(p *PoE, u, w, x, n *big.Int) (bool, error) {
	if p == nil || p.Q == nil {
		return false, ErrProofMalformed
	}
	if u == nil || w == nil || x == nil || n == nil {
		return false, ErrNilStatement
	}
	if !inGroup(p.Q, n) || !inGroup(u, n) || !inGroup(w, n) {
		return false, ErrProofMalformed
	}

	l, err := poeChallenge(u, w, x)
	if err != nil {
		return false, fmt.Errorf("accumulator: PoE challenge: %w", err)
	}
	r := new(big.Int).Mod(x, l)

	lhs := new(big.Int).Exp(p.Q, l, n)
	lhs.Mul(lhs, new(big.Int).Exp(u, r, n))
	lhs.Mod(lhs, n)

	return lhs.Cmp(new(big.Int).Mod(w, n)) == 0, nil
}

// ProvePoKE produces a proof of knowledge of x with u^x = w mod n.
//
// PoKE* rather than a bare PoE because Ref[22] uses it where the exponent is a
// SECRET Bezout coefficient (Algorithm 7 line 22 proves knowledge of beta), not
// a value the verifier already holds. A PoE would require publishing beta.
func ProvePoKE(u, x, g, n *big.Int) (*PoKE, *big.Int, error) {
	if u == nil || x == nil || g == nil || n == nil {
		return nil, nil, ErrNilStatement
	}
	w := expSignedOrPositive(u, x, n)
	z := expSignedOrPositive(g, x, n)

	l, err := HashToPrime(concatOperands(u, w, z))
	if err != nil {
		return nil, nil, fmt.Errorf("accumulator: PoKE challenge: %w", err)
	}
	alpha := pokeAlpha(u, w, z, l)

	q := new(big.Int).Div(x, l)
	r := new(big.Int).Mod(x, l)

	// base = u * g^alpha
	base := new(big.Int).Exp(g, alpha, n)
	base.Mul(base, u)
	base.Mod(base, n)

	return &PoKE{
		Z: z,
		Q: expSignedOrPositive(base, q, n),
		R: r,
	}, w, nil
}

// VerifyPoKE checks Q^l * (u*g^alpha)^r == w * z^alpha mod n.
func VerifyPoKE(p *PoKE, u, w, g, n *big.Int) (bool, error) {
	if p == nil || p.Q == nil || p.Z == nil || p.R == nil {
		return false, ErrProofMalformed
	}
	if u == nil || w == nil || g == nil || n == nil {
		return false, ErrNilStatement
	}
	if !inGroup(p.Q, n) || !inGroup(p.Z, n) || !inGroup(u, n) || !inGroup(w, n) {
		return false, ErrProofMalformed
	}

	l, err := HashToPrime(concatOperands(u, w, p.Z))
	if err != nil {
		return false, fmt.Errorf("accumulator: PoKE challenge: %w", err)
	}
	// r must be a genuine residue. Without this an adversary could present
	// r = x and Q = 1, which satisfies the equation for any x it knows and
	// proves nothing succinct.
	if p.R.Sign() < 0 || p.R.Cmp(l) >= 0 {
		return false, nil
	}
	alpha := pokeAlpha(u, w, p.Z, l)

	base := new(big.Int).Exp(g, alpha, n)
	base.Mul(base, u)
	base.Mod(base, n)

	lhs := new(big.Int).Exp(p.Q, l, n)
	lhs.Mul(lhs, new(big.Int).Exp(base, p.R, n))
	lhs.Mod(lhs, n)

	rhs := new(big.Int).Exp(p.Z, alpha, n)
	rhs.Mul(rhs, w)
	rhs.Mod(rhs, n)

	return lhs.Cmp(rhs) == 0, nil
}

// expSignedOrPositive exponentiates, handling the negative exponents that
// Bezout coefficients produce.
func expSignedOrPositive(base, exp, n *big.Int) *big.Int {
	if exp.Sign() >= 0 {
		return new(big.Int).Exp(base, exp, n)
	}
	inv := new(big.Int).ModInverse(base, n)
	if inv == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Exp(inv, new(big.Int).Neg(exp), n)
}

// inGroup rejects operands outside [1, n-1]. Zero and n are not group elements,
// and admitting them lets a proof verify trivially.
func inGroup(x, n *big.Int) bool {
	return x.Sign() > 0 && x.Cmp(n) < 0
}

// concatOperands serialises a statement for hashing, length-prefixing each
// operand so that (a, bc) and (ab, c) cannot collide into the same challenge.
func concatOperands(xs ...*big.Int) []byte {
	var out []byte
	for _, x := range xs {
		b := x.Bytes()
		var l [8]byte
		for i := 0; i < 8; i++ {
			l[7-i] = byte(len(b) >> (8 * i))
		}
		out = append(out, l[:]...)
		out = append(out, b...)
	}
	return out
}

// hashOperands is SHA-256 over the same length-prefixed encoding.
func hashOperands(xs ...*big.Int) []byte {
	sum := sha256.Sum256(concatOperands(xs...))
	return sum[:]
}
