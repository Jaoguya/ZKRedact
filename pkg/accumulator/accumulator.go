// Package accumulator implements the trapdoorless universal RSA accumulator
// Ref[22] uses as its chain-state commitment.
//
// UNIVERSAL means it produces both membership and NON-membership witnesses.
// Ref[22] needs both: Modify calls UA.Del to invalidate a prior block version
// and then must be able to prove that version is gone. An accumulator with only
// membership witnesses cannot make that statement, and the paper's central
// security claim — that a reverted block is detectable — would be unenforceable.
//
// TRAPDOORLESS describes what VERIFIERS must trust: the group has unknown order
// to them, no trusted setup is needed to check a witness, and soundness does not
// rest on anyone's ignorance of the factors.
//
// It does NOT mean nobody holds phi(N). Ref[22] gives it to the regulator, and
// says so directly — §II-C closes with "since the deletion algorithm is costy
// without the knowledge of group order, it is executed by the regulator with the
// RSA group order in the proposed blockchain" — and Algorithms 5 and 7 both take
// phi(N) as an input. That regulator already holds the double-trapdoor chameleon
// hash key, so it is the redaction authority by construction and the group order
// adds no trust assumption.
//
// This distinction is a cost, not a footnote. Deleting without phi(N) means
// rebuilding the state from the generator over every surviving element: measured
// at RSA-3072, one deletion costs 34ms at n=50, 69ms at n=100 and 139ms at
// n=200, against a flat 8.4ms with the group order. Delete is timed as
// CryptoTime and carries Ref[22]'s headline Exp 2 curve, so the difference is
// the measurement. See Config.GroupOrder.
//
// WHY NOT A HASH SET. A set of hashes supports membership trivially and is far
// faster, and Exp 2 reports CryptoTime as a headline metric — so substituting
// one would make Ref[22] look good for a reason unrelated to its design, and no
// functional test would notice. RequireAccumulator and the reversion test in
// this package exist to stop that.
package accumulator

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// Accumulator is an RSA accumulator over a fixed modulus.
//
// The state A is g^{prod e_i} mod N, where each accumulated element is mapped to
// an odd prime e_i. Membership of x is a witness w with w^{e_x} = A; the prime
// representation is what makes witnesses unforgeable, because a composite
// exponent would let an adversary factor its way to a witness for an element
// never added.
type Accumulator struct {
	n *big.Int // modulus, factorisation unknown
	g *big.Int // generator of the quotient group

	state *big.Int

	// elements holds the prime representative of every accumulated element, so
	// witnesses can be regenerated. The accumulator itself is the commitment;
	// this is bookkeeping the accumulator OWNER keeps, not part of the state a
	// verifier trusts.
	// phi is phi(N), when the regulator holds it. See Config.GroupOrder.
	phi *big.Int

	elements map[string]*big.Int

	// nonces records the counter that produced each element's prime, so a
	// verifier can rederive it with one primality test instead of a search.
	nonces map[string]uint64

	order []string
}

// Config carries the accumulator's parameters. Bits is required and checked
// against the shared security level by the caller.
type Config struct {
	// Bits is the modulus size. Ref[22] specifies 3072, which NIST SP 800-57
	// places at 128-bit security.
	Bits int

	// Modulus, when set, is used directly. This is the trapdoorless path: a
	// modulus nobody generated privately.
	Modulus *big.Int

	// GroupOrder is phi(N), held by the REGULATOR so deletion is one
	// exponentiation instead of a full rebuild.
	//
	// This is not a shortcut, it is what Ref[22] specifies. §II-C closes with:
	// "since the deletion algorithm is costy without the knowledge of group
	// order, it is executed by the regulator with the RSA group order in the
	// proposed blockchain." The UA.Del written in that same section — recompute
	// x* over every surviving element and raise h to it — is the version the
	// paper explicitly says it does NOT use.
	//
	// It adds no trust assumption. The regulator performing Modify and Delete
	// already holds the double-trapdoor chameleon hash key; it is the redaction
	// authority by construction. "Trapdoorless" describes the accumulator as a
	// construction class: VERIFIERS need no trusted setup and soundness does not
	// rest on anyone's ignorance of the factors. Algorithms 5 and 7 both take
	// phi(N) as an input for exactly this reason.
	//
	// Optional. Left nil, Delete falls back to the rebuild, which is correct but
	// O(n) in the accumulated set — and Delete is the operation Exp 2 reports as
	// Ref[22]'s headline cost, so the fallback inflates that curve by a factor
	// of n.
	GroupOrder *big.Int
}

// New builds an accumulator over the configured modulus.
func New(cfg Config) (*Accumulator, error) {
	if cfg.Bits <= 0 {
		return nil, fmt.Errorf("accumulator: modulus size must be positive, got %d", cfg.Bits)
	}
	n := cfg.Modulus
	if n == nil {
		return nil, fmt.Errorf(
			"accumulator: no modulus supplied. A trapdoorless accumulator needs one " +
				"nobody generated privately; see GenerateUntrusted")
	}
	if n.BitLen() != cfg.Bits {
		return nil, fmt.Errorf(
			"accumulator: modulus is %d bits but %d were configured; the security "+
				"level of this baseline must match every other system's",
			n.BitLen(), cfg.Bits)
	}

	// g = 2 is a standard choice. Any fixed element of the quotient group works;
	// what matters for soundness is that the FACTORISATION is unknown, not which
	// generator is picked.
	g := big.NewInt(2)

	return &Accumulator{
		n:        n,
		g:        g,
		phi:      cfg.GroupOrder,
		state:    new(big.Int).Set(g),
		elements: make(map[string]*big.Int),
		nonces:   make(map[string]uint64),
	}, nil
}

// HasGroupOrder reports whether deletion can use the regulator's trapdoor.
//
// Exposed so a run can RECORD which path it took. The two produce identical
// state but differ by a factor of n in cost, and Exp 2 measures that cost —
// so a results file that cannot say which one ran is not reproducible.
func (a *Accumulator) HasGroupOrder() bool { return a.phi != nil }

// State returns the current accumulator value A.
func (a *Accumulator) State() *big.Int { return new(big.Int).Set(a.state) }

// Modulus returns N.
func (a *Accumulator) Modulus() *big.Int { return new(big.Int).Set(a.n) }

// Size reports how many elements are accumulated.
func (a *Accumulator) Size() int { return len(a.elements) }

// Add accumulates x and returns the membership witness for it.
//
// The witness is the accumulator state BEFORE the addition, which satisfies
// w^{e_x} = A by construction. Every previously issued witness is invalidated by
// this update and must be regenerated — that is inherent to RSA accumulators and
// is exactly the cost Ref[22]'s Modify pays.
func (a *Accumulator) Add(x []byte) (*big.Int, error) {
	key := string(x)
	if _, dup := a.elements[key]; dup {
		return nil, fmt.Errorf("accumulator: element is already accumulated")
	}

	e, nonce, err := HashToPrimeWithNonce(x)
	if err != nil {
		return nil, err
	}

	witness := new(big.Int).Set(a.state)
	a.state.Exp(a.state, e, a.n)
	a.elements[key] = e
	a.nonces[key] = nonce
	a.order = append(a.order, key)
	return witness, nil
}

// Delete removes x, invalidating it.
//
// WITHOUT THE FACTORISATION this cannot be done by taking an e_x-th root, so the
// accumulator is REBUILT from the remaining elements. That is expensive and it
// is meant to be: Ref[22]'s Modify pays it on every redaction, and an
// implementation that faked deletion by dropping a bookkeeping entry would make
// the baseline dramatically cheaper while leaving a reverted block accepted.
func (a *Accumulator) Delete(x []byte) error {
	key := string(x)
	removed, ok := a.elements[key]
	if !ok {
		return fmt.Errorf("accumulator: element is not accumulated")
	}
	removed = new(big.Int).Set(removed)

	delete(a.elements, key)
	delete(a.nonces, key)
	for i, k := range a.order {
		if k == key {
			a.order = append(a.order[:i], a.order[i+1:]...)
			break
		}
	}

	return a.recomputeAfterDelete(removed)
}

// recomputeAfterDelete restores A to g^{prod of surviving primes}.
//
// With phi(N) that is one exponentiation: dividing the exponent by the removed
// prime is multiplying by its inverse mod phi(N), since g^phi = 1. Without it,
// the exponent is not invertible and the only route is to rebuild from the
// generator, which is O(n) exponentiations.
func (a *Accumulator) recomputeAfterDelete(removed *big.Int) error {
	if a.phi != nil {
		inv := new(big.Int).ModInverse(removed, a.phi)
		if inv != nil {
			a.state.Exp(a.state, inv, a.n)
			return nil
		}
		// gcd(e, phi(N)) != 1, so the prime divides p-1 or q-1. Astronomically
		// unlikely, and falling back is correct rather than fatal — but it must
		// not pass unnoticed, because the cost profile silently changes.
		return fmt.Errorf(
			"accumulator: prime representative is not invertible mod phi(N); " +
				"deletion would silently fall back to the O(n) rebuild and change " +
				"the cost Exp 2 measures")
	}

	a.state.Set(a.g)
	for _, k := range a.order {
		a.state.Exp(a.state, a.elements[k], a.n)
	}
	return nil
}

// MembershipWitness returns w with w^{e_x} = A mod N.
func (a *Accumulator) MembershipWitness(x []byte) (*big.Int, error) {
	key := string(x)
	if _, ok := a.elements[key]; !ok {
		return nil, fmt.Errorf("accumulator: element is not accumulated")
	}

	// The product of every OTHER element's prime, applied to g.
	w := new(big.Int).Set(a.g)
	for _, k := range a.order {
		if k == key {
			continue
		}
		w.Exp(w, a.elements[k], a.n)
	}
	return w, nil
}

// Nonce returns the counter that produced an element's prime representative.
func (a *Accumulator) Nonce(x []byte) (uint64, bool) {
	v, ok := a.nonces[string(x)]
	return v, ok
}

// VerifyMembership checks w^{e_x} = A mod N, deriving e_x by search.
//
// Prefer VerifyMembershipWithNonce wherever the nonce is available: the search
// costs about 3,500 modular exponentiations and dominates everything else here.
func VerifyMembership(n, state, witness *big.Int, x []byte) (bool, error) {
	e, err := HashToPrime(x)
	if err != nil {
		return false, err
	}
	got := new(big.Int).Exp(witness, e, n)
	return got.Cmp(state) == 0, nil
}

// VerifyMembershipWithNonce checks w^{e_x} = A mod N using a published nonce.
func VerifyMembershipWithNonce(n, state, witness *big.Int, x []byte, nonce uint64) (bool, error) {
	e, err := PrimeFromNonce(x, nonce)
	if err != nil {
		return false, err
	}
	got := new(big.Int).Exp(witness, e, n)
	return got.Cmp(state) == 0, nil
}

// NonMembershipWitness returns (a_coef, d) proving x is NOT accumulated.
//
// The standard construction (Li-Li-Xue): with u the product of accumulated
// primes and e the candidate's prime, x is absent iff gcd(e, u) = 1. Bezout
// gives coefficients with
//
//	a*u + b*e = 1
//
// and the witness is (a, d = g^b). Verification then checks
//
//	A^a * d^e = g^{ua} * g^{be} = g^{ua + be} = g
//
// THE COEFFICIENT ORDER IS THE WHOLE TRICK, and getting it backwards is silent:
// a is the coefficient of u (applied to the accumulator) and b the coefficient
// of e (applied to the generator). Swapping them yields g^{ua - be}, which is
// not g, and every non-membership proof fails to verify — which reads as a
// broken accumulator rather than as two transposed variables.
//
// This is the half that makes the accumulator UNIVERSAL, and it is what detects
// a reverted block: the old version's non-membership is provable, so presenting
// it is caught rather than merely unsupported.
func (a *Accumulator) NonMembershipWitness(x []byte) (aCoef, d *big.Int, err error) {
	key := string(x)
	if _, present := a.elements[key]; present {
		return nil, nil, fmt.Errorf("accumulator: element IS accumulated; there is no non-membership witness")
	}

	e, err := HashToPrime(x)
	if err != nil {
		return nil, nil, err
	}

	u := big.NewInt(1)
	for _, k := range a.order {
		u.Mul(u, a.elements[k])
	}

	// Extended Euclid, with u FIRST so that gcd = aCoef*u + b*e.
	gcd := new(big.Int)
	aCoef = new(big.Int)
	b := new(big.Int)
	gcd.GCD(aCoef, b, u, e)

	if gcd.Cmp(big.NewInt(1)) != 0 {
		// Only possible if e divides u, i.e. a prime collision between distinct
		// elements. HashToPrime makes it negligible, but a silent wrong answer
		// here would be a forged non-membership proof.
		return nil, nil, fmt.Errorf(
			"accumulator: gcd(e_x, u) = %s, not 1: the prime representation collided", gcd)
	}

	// d = g^b mod N. b is routinely negative, so a negative exponent is the
	// normal case rather than an edge case.
	d, err = expSigned(a.g, b, a.n)
	if err != nil {
		return nil, nil, err
	}
	return aCoef, d, nil
}

// expSigned computes base^exp mod n for a possibly negative exponent.
//
// math/big's Exp returns 1 for a negative exponent when no modular inverse is
// requested, which would silently produce a witness that never verifies.
func expSigned(base, exp, n *big.Int) (*big.Int, error) {
	if exp.Sign() >= 0 {
		return new(big.Int).Exp(base, exp, n), nil
	}
	pos := new(big.Int).Neg(exp)
	p := new(big.Int).Exp(base, pos, n)
	inv := new(big.Int).ModInverse(p, n)
	if inv == nil {
		return nil, fmt.Errorf("accumulator: %s^%s is not invertible mod N", base, pos)
	}
	return inv, nil
}

// VerifyNonMembership checks A^{aCoef} * d^{e_x} = g mod N.
func VerifyNonMembership(n, g, state, aCoef, d *big.Int, x []byte) (bool, error) {
	e, err := HashToPrime(x)
	if err != nil {
		return false, err
	}

	left, err := expSigned(state, aCoef, n)
	if err != nil {
		return false, err
	}

	right := new(big.Int).Exp(d, e, n)
	left.Mul(left, right)
	left.Mod(left, n)

	return left.Cmp(g) == 0, nil
}

// Generator returns g, needed by VerifyNonMembership.
func (a *Accumulator) Generator() *big.Int { return new(big.Int).Set(a.g) }

// GenerateUntrusted produces a modulus for testing and for the harness.
//
// Whoever calls it knows the factors. A real deployment derives N from an RSA
// UFO or a multi-party ceremony, and the regulator's phi(N) would come from that
// ceremony rather than from here.
//
// This is acceptable for the evaluation because it measures COST, and cost
// depends on the modulus size rather than on who knows the factors — with ONE
// exception that an earlier version of this comment got wrong. Deletion is
// exactly the operation whose cost turns on knowing phi(N), which is why
// Ref[22] hands it to the regulator. Use GenerateUntrustedWithOrder for the
// regulator's side; this function discards phi(N) and leaves Delete on the O(n)
// rebuild. Recorded as a deviation in docs/baselines/ref22-shen.md.
func GenerateUntrusted(bits int) (*big.Int, error) {
	n, _, err := GenerateUntrustedWithOrder(bits)
	return n, err
}

// GenerateUntrustedWithOrder returns the modulus AND phi(N).
//
// The regulator needs phi(N) to delete in one exponentiation, which is what
// Ref[22] §II-C specifies. GenerateUntrusted discards it, and a caller that
// takes that path gets the O(n) rebuild — correct, but not this scheme's cost.
//
// Same caveat as GenerateUntrusted about who knows the factors: a real
// deployment derives N from an RSA UFO or a multi-party ceremony, and the
// regulator's phi(N) would come from that ceremony rather than from here.
func GenerateUntrustedWithOrder(bits int) (n, phi *big.Int, err error) {
	if bits < 2 {
		return nil, nil, fmt.Errorf("accumulator: modulus must be at least 2 bits, got %d", bits)
	}
	p, err := rand.Prime(rand.Reader, bits/2)
	if err != nil {
		return nil, nil, fmt.Errorf("accumulator: generate p: %w", err)
	}
	q, err := rand.Prime(rand.Reader, bits-bits/2)
	if err != nil {
		return nil, nil, fmt.Errorf("accumulator: generate q: %w", err)
	}
	n = new(big.Int).Mul(p, q)
	phi = new(big.Int).Mul(
		new(big.Int).Sub(p, big.NewInt(1)),
		new(big.Int).Sub(q, big.NewInt(1)))
	return n, phi, nil
}
