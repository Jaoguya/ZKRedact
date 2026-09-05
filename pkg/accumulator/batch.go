package accumulator

import "math/big"

// AllMembershipWitnesses computes every element's witness at once.
//
// WHY THIS IS NOT A LOOP OVER MembershipWitness. Each witness is
// g^{prod of every OTHER prime}, so computing them one at a time is O(n^2)
// modular exponentiations. Ref[22] regenerates witnesses after every
// accumulator update — an RSA accumulator invalidates all of them on any change
// — and Exp 3 builds ledgers of 10,000 blocks. At O(n^2) that is around 10^8
// exponentiations of 3072-bit integers: the baseline could not be constructed at
// all, let alone measured.
//
// RootFactor (Sander-Ta-Shma) splits the exponent set in half, raises g by each
// half's product, and recurses, giving O(n log n). It computes exactly the same
// witnesses — this is an algorithmic improvement to witness GENERATION, not a
// shortcut in what the accumulator proves.
//
// The witnesses are returned in the accumulator's insertion order.
func (a *Accumulator) AllMembershipWitnesses() (map[string]*big.Int, error) {
	if len(a.order) == 0 {
		return map[string]*big.Int{}, nil
	}

	primes := make([]*big.Int, len(a.order))
	for i, k := range a.order {
		primes[i] = a.elements[k]
	}

	out := make([]*big.Int, 0, len(primes))
	rootFactor(a.g, primes, a.n, &out)

	witnesses := make(map[string]*big.Int, len(a.order))
	for i, k := range a.order {
		witnesses[k] = out[i]
	}
	return witnesses, nil
}

// rootFactor appends g^{prod of all primes except primes[i]} for each i.
func rootFactor(g *big.Int, primes []*big.Int, n *big.Int, out *[]*big.Int) {
	if len(primes) == 1 {
		*out = append(*out, new(big.Int).Set(g))
		return
	}

	half := len(primes) / 2
	left, right := primes[:half], primes[half:]

	// g raised by the OPPOSITE half's product, so each recursion carries the
	// contribution of everything outside its own subtree.
	gLeft := new(big.Int).Set(g)
	for _, e := range right {
		gLeft.Exp(gLeft, e, n)
	}
	gRight := new(big.Int).Set(g)
	for _, e := range left {
		gRight.Exp(gRight, e, n)
	}

	rootFactor(gLeft, left, n, out)
	rootFactor(gRight, right, n, out)
}
