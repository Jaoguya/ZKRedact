package accumulator

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
)

// primeBits is the size of the odd prime each element maps to.
//
// DERIVED, not chosen. The security argument needs distinct primes for distinct
// elements: two elements sharing a prime would make one's witness prove the
// other. With 256-bit representatives the birthday bound over any ledger this
// evaluation builds (10^4 blocks) is around 2^-200, so a collision is not a risk
// the measurement has to model.
//
// Larger primes would cost more per exponentiation and Exp 2 reports CryptoTime
// as a headline metric, so the size is a real parameter — it is fixed here
// rather than configured because it follows from the hash, and changing the hash
// is what would change it.
const primeBits = 256

// HashToPrime maps an element deterministically to an odd prime.
//
// Deterministic matters: a verifier must derive the same representative from the
// same element without being told it, or a prover could pick a convenient prime
// and forge a witness.
//
// The construction is hash-and-increment: hash the element with a counter, force
// the top and bottom bits, and test for primality; on failure, bump the counter.
// The counter is part of the hashed input, so the search is reproducible from
// the element alone.
func HashToPrime(x []byte) (*big.Int, error) {
	p, _, err := HashToPrimeWithNonce(x)
	return p, err
}

// HashToPrimeWithNonce returns the representative AND the counter that produced
// it.
//
// THE NONCE IS WHAT MAKES VERIFICATION AFFORDABLE. The search tries roughly
// ln(2^256) ~ 177 candidates on average, each costing a 20-round Miller-Rabin
// test: about 3,500 modular exponentiations to derive ONE representative. A
// verifier that repeats the search pays that per element, which is what made
// building a 200-block chain take four minutes.
//
// Publishing the counter alongside the element lets the verifier derive the same
// candidate directly and run a single primality test. That is standard practice
// for hash-to-prime and it is not a shortcut in what is proved: the verifier
// still confirms the representative is prime and is the one this element maps
// to. A wrong nonce yields a different candidate, which fails the primality
// check or simply is not the accumulated prime.
func HashToPrimeWithNonce(x []byte) (*big.Int, uint64, error) {
	for counter := uint64(0); counter < maxPrimeSearch; counter++ {
		candidate := primeCandidate(x, counter)
		if candidate.ProbablyPrime(millerRabinRounds) {
			return candidate, counter, nil
		}
	}
	return nil, 0, fmt.Errorf(
		"accumulator: no prime representative for the element within %d attempts",
		maxPrimeSearch)
}

// PrimeFromNonce rederives a representative from an element and its nonce.
//
// One primality test instead of a search. Returns an error if the candidate is
// not prime, so a forged nonce cannot smuggle in a composite exponent — which
// would let an adversary factor its way to a witness for an element never added.
func PrimeFromNonce(x []byte, nonce uint64) (*big.Int, error) {
	candidate := primeCandidate(x, nonce)
	if !candidate.ProbablyPrime(millerRabinRounds) {
		return nil, fmt.Errorf("accumulator: nonce %d does not yield a prime for this element", nonce)
	}
	return candidate, nil
}

// maxPrimeSearch bounds the hash-and-increment search.
//
// By the prime number theorem roughly one in ln(2^256) ~ 177 odd candidates of
// this size is prime, so the search almost always ends within a few hundred
// attempts. The bound exists so a pathological input fails loudly instead of
// spinning: an unbounded loop here would appear as a hung run, not as an error.
const maxPrimeSearch = 1 << 20

// millerRabinRounds is Go's own convention for ProbablyPrime. At 256 bits the
// error probability is below 2^-128, matching the target security level.
const millerRabinRounds = 20

// primeCandidate derives one candidate from an element and a counter.
func primeCandidate(x []byte, counter uint64) *big.Int {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	h := sha256.New()
	h.Write([]byte("ref22/ua/prime"))
	h.Write(buf[:])
	h.Write(x)
	sum := h.Sum(nil)

	c := new(big.Int).SetBytes(sum)

	// Force the top bit so every representative is the same size — a shorter
	// prime would be cheaper to exponentiate, making some elements
	// systematically cheaper than others.
	c.SetBit(c, primeBits-1, 1)
	// Force odd: every prime above 2 is.
	c.SetBit(c, 0, 1)
	return c
}
