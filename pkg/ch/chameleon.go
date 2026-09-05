// Package ch implements chameleon hashing over a prime-order elliptic curve.
//
// A chameleon hash behaves like an ordinary collision-resistant hash to anyone
// without the trapdoor, but the trapdoor holder can compute a second preimage
// on demand. That is what makes redaction possible without breaking the hash
// chain: the ledger keeps the same hash while its content changes.
//
// Construction (Krawczyk-Rabin, in additive elliptic-curve notation):
//
//	KeyGen:  x <- [1, n-1],  Y = x*G
//	Hash:    CH(m, r) = e*G + r*Y      where e = H(m) mod n
//	Adapt:   r' = r + (e - e') * x^-1  (mod n)
//
// Correctness of Adapt:
//
//	CH(m, r)   = eG + rY  = (e + rx)G
//	CH(m', r') = e'G + r'Y = (e' + r'x)G
//	so r' must satisfy  e + rx = e' + r'x  (mod n),
//	giving r' = r + (e - e')x^-1.
//
// KEY EXPOSURE. This construction is not key-exposure resistant: anyone holding
// two colliding pairs recovers the trapdoor as x = (e - e') / (r' - r). Every
// redaction publishes exactly such a pair, so a single redaction reveals x to
// the whole network.
//
// That is a known property of the classic construction and the reason Ref[22]
// builds on a double-trapdoor family instead. It is retained here because it is
// the construction the schemes under comparison actually specify, and because
// the cost profile - one scalar inversion and one multiplication per adaptation
// - is what Exp 2 measures. A key-exposure-resistant variant would change those
// costs, so substituting one would silently change the thing being measured.
//
// Any deployment reusing this package outside the benchmark must move to a
// key-exposure-resistant variant first.
package ch

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
)

var (
	// ErrInvalidPoint reports a hash value that is not on the curve.
	ErrInvalidPoint = errors.New("ch: point is not on the curve")

	// ErrZeroRandomness reports randomness outside [1, n-1].
	ErrZeroRandomness = errors.New("ch: randomness must be in [1, n-1]")

	// ErrCurveMismatch reports operands from different curves.
	ErrCurveMismatch = errors.New("ch: key and value are on different curves")

	// ErrNoTrapdoor reports an adaptation attempted without a private key.
	ErrNoTrapdoor = errors.New("ch: adaptation requires the trapdoor")
)

// PublicKey is the chameleon hash key, Y = x*G.
type PublicKey struct {
	Curve elliptic.Curve
	X, Y  *big.Int
}

// PrivateKey holds the trapdoor x.
type PrivateKey struct {
	PublicKey
	D *big.Int // the trapdoor
}

// Value is a chameleon hash value: a curve point.
type Value struct {
	X, Y *big.Int
}

// Equal reports whether two hash values are identical.
//
// This is the check a verifier performs after a redaction: the ledger's stored
// hash must equal the recomputed one, which is precisely what lets content
// change without the chain breaking.
func (v *Value) Equal(other *Value) bool {
	if v == nil || other == nil {
		return v == other
	}
	return v.X.Cmp(other.X) == 0 && v.Y.Cmp(other.Y) == 0
}

// Bytes returns the uncompressed SEC1 encoding, for hashing into a ledger.
func (v *Value) Bytes(curve elliptic.Curve) []byte {
	return elliptic.Marshal(curve, v.X, v.Y)
}

// KeyGen generates a trapdoor key pair.
//
// rnd may be nil, in which case crypto/rand is used. Tests pass a deterministic
// reader; benchmarks and real use must not.
func KeyGen(curve elliptic.Curve, rnd io.Reader) (*PrivateKey, error) {
	if curve == nil {
		return nil, errors.New("ch: nil curve")
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	n := curve.Params().N

	d, err := randScalar(rnd, n)
	if err != nil {
		return nil, fmt.Errorf("ch: keygen: %w", err)
	}
	px, py := curve.ScalarBaseMult(d.Bytes())

	return &PrivateKey{
		PublicKey: PublicKey{Curve: curve, X: px, Y: py},
		D:         d,
	}, nil
}

// NewRandomness draws a fresh r in [1, n-1].
func NewRandomness(curve elliptic.Curve, rnd io.Reader) (*big.Int, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	return randScalar(rnd, curve.Params().N)
}

// Hash computes CH(m, r) = e*G + r*Y, with e = H(m) mod n.
func (pk *PublicKey) Hash(m []byte, r *big.Int) (*Value, error) {
	if pk == nil || pk.Curve == nil {
		return nil, errors.New("ch: nil public key")
	}
	n := pk.Curve.Params().N
	if r == nil || r.Sign() <= 0 || r.Cmp(n) >= 0 {
		return nil, ErrZeroRandomness
	}
	if !pk.Curve.IsOnCurve(pk.X, pk.Y) {
		return nil, ErrInvalidPoint
	}

	e := messageScalar(m, n)

	ex, ey := pk.Curve.ScalarBaseMult(e.Bytes())
	rx, ry := pk.Curve.ScalarMult(pk.X, pk.Y, r.Bytes())
	hx, hy := pk.Curve.Add(ex, ey, rx, ry)

	return &Value{X: hx, Y: hy}, nil
}

// Verify reports whether (m, r) hashes to v.
//
// Returns false rather than an error on a mismatch: a failed verification is a
// normal outcome, not a fault. Errors are reserved for malformed inputs.
func (pk *PublicKey) Verify(m []byte, r *big.Int, v *Value) bool {
	got, err := pk.Hash(m, r)
	if err != nil {
		return false
	}
	return got.Equal(v)
}

// Adapt finds r' such that CH(newM, r') == CH(oldM, oldR).
//
// This is the redaction operation. Its cost - one modular inversion plus the
// scalar arithmetic - is the per-request floor that batching cannot amortise,
// and therefore the quantity Exp 2 isolates as CryptoTime.
func (sk *PrivateKey) Adapt(oldM []byte, oldR *big.Int, newM []byte) (*big.Int, error) {
	if sk == nil || sk.D == nil {
		return nil, ErrNoTrapdoor
	}
	n := sk.Curve.Params().N
	if oldR == nil || oldR.Sign() <= 0 || oldR.Cmp(n) >= 0 {
		return nil, ErrZeroRandomness
	}

	e := messageScalar(oldM, n)
	ePrime := messageScalar(newM, n)

	// xInv exists because n is prime and 0 < D < n, both guaranteed by KeyGen.
	xInv := new(big.Int).ModInverse(sk.D, n)
	if xInv == nil {
		return nil, errors.New("ch: trapdoor is not invertible modulo the group order")
	}

	// r' = r + (e - e') * x^-1  (mod n)
	diff := new(big.Int).Sub(e, ePrime)
	diff.Mod(diff, n)
	delta := new(big.Int).Mul(diff, xInv)
	delta.Mod(delta, n)

	rPrime := new(big.Int).Add(oldR, delta)
	rPrime.Mod(rPrime, n)

	// r' = 0 would be outside the valid range. It occurs only for a specific
	// (e - e') and is astronomically unlikely, but a zero here would produce a
	// hash the verifier rejects, so it is reported rather than returned.
	if rPrime.Sign() == 0 {
		return nil, ErrZeroRandomness
	}
	return rPrime, nil
}

// RecoverTrapdoor derives the trapdoor from a single collision:
//
//	x = (e - e') / (r' - r)  (mod n)
//
// Exported deliberately. It is not an attack tool but a test instrument: the
// fidelity tests use it to assert that this construction really is key-exposure
// vulnerable, so the property is demonstrated by the code rather than only
// asserted in a comment.
//
// It also gives the schemes a concrete way to show the difference: Ref[22]'s
// double-trapdoor construction must resist exactly this.
func RecoverTrapdoor(curve elliptic.Curve, m1 []byte, r1 *big.Int, m2 []byte, r2 *big.Int) (*big.Int, error) {
	n := curve.Params().N

	e1 := messageScalar(m1, n)
	e2 := messageScalar(m2, n)

	num := new(big.Int).Sub(e1, e2)
	num.Mod(num, n)

	den := new(big.Int).Sub(r2, r1)
	den.Mod(den, n)
	if den.Sign() == 0 {
		return nil, errors.New("ch: randomness values are equal; not a collision")
	}

	denInv := new(big.Int).ModInverse(den, n)
	if denInv == nil {
		return nil, errors.New("ch: randomness difference is not invertible")
	}

	x := new(big.Int).Mul(num, denInv)
	x.Mod(x, n)
	return x, nil
}

// -----------------------------------------------------------------------------
// Internals
// -----------------------------------------------------------------------------

// messageScalar maps a message into [0, n).
//
// Reduction modulo n introduces a negligible bias for the 256-bit curves used
// here, and preserves collision resistance under the hash.
func messageScalar(m []byte, n *big.Int) *big.Int {
	sum := sha256.Sum256(m)
	e := new(big.Int).SetBytes(sum[:])
	return e.Mod(e, n)
}

// randScalar draws uniformly from [1, n-1].
//
// Rejection sampling rather than modular reduction: reducing a random 256-bit
// value modulo n biases the low end, and biased nonces are how discrete-log
// systems leak keys.
func randScalar(rnd io.Reader, n *big.Int) (*big.Int, error) {
	byteLen := (n.BitLen() + 7) / 8
	buf := make([]byte, byteLen)

	for i := 0; i < 1000; i++ {
		if _, err := io.ReadFull(rnd, buf); err != nil {
			return nil, err
		}
		// Mask off bits above the group order so rejection converges quickly.
		if excess := uint(byteLen*8 - n.BitLen()); excess > 0 {
			buf[0] &= byte(0xff >> excess)
		}
		k := new(big.Int).SetBytes(buf)
		if k.Sign() > 0 && k.Cmp(n) < 0 {
			return k, nil
		}
	}
	return nil, errors.New("ch: failed to draw a scalar in range")
}
