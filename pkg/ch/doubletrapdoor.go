package ch

import (
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// Double-trapdoor chameleon hash — the construction Ref[22] specifies.
//
// Source: Ref[22].md §II-A, the family of Chen et al. with algorithms
// (KGen, HGen, RHGen, Verify, Adapt), transcribed exactly:
//
//	KGen(1^λ)              -> tk = (x, t), hk = Y = xP
//	HGen(tk, m)            -> h = tP;  k <-$ Z_q;  K = kP
//	                          r = t − H(m, K)·(k + x)
//	                          ξ = (r, K)
//	RHGen(m, ξ, hk)        -> h = H(m, K)·(K + hk) + rP
//	Verify(h, m, ξ, hk)    -> h ?= H(m, K)·(K + hk) + rP
//	Adapt(tk, h, m, ξ, m') -> k' <-$ Z_q;  K' = k'P
//	                          r' = t − H(m', K')·(k' + x)
//	                          ξ' = (r', K')
//
// Correctness of RHGen:
//
//	H(m,K)·(K + Y) + rP = [H(m,K)(k + x) + r]P
//	                    = [H(m,K)(k + x) + t − H(m,K)(k + x)]P = tP = h
//
// TWO TRAPDOORS. x is long-term and shared across hashes; t is specific to one
// hash value, since h = tP. As the paper notes, reusing (x, Y) with different t
// yields different hash values, which is what keeps the redactor's storage
// small.
//
// KEY-EXPOSURE FREENESS is the reason this construction exists, and the reason
// it cannot be swapped for the classic one. Each adaptation samples a fresh k',
// so every published collision introduces a new unknown alongside the two
// secrets. The system stays underdetermined no matter how many collisions an
// observer collects — whereas the classic construction (chameleon.go) yields x
// from a single collision.
//
// Ref[22] names Krawczyk-Rabin as the scheme it replaces for exactly this
// reason (Ref[22].md:69). Benchmarking that baseline on the classic
// construction would implement the weakness the paper exists to remove, and
// would understate its per-redaction cost in Exp 2.

// DoubleTrapdoorKey holds the long-term secret x and public Y = xP.
//
// The per-hash secret t is not stored here: it belongs to a specific hash value
// and is returned by HGen as part of DoubleTrapdoorHandle.
type DoubleTrapdoorKey struct {
	Curve elliptic.Curve

	x      *big.Int // long-term trapdoor
	Yx, Yy *big.Int // hk = Y = xP
}

// DoubleTrapdoorHandle is the redactor's state for one hash value: the value
// itself plus the per-hash trapdoor t needed to adapt it.
//
// t is secret. It is separated from the checking string so that the type system
// distinguishes what may be published (Checking) from what may not (T).
type DoubleTrapdoorHandle struct {
	Hash *Value
	T    *big.Int // per-hash trapdoor; h = tP
}

// DoubleTrapdoorChecking is the checking string ξ = (r, K), which is public.
type DoubleTrapdoorChecking struct {
	R      *big.Int
	Kx, Ky *big.Int
}

// Scalar implements Randomness.
func (c DoubleTrapdoorChecking) Scalar() *big.Int { return c.R }

// Aux implements Randomness, returning K.
func (c DoubleTrapdoorChecking) Aux() []*big.Int { return []*big.Int{c.Kx, c.Ky} }

// Public implements Key.
func (k *DoubleTrapdoorKey) Public() []*big.Int { return []*big.Int{k.Yx, k.Yy} }

// HasTrapdoor implements Key.
func (k *DoubleTrapdoorKey) HasTrapdoor() bool { return k != nil && k.x != nil }

// DoubleTrapdoorKeyGen implements CH.KGen: x <-$ Z_q, Y = xP.
func DoubleTrapdoorKeyGen(curve elliptic.Curve, rnd io.Reader) (*DoubleTrapdoorKey, error) {
	if curve == nil {
		return nil, errors.New("ch: nil curve")
	}
	x, err := randScalar(rnd, curve.Params().N)
	if err != nil {
		return nil, fmt.Errorf("ch/double: keygen: %w", err)
	}
	yx, yy := curve.ScalarBaseMult(x.Bytes())
	return &DoubleTrapdoorKey{Curve: curve, x: x, Yx: yx, Yy: yy}, nil
}

// HGen implements CH.HGen: h = tP with fresh t, and ξ = (r, K) where K = kP and
// r = t − H(m, K)(k + x).
func (k *DoubleTrapdoorKey) HGen(m []byte, rnd io.Reader) (*DoubleTrapdoorHandle, DoubleTrapdoorChecking, error) {
	var ck DoubleTrapdoorChecking
	if !k.HasTrapdoor() {
		return nil, ck, ErrNoTrapdoor
	}
	n := k.Curve.Params().N

	t, err := randScalar(rnd, n)
	if err != nil {
		return nil, ck, fmt.Errorf("ch/double: hgen t: %w", err)
	}
	kk, err := randScalar(rnd, n)
	if err != nil {
		return nil, ck, fmt.Errorf("ch/double: hgen k: %w", err)
	}

	kx, ky := k.Curve.ScalarBaseMult(kk.Bytes())
	r := doubleTrapdoorR(k.Curve, t, kk, k.x, m, kx, ky)

	hx, hy := k.Curve.ScalarBaseMult(t.Bytes())

	return &DoubleTrapdoorHandle{Hash: &Value{X: hx, Y: hy}, T: t},
		DoubleTrapdoorChecking{R: r, Kx: kx, Ky: ky}, nil
}

// RHGen implements CH.RHGen: recompute h from public data alone.
//
// Takes no trapdoor, which is the point — any verifier holding hk can rebuild
// the hash from (m, ξ).
func RHGen(curve elliptic.Curve, m []byte, ck DoubleTrapdoorChecking, hkx, hky *big.Int) (*Value, error) {
	n := curve.Params().N
	if ck.R == nil || ck.R.Sign() < 0 || ck.R.Cmp(n) >= 0 {
		return nil, ErrZeroRandomness
	}
	if !curve.IsOnCurve(ck.Kx, ck.Ky) || !curve.IsOnCurve(hkx, hky) {
		return nil, ErrInvalidPoint
	}

	e := doubleTrapdoorChallenge(curve, m, ck.Kx, ck.Ky)

	// H(m,K)·(K + hk) + rP
	sx, sy := curve.Add(ck.Kx, ck.Ky, hkx, hky)
	ex, ey := curve.ScalarMult(sx, sy, e.Bytes())
	rx, ry := curve.ScalarBaseMult(ck.R.Bytes())
	hx, hy := curve.Add(ex, ey, rx, ry)

	return &Value{X: hx, Y: hy}, nil
}

// Verify implements CH.Verify.
func (k *DoubleTrapdoorKey) Verify(h *Value, m []byte, ck DoubleTrapdoorChecking) bool {
	got, err := RHGen(k.Curve, m, ck, k.Yx, k.Yy)
	if err != nil {
		return false
	}
	return got.Equal(h)
}

// Adapt implements CH.Adapt: sample a fresh k', set K' = k'P and
// r' = t − H(m', K')(k' + x).
//
// The fresh k' per adaptation is what provides key-exposure freeness: each
// published collision adds an unknown rather than an equation.
func (k *DoubleTrapdoorKey) Adapt(handle *DoubleTrapdoorHandle, newM []byte, rnd io.Reader) (DoubleTrapdoorChecking, error) {
	var out DoubleTrapdoorChecking
	if !k.HasTrapdoor() {
		return out, ErrNoTrapdoor
	}
	if handle == nil || handle.T == nil {
		return out, errors.New("ch/double: adaptation requires the per-hash trapdoor t")
	}
	n := k.Curve.Params().N

	kPrime, err := randScalar(rnd, n)
	if err != nil {
		return out, fmt.Errorf("ch/double: adapt k': %w", err)
	}
	kx, ky := k.Curve.ScalarBaseMult(kPrime.Bytes())
	r := doubleTrapdoorR(k.Curve, handle.T, kPrime, k.x, newM, kx, ky)

	return DoubleTrapdoorChecking{R: r, Kx: kx, Ky: ky}, nil
}

// doubleTrapdoorR computes r = t − H(m, K)·(k + x) mod n.
func doubleTrapdoorR(curve elliptic.Curve, t, k, x *big.Int, m []byte, kx, ky *big.Int) *big.Int {
	n := curve.Params().N

	e := doubleTrapdoorChallenge(curve, m, kx, ky)

	sum := new(big.Int).Add(k, x)
	sum.Mod(sum, n)

	prod := new(big.Int).Mul(e, sum)
	prod.Mod(prod, n)

	r := new(big.Int).Sub(t, prod)
	return r.Mod(r, n)
}

// doubleTrapdoorChallenge computes H_{Z_q}(m, K) mod n.
func doubleTrapdoorChallenge(curve elliptic.Curve, m []byte, kx, ky *big.Int) *big.Int {
	h := sha256.New()
	h.Write([]byte{0x03}) // domain tag, distinct from the other constructions
	writeLengthPrefixed(h, m)
	writeLengthPrefixed(h, elliptic.Marshal(curve, kx, ky))

	e := new(big.Int).SetBytes(h.Sum(nil))
	return e.Mod(e, curve.Params().N)
}
