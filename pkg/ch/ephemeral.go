package ch

import (
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// Ephemeral-trapdoor chameleon hash — the construction Ref[13] specifies.
//
// Source: Ref[13].md Eq. 5, with the adaptation rule from §4.3.
//
//	ch_i = (X · Y)^{H1(h_{i-1} ‖ m_i, Y)} · g^{r_i}
//	     = g^{H1(h_{i-1} ‖ m_i, Y)·(x+y) + r_i}
//
// written here in additive elliptic-curve notation as
//
//	CH = e·(X + Y) + r·P,   e = H1(ctx ‖ m ‖ Y) mod n
//
// The key has TWO secret components. x is long-term; y is ephemeral and is
// replaced on every adaptation via y' = H2(x ‖ m'), so the public component Y
// changes with each redaction and the verifier checks against the new Y'.
//
// WHY THE VARIANT MATTERS FOR THE MEASUREMENT. Every adaptation derives a fresh
// key component and a fresh curve point — work the classic single-trapdoor
// construction never performs. Running Ref[13] on the classic construction
// would omit that cost, and since Exp 2 reports CryptoTime as a headline
// metric, the baseline would appear faster than its own design permits with
// nothing in the results to show why.

// EphemeralKey is a two-component chameleon hash key.
type EphemeralKey struct {
	Curve elliptic.Curve

	// x is the long-term secret; X = x·P.
	x      *big.Int
	Xx, Xy *big.Int

	// y is the current ephemeral secret; Y = y·P. Both change on every Adapt.
	y      *big.Int
	Yx, Yy *big.Int
}

// EphemeralRandomness carries the scalar r together with the ephemeral public
// point Y that was in force when the hash was computed.
//
// Y travels with the randomness because the verification equation needs it: the
// verifier cannot recompute e without knowing which Y was used. Modelling this
// as a bare scalar would push Y into a side channel outside the type system,
// where it would eventually be dropped and the verification would silently
// start checking the wrong equation.
type EphemeralRandomness struct {
	R      *big.Int
	Yx, Yy *big.Int
}

// Scalar implements Randomness.
func (e EphemeralRandomness) Scalar() *big.Int { return e.R }

// Aux implements Randomness, returning the ephemeral public point.
func (e EphemeralRandomness) Aux() []*big.Int { return []*big.Int{e.Yx, e.Yy} }

// Public implements Key, returning X followed by the current Y.
func (k *EphemeralKey) Public() []*big.Int { return []*big.Int{k.Xx, k.Xy, k.Yx, k.Yy} }

// HasTrapdoor implements Key.
func (k *EphemeralKey) HasTrapdoor() bool { return k != nil && k.x != nil && k.y != nil }

// EphemeralKeyGen generates a two-component key pair.
func EphemeralKeyGen(curve elliptic.Curve, rnd io.Reader) (*EphemeralKey, error) {
	if curve == nil {
		return nil, errors.New("ch: nil curve")
	}
	n := curve.Params().N

	x, err := randScalar(rnd, n)
	if err != nil {
		return nil, fmt.Errorf("ch/ephemeral: keygen x: %w", err)
	}
	y, err := randScalar(rnd, n)
	if err != nil {
		return nil, fmt.Errorf("ch/ephemeral: keygen y: %w", err)
	}

	xx, xy := curve.ScalarBaseMult(x.Bytes())
	yx, yy := curve.ScalarBaseMult(y.Bytes())

	return &EphemeralKey{
		Curve: curve,
		x:     x, Xx: xx, Xy: xy,
		y: y, Yx: yx, Yy: yy,
	}, nil
}

// EphemeralHash computes CH = e·(X + Y) + r·P with e = H1(ctx ‖ m ‖ Y).
//
// ctx binds the hash to its position in the chain — Ref[13] uses the previous
// block hash h_{i-1}. Passing nil is allowed for standalone use but loses that
// binding, so callers building a ledger must supply it.
func EphemeralHash(curve elliptic.Curve, Xx, Xy, Yx, Yy *big.Int, ctx, m []byte, r *big.Int) (*Value, error) {
	n := curve.Params().N
	if r == nil || r.Sign() <= 0 || r.Cmp(n) >= 0 {
		return nil, ErrZeroRandomness
	}
	if !curve.IsOnCurve(Xx, Xy) || !curve.IsOnCurve(Yx, Yy) {
		return nil, ErrInvalidPoint
	}

	e := ephemeralChallenge(curve, ctx, m, Yx, Yy)

	// S = X + Y, then e·S + r·P
	sx, sy := curve.Add(Xx, Xy, Yx, Yy)
	ex, ey := curve.ScalarMult(sx, sy, e.Bytes())
	rx, ry := curve.ScalarBaseMult(r.Bytes())
	hx, hy := curve.Add(ex, ey, rx, ry)

	return &Value{X: hx, Y: hy}, nil
}

// EphemeralPointFor returns the ephemeral component in force for a message:
// y_s = H2(x ‖ m_s) and Y_s = y_s·P.
//
// PER MESSAGE, NOT PER KEY. Ref[13] §3.2.3 stores the ephemeral point WITH the
// block — B_s = (ch_s, m_s, Y_s, r_s) — and Eq. 8 computes the block's trapdoor
// from y_s, the component belonging to that block. A key-wide "current Y" can
// serve only one block at a time, which is what a ledger never has.
//
// Callers hashing a block need Y_s to record alongside it, so this is exported:
// asking the key for its Public() Y after a Hash would hand back a component
// that says nothing about the message just hashed.
func (k *EphemeralKey) EphemeralPointFor(m []byte) (y, yx, yy *big.Int, err error) {
	if k == nil || k.x == nil {
		return nil, nil, nil, errors.New("ch/ephemeral: nil key")
	}
	n := k.Curve.Params().N
	y = deriveEphemeral(k.x, m, n)
	if y.Sign() == 0 {
		return nil, nil, nil, errors.New("ch/ephemeral: derived ephemeral component is zero")
	}
	yx, yy = k.Curve.ScalarBaseMult(y.Bytes())
	return y, yx, yy, nil
}

// Hash computes the chameleon hash of m under the ephemeral component derived
// for m, per Ref[13] Eq. 5.
//
// The component comes from the MESSAGE, not from mutable key state. Eq. 9
// derives the post-redaction component as y'_s = H2(x ‖ m'_s); deriving the
// pre-redaction one by the same rule is what lets a block be redacted twice,
// and lets two different blocks be redacted at all.
func (k *EphemeralKey) Hash(ctx, m []byte, r *big.Int) (*Value, error) {
	if k == nil {
		return nil, errors.New("ch/ephemeral: nil key")
	}
	_, yx, yy, err := k.EphemeralPointFor(m)
	if err != nil {
		return nil, err
	}
	return EphemeralHash(k.Curve, k.Xx, k.Xy, yx, yy, ctx, m, r)
}

// Verify checks a hash against a message and its randomness.
//
// The ephemeral point travels inside er, so a verifier holding only X can check
// a redacted value without any out-of-band state.
func (k *EphemeralKey) Verify(ctx, m []byte, er EphemeralRandomness, v *Value) bool {
	if k == nil || er.R == nil || er.Yx == nil || er.Yy == nil {
		return false
	}
	got, err := EphemeralHash(k.Curve, k.Xx, k.Xy, er.Yx, er.Yy, ctx, m, er.R)
	if err != nil {
		return false
	}
	return got.Equal(v)
}

// EphemeralAdapt finds randomness collapsing newM onto the hash of (oldM, oldR).
//
// Derives a fresh ephemeral component y' = H2(x ‖ newM), then solves
//
//	e·(x+y) + r  =  e'·(x+y') + r'      (mod n)
//	r' = e·(x+y) + r − e'·(x+y')
//
// The key's ephemeral component is advanced to y' on success, so subsequent
// hashes use the new Y — matching Ref[13], where Y_s is per-block state.
func (k *EphemeralKey) EphemeralAdapt(ctx, oldM []byte, oldR EphemeralRandomness, newM []byte) (EphemeralRandomness, error) {
	var out EphemeralRandomness

	if !k.HasTrapdoor() {
		return out, ErrNoTrapdoor
	}
	n := k.Curve.Params().N
	if oldR.R == nil || oldR.R.Sign() <= 0 || oldR.R.Cmp(n) >= 0 {
		return out, ErrZeroRandomness
	}

	// y' = H2(x ‖ m') mod n, deterministic per (trapdoor, new message). Eq. 9.
	yPrime := deriveEphemeral(k.x, newM, n)
	if yPrime.Sign() == 0 {
		return out, errors.New("ch/ephemeral: derived ephemeral component is zero")
	}
	ypx, ypy := k.Curve.ScalarBaseMult(yPrime.Bytes())

	// y_s for the OLD message, by the same rule. Eq. 8 needs the component that
	// belongs to THIS block, which is why it cannot be read off the key: a
	// ledger redacts many blocks and a key holds one current component.
	yOld, yoldx, yoldy, err := k.EphemeralPointFor(oldM)
	if err != nil {
		return out, err
	}

	// e over the OLD ephemeral point, e' over the new one.
	e := ephemeralChallenge(k.Curve, ctx, oldM, oldR.Yx, oldR.Yy)
	ePrime := ephemeralChallenge(k.Curve, ctx, newM, ypx, ypy)

	// The randomness must carry the point this trapdoor derives for oldM. A
	// caller passing an unrelated Y would silently produce a non-collision.
	// Checking against the DERIVED point rather than a key-wide "current Y" is
	// what makes the check correct for every block rather than the last one
	// adapted — the previous form rejected every block but one.
	if yoldx.Cmp(oldR.Yx) != 0 || yoldy.Cmp(oldR.Yy) != 0 {
		return out, errors.New(
			"ch/ephemeral: randomness carries an ephemeral point this key did not produce")
	}

	// lhs = e(x+y) + r
	sum := new(big.Int).Add(k.x, yOld)
	sum.Mod(sum, n)
	lhs := new(big.Int).Mul(e, sum)
	lhs.Add(lhs, oldR.R)
	lhs.Mod(lhs, n)

	// rhs = e'(x+y')
	sumPrime := new(big.Int).Add(k.x, yPrime)
	sumPrime.Mod(sumPrime, n)
	rhs := new(big.Int).Mul(ePrime, sumPrime)
	rhs.Mod(rhs, n)

	rPrime := new(big.Int).Sub(lhs, rhs)
	rPrime.Mod(rPrime, n)
	if rPrime.Sign() == 0 {
		return out, ErrZeroRandomness
	}

	// The new ephemeral state travels with the BLOCK, in the returned
	// randomness — B'_s = (ch_s, m'_s, Y'_s, r'_s), Ref[13] §3.2.3. The key is
	// deliberately NOT mutated: advancing a key-wide component here made every
	// other block's stored Y stale, so a second redaction against a different
	// block was refused and counted as a failure. Ref[13] indexes y and Y by
	// the block s throughout; nothing about them is key-wide.
	return EphemeralRandomness{R: rPrime, Yx: ypx, Yy: ypy}, nil
}

// ephemeralChallenge computes e = H1(ctx ‖ m ‖ Y) mod n.
//
// Y is bound into the challenge, which is what forces a verifier to use the
// ephemeral point that was actually in force. Lengths are prefixed so that
// distinct (ctx, m) pairs cannot be concatenated into the same preimage.
func ephemeralChallenge(curve elliptic.Curve, ctx, m []byte, yx, yy *big.Int) *big.Int {
	h := sha256.New()
	h.Write([]byte{0x01}) // domain tag, distinct from deriveEphemeral
	writeLengthPrefixed(h, ctx)
	writeLengthPrefixed(h, m)
	writeLengthPrefixed(h, elliptic.Marshal(curve, yx, yy))

	e := new(big.Int).SetBytes(h.Sum(nil))
	return e.Mod(e, curve.Params().N)
}

// deriveEphemeral computes y' = H2(x ‖ m') mod n.
func deriveEphemeral(x *big.Int, m []byte, n *big.Int) *big.Int {
	h := sha256.New()
	h.Write([]byte{0x02}) // domain tag, distinct from ephemeralChallenge
	writeLengthPrefixed(h, x.Bytes())
	writeLengthPrefixed(h, m)

	y := new(big.Int).SetBytes(h.Sum(nil))
	return y.Mod(y, n)
}

func writeLengthPrefixed(h io.Writer, b []byte) {
	var l [4]byte
	n := uint32(len(b))
	l[0] = byte(n >> 24)
	l[1] = byte(n >> 16)
	l[2] = byte(n >> 8)
	l[3] = byte(n)
	_, _ = h.Write(l[:])
	_, _ = h.Write(b)
}
