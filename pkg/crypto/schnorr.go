package crypto

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// Schnorr signatures over a prime-order elliptic curve.
//
// Ref[10] uses Schnorr for committee voting: each authorized node signs its
// yes/no decision, and the redaction contract verifies every vote before
// counting it toward the threshold (Algorithm 4; Ref[10].md:322-338, citing
// Schnorr, CRYPTO '89 [43]).
//
// Construction, in additive elliptic-curve notation:
//
//	KeyGen:  x <- [1, n-1],  P = x*G
//	Sign:    k <- [1, n-1],  R = k*G
//	         e = H(R || P || m) mod n
//	         s = k + e*x       mod n        signature is (e, s)
//	Verify:  R' = s*G - e*P
//	         accept iff H(R' || P || m) mod n == e
//
// Correctness: s*G - e*P = (k + ex)G - e(xG) = kG = R, so an honest signature
// reproduces the same challenge.
//
// WHY THIS LIVES IN pkg/crypto. It is a shared primitive subject to the uniform
// security level, not a Ref[10] internal. Putting it beside the curve registry
// means the curve a signature is produced on and the curve the validator checks
// come from one table; two tables would eventually disagree, and the
// disagreement would show up as one system quietly running at a weaker level.
//
// NOT AN AGGREGATE SIGNATURE. Ref[10] writes the vote set as
// "aggregate signatures Sigma = {xi_1, xi_2, ..., xi_j}" (Ref[10].md:348), but
// that is a collection, not a cryptographic aggregate: Algorithm 3's vote()
// verifies each signature individually. Implementing a real aggregate scheme
// here would make verification sublinear in committee size and hand Ref[10] a
// speedup its own design does not provide — exactly the silent advantage this
// project exists to prevent. VerifyVotes therefore verifies one at a time.

var (
	// ErrNilCurve reports a missing curve.
	ErrNilCurve = errors.New("crypto: nil curve")

	// ErrNoPrivateKey reports signing attempted without a private key.
	ErrNoPrivateKey = errors.New("crypto: signing requires a private key")

	// ErrMalformedSignature reports a signature whose components are absent or
	// outside [1, n-1]. Rejected before any curve arithmetic, so a malformed
	// signature can never be counted as a vote.
	ErrMalformedSignature = errors.New("crypto: signature components out of range")
)

// stdCurves maps registry names to the standard-library implementations.
//
// Deliberately partial. A name in the registry but absent here is a curve whose
// security level we can check but whose arithmetic we cannot perform, and
// SignatureCurve reports that rather than falling back to a curve nobody chose.
var stdCurves = map[string]func() elliptic.Curve{
	CurveP256: elliptic.P256,
	CurveP384: elliptic.P384,
}

// SignatureCurve resolves the configured curve name and enforces the uniform
// security level in one step.
//
// Both halves matter and neither is optional: resolving without checking would
// let a weaker curve through, and checking without resolving would leave the
// caller to pick an implementation, which is where a hardcoded elliptic.P256()
// would appear. Callers pass security.signature_curve and security.target_bits
// straight from config.
func SignatureCurve(name string, targetBits int) (elliptic.Curve, error) {
	if err := RequireCurve(name, targetBits); err != nil {
		return nil, err
	}
	mk, ok := stdCurves[name]
	if !ok {
		return nil, fmt.Errorf(
			"curve %s is registered but has no standard-library implementation; "+
				"signing on it needs an external dependency, which must be recorded in "+
				"the baseline's dependency table before use", name)
	}
	return mk(), nil
}

// RequireHash reports an error unless the configured hash is the one this
// package implements.
//
// security.hash is a config field, so it can be changed. Nothing would read the
// new value — the challenge below is SHA-256 — and the run would proceed with a
// hash different from the one the config documents. That is a silent
// divergence, so it is refused instead.
func RequireHash(name string) error {
	if name != "SHA-256" {
		return fmt.Errorf(
			"security.hash=%q but the Schnorr challenge is implemented over SHA-256; "+
				"change the implementation or the config, not one without the other", name)
	}
	return nil
}

// SchnorrPublicKey is the verification key P = x*G.
type SchnorrPublicKey struct {
	Curve elliptic.Curve
	X, Y  *big.Int
}

// SchnorrPrivateKey holds the signing key x.
type SchnorrPrivateKey struct {
	SchnorrPublicKey
	D *big.Int
}

// SchnorrSignature is the pair (e, s) of Schnorr's original formulation.
//
// The (e, s) encoding is the one Ref[10]'s cited reference defines, and it is
// smaller than (R, s) — one scalar rather than a point — which matters here
// because every vote travels over the network to the redaction contract.
type SchnorrSignature struct {
	E, S *big.Int
}

// SchnorrKeyGen generates a voting key pair.
//
// rnd may be nil, in which case crypto/rand is used. Tests pass a deterministic
// reader; measured runs must not.
func SchnorrKeyGen(curve elliptic.Curve, rnd io.Reader) (*SchnorrPrivateKey, error) {
	if curve == nil {
		return nil, ErrNilCurve
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	x, err := randScalar(rnd, curve.Params().N)
	if err != nil {
		return nil, fmt.Errorf("crypto: schnorr keygen: %w", err)
	}
	px, py := curve.ScalarBaseMult(x.Bytes())
	return &SchnorrPrivateKey{
		SchnorrPublicKey: SchnorrPublicKey{Curve: curve, X: px, Y: py},
		D:                x,
	}, nil
}

// Sign produces a signature over m.
func (sk *SchnorrPrivateKey) Sign(m []byte, rnd io.Reader) (*SchnorrSignature, error) {
	if sk == nil || sk.D == nil {
		return nil, ErrNoPrivateKey
	}
	if sk.Curve == nil {
		return nil, ErrNilCurve
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	n := sk.Curve.Params().N

	// k must be fresh per signature and never reused: two signatures under the
	// same k reveal x as (s1 - s2)/(e1 - e2).
	k, err := randScalar(rnd, n)
	if err != nil {
		return nil, fmt.Errorf("crypto: schnorr sign: %w", err)
	}
	rx, ry := sk.Curve.ScalarBaseMult(k.Bytes())

	e := sk.challenge(rx, ry, m)

	// s = k + e*x mod n
	s := new(big.Int).Mul(e, sk.D)
	s.Add(s, k)
	s.Mod(s, n)

	if e.Sign() == 0 || s.Sign() == 0 {
		// Probability ~2^-256; retrying keeps Verify's range check total.
		return sk.Sign(m, rnd)
	}
	return &SchnorrSignature{E: e, S: s}, nil
}

// Verify reports whether sig is a valid signature on m under pk.
//
// Returns a bool rather than an error because that is how the caller uses it:
// vote() counts approvals and discards the rest. A vote that fails here is not
// an exceptional condition, it is a rejected vote.
func (pk *SchnorrPublicKey) Verify(m []byte, sig *SchnorrSignature) bool {
	if pk == nil || pk.Curve == nil || pk.X == nil || pk.Y == nil {
		return false
	}
	if sig == nil || sig.E == nil || sig.S == nil {
		return false
	}
	n := pk.Curve.Params().N
	if sig.E.Sign() <= 0 || sig.E.Cmp(n) >= 0 || sig.S.Sign() <= 0 || sig.S.Cmp(n) >= 0 {
		return false
	}
	if !pk.Curve.IsOnCurve(pk.X, pk.Y) {
		return false
	}

	// R' = s*G - e*P, computed as s*G + (n-e)*P.
	sgx, sgy := pk.Curve.ScalarBaseMult(sig.S.Bytes())
	negE := new(big.Int).Sub(n, sig.E)
	epx, epy := pk.Curve.ScalarMult(pk.X, pk.Y, negE.Bytes())
	rx, ry := pk.Curve.Add(sgx, sgy, epx, epy)

	// The identity element marshals to a fixed encoding, so an attacker able to
	// force it could produce a challenge independent of the key. Reject it.
	if rx.Sign() == 0 && ry.Sign() == 0 {
		return false
	}

	return pk.challenge(rx, ry, m).Cmp(sig.E) == 0
}

// challenge computes e = H(R || P || m) mod n.
//
// KEY PREFIXING. Schnorr's 1989 formulation hashes only (R, m). Binding the
// public key into the challenge is the modern standard (RFC 8032, BIP-340) and
// closes related-key attacks in the multi-key setting — which is exactly
// Ref[10]'s setting, since a committee verifies votes from many keys against
// one message. The cost is hashing one extra point per operation, which if
// anything counts slightly against Ref[10]; it is recorded as a deviation in
// docs/baselines/ref10-emt.md.
func (pk *SchnorrPublicKey) challenge(rx, ry *big.Int, m []byte) *big.Int {
	h := sha256.New()
	h.Write(elliptic.Marshal(pk.Curve, rx, ry))
	h.Write(elliptic.Marshal(pk.Curve, pk.X, pk.Y))
	h.Write(m)
	return new(big.Int).Mod(new(big.Int).SetBytes(h.Sum(nil)), pk.Curve.Params().N)
}

// Vote pairs a committee member's signature with the key it must verify under.
type Vote struct {
	Key       *SchnorrPublicKey
	Signature *SchnorrSignature
}

// VerifyVotes returns how many votes in the set carry a valid signature over m.
//
// Linear in the number of votes, by design — see the note on aggregation in the
// package comment. This is the loop Experiment 1's measurement boundary closes
// over (docs/baselines/ref10-emt.md §2), so its cost must be Ref[10]'s real
// cost: every signature verified, none skipped, no early exit once a threshold
// is reached. An early exit would make the measured cost depend on vote
// ordering rather than on committee size.
func VerifyVotes(m []byte, votes []Vote) int {
	valid := 0
	for _, v := range votes {
		if v.Key != nil && v.Key.Verify(m, v.Signature) {
			valid++
		}
	}
	return valid
}

// randScalar draws a uniform scalar in [1, n-1] by rejection sampling.
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
	return nil, errors.New("crypto: failed to draw a scalar in range")
}
