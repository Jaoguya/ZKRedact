package ch

import (
	"crypto/elliptic"
	"io"
	"math/big"
)

// This file records which chameleon hash construction each system under test
// actually specifies, and defines the interface they share.
//
// WHY THIS MATTERS. Exp 2 reports CryptoTime as a first-class metric, and CH
// adaptation is the whole of it. The constructions below differ in cost: the
// classic scheme performs one inversion, the ephemeral-trapdoor scheme
// additionally derives a fresh key component per redaction, and the
// double-trapdoor scheme carries two secrets through every operation.
//
// Substituting a cheaper construction for a more expensive one does not fail
// any test. It simply makes that baseline faster than its own paper allows, and
// nothing in the results would reveal it. So the mapping is written down here
// rather than left to whoever wires the schemes together.
//
//	System      Construction                        Source
//	---------   ---------------------------------   ---------------------------
//	ZK-Redact   unspecified; classic is admissible  ZK-Redact.md Phase 1 Step 3,
//	                                                Phase 4 Step 3 (generic
//	                                                CH.KeyGen / Hash / Adapt)
//	Ref[10]     none - uses pruning plus voting     no CH anywhere in the scheme
//	Ref[13]     ephemeral trapdoor, two-component   Ref[13].md Eq. 5:
//	            key (x, y) with per-block Y         ch = (X*Y)^H1(h||m,Y) * g^r
//	                                                     = g^(H1(...)(x+y)+r)
//	Ref[22]     double trapdoor (Chen et al.),      Ref[22].md §II-A: KGen, HGen,
//	            key-exposure resistant              RHGen, Verify, Adapt
//
// Ref[22] explicitly identifies the classic Krawczyk-Rabin construction - the
// one implemented in chameleon.go - as the scheme it replaces, precisely because
// of key exposure (Ref[22].md:69). Using it for that baseline would implement
// the thing the paper argues against.

// Scheme is the chameleon hash interface every construction implements.
//
// Kept deliberately narrow: the experiment harness only ever needs to hash,
// verify and adapt. Construction-specific state - Ref[13]'s ephemeral Y,
// Ref[22]'s second trapdoor - stays inside each implementation rather than
// leaking into a union type that every caller would have to reason about.
type Scheme interface {
	// Name identifies the construction in results, so a reader can tell which
	// CH produced a given CryptoTime.
	Name() string

	// KeyGen produces a key pair.
	KeyGen(curve elliptic.Curve, rnd io.Reader) (Key, error)

	// Hash computes the chameleon hash of m under randomness r.
	Hash(k Key, m []byte, r *big.Int) (*Value, error)

	// Verify reports whether (m, r) hashes to v.
	Verify(k Key, m []byte, r *big.Int, v *Value) bool

	// Adapt finds randomness collapsing newM onto the hash of (oldM, oldR).
	//
	// The returned Randomness may carry construction-specific components: Ref[13]
	// must return a fresh ephemeral Y alongside r', since its verification
	// equation takes both.
	Adapt(k Key, oldM []byte, oldR Randomness, newM []byte, rnd io.Reader) (Randomness, error)

	// KeyExposureResistant reports whether publishing a collision leaks the
	// trapdoor. Recorded into results: a scheme benchmarked with a
	// non-resistant construction where its paper specifies a resistant one has
	// been given an unearned advantage.
	KeyExposureResistant() bool
}

// Key is a construction-specific key pair.
type Key interface {
	// Public returns the curve point(s) a verifier needs.
	Public() []*big.Int

	// HasTrapdoor reports whether this key can adapt.
	HasTrapdoor() bool
}

// Randomness is the per-hash randomness.
//
// An interface rather than *big.Int because Ref[13] carries an ephemeral public
// component Y in addition to the scalar r, and its verification equation needs
// both. Modelling that as a bare scalar would force the ephemeral part into a
// side channel outside the type system, where it would eventually be dropped.
type Randomness interface {
	// Scalar returns the primary randomness value.
	Scalar() *big.Int

	// Aux returns any additional components, empty for the classic
	// construction.
	Aux() []*big.Int
}

// -----------------------------------------------------------------------------
// Classic construction (implemented in chameleon.go)
// -----------------------------------------------------------------------------

// ClassicRandomness wraps a scalar for the classic construction.
type ClassicRandomness struct{ R *big.Int }

func (c ClassicRandomness) Scalar() *big.Int { return c.R }
func (c ClassicRandomness) Aux() []*big.Int  { return nil }

// Public returns the single public point.
func (pk *PublicKey) Public() []*big.Int { return []*big.Int{pk.X, pk.Y} }

// HasTrapdoor reports false: a PublicKey alone cannot adapt.
func (pk *PublicKey) HasTrapdoor() bool { return false }

// HasTrapdoor reports true when the private scalar is present.
func (sk *PrivateKey) HasTrapdoor() bool { return sk != nil && sk.D != nil }

// -----------------------------------------------------------------------------
// Constructions still required
// -----------------------------------------------------------------------------

// EphemeralTrapdoor is Ref[13]'s construction (Ref[13].md Eq. 5):
//
//	ch = (X * Y)^H1(h_{i-1} || m_i, Y) * g^r  =  g^(H1(...)(x+y) + r)
//
// The key has two secret components (x, y). Redaction derives a fresh ephemeral
// y' per block, so Y' = g^y' changes with every adaptation and the verification
// equation must be checked against the new Y'.
//
// NOT YET IMPLEMENTED. Wiring Ref[13] to the classic construction instead would
// omit the per-redaction ephemeral key derivation, making that baseline's
// CryptoTime lower than its design permits - a silent, invisible advantage in
// Exp 2.
//
// TODO(ref13): implement over the configured pairing curve and register here.

// DoubleTrapdoor is Ref[22]'s construction: the key-exposure resistant double
// trapdoor family of Chen et al. (Ref[22].md §II-A), with algorithms
// KGen, HGen, RHGen, Verify, Adapt.
//
// NOT YET IMPLEMENTED. Ref[22] adopts it specifically to escape the key exposure
// of the classic scheme (Ref[22].md:69), so substituting the classic one would
// implement the very weakness the paper exists to remove, and would understate
// that baseline's cost.
//
// TODO(ref22): implement over P-256 and register here.

// Registry maps a construction name to its implementation.
//
// Empty entries are deliberate. A scheme that cannot find its required
// construction must fail at Setup rather than silently falling back to the
// classic one - a fallback here would be indistinguishable from correct
// behaviour in every result the harness produces.
var Registry = map[string]Scheme{
	// "classic":            &classicScheme{},   // TODO: adapter over chameleon.go
	// "ephemeral_trapdoor": nil,                // TODO(ref13)
	// "double_trapdoor":    nil,                // TODO(ref22)
}

// Required names the construction each system must use. Consulted at Setup so a
// mismatch is refused before any measurement is taken.
var Required = map[string]string{
	"zkredact":   "classic", // spec is construction-agnostic; classic admissible
	"ref13_vrbc": "ephemeral_trapdoor",
	"ref22_shen": "double_trapdoor",
	// ref10_emt uses no chameleon hash.
}
