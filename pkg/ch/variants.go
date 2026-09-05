package ch

import (
	"crypto/elliptic"
	"fmt"
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
// Baseline constructions
// -----------------------------------------------------------------------------

// Both constructions the baselines require are implemented:
//
//	ephemeral.go        Ref[13], Eq. 5 - two-component key with per-block Y
//	doubletrapdoor.go   Ref[22], §II-A - Chen et al. (KGen, HGen, RHGen,
//	                    Verify, Adapt), key-exposure free
//
// Their cost profiles differ, which is the reason the mapping is enforced
// rather than documented: Ref[13] derives a fresh key component and curve point
// on every adaptation, and Ref[22] samples a fresh k' and recomputes the
// checking string. Neither cost exists in the classic construction.

// Implemented lists the constructions available, keyed by the name used in
// Required. Consulted at Setup: a scheme whose required construction is absent
// must fail there rather than falling back to another, since a fallback would
// be indistinguishable from correct behaviour in every result the harness
// produces.
//
// The Scheme interface adapters are deliberately not wired yet. Each
// construction has a different natural signature - Ref[13] carries an ephemeral
// point through its randomness, Ref[22] separates a public checking string from
// a secret per-hash trapdoor - and forcing them through one signature before
// the schemes that use them exist would shape the interface around guesses
// rather than around the two call sites that will actually consume it.
var Implemented = map[string]bool{
	"classic":            true, // chameleon.go
	"ephemeral_trapdoor": true, // ephemeral.go
	"double_trapdoor":    true, // doubletrapdoor.go
}

// CheckRequired reports whether the construction a scheme needs is available.
func CheckRequired(schemeName string) error {
	want, ok := Required[schemeName]
	if !ok {
		return nil // scheme uses no chameleon hash
	}
	if !Implemented[want] {
		return fmt.Errorf(
			"ch: %s requires the %q construction, which is not implemented; "+
				"substituting another would change the per-redaction cost that Exp 2 measures",
			schemeName, want)
	}
	return nil
}

// Required names the construction each system must use. Consulted at Setup so a
// mismatch is refused before any measurement is taken.
var Required = map[string]string{
	"zkredact":   "classic", // spec is construction-agnostic; classic admissible
	"ref13_vrbc": "ephemeral_trapdoor",
	"ref22_shen": "double_trapdoor",
	// ref10_emt uses no chameleon hash.
}
