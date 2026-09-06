// Package crypto holds primitives and parameter checks shared by every system
// under test.
//
// The security-level registry lives here rather than in the config validator so
// that the validator and the runtime consult one table. Two copies would
// eventually disagree, and the disagreement would surface as a scheme quietly
// running at a weaker level than the comparison assumes — which produces clean,
// plausible, wrong numbers rather than an error.
package crypto

import (
	"fmt"
	"sort"
	"strings"
)

// Curve names recognised by the registry.
const (
	CurveP256      = "P-256"
	CurveP384      = "P-384"
	CurveSecp256k1 = "secp256k1"
	CurveEd25519   = "Ed25519"
	CurveBLS12381  = "BLS12-381"
	CurveBLS12377  = "BLS12-377"
	CurveBN254     = "BN254"
	CurveBN382     = "BN382"
)

// curveBits maps a curve to its effective security level.
//
// BN254 is the entry that matters. It was quoted at 128-bit for years until the
// Kim-Barbulescu exTNFS improvements (2016) reduced it to roughly 100-110 bits.
// Much ZK tooling still defaults to it, so an accidental BN254 is easy to
// introduce and invisible in results: whichever scheme uses it simply looks
// faster.
var curveBits = map[string]int{
	CurveP256:      128,
	CurveP384:      192,
	CurveSecp256k1: 128,
	CurveEd25519:   128,
	CurveBLS12381:  128,
	CurveBLS12377:  128,
	CurveBN254:     100,
	"BN128":        100, // alias for BN254
	CurveBN382:     128,
}

// pairingCapable lists curves usable for the pairing operations Ref[13]
// requires. A non-pairing curve there is a configuration error, not a
// performance trade-off.
var pairingCapable = map[string]bool{
	CurveBLS12381: true,
	CurveBLS12377: true,
	CurveBN254:    true,
	"BN128":       true,
	CurveBN382:    true,
}

// ErrUnknownCurve reports a curve absent from the registry. Unknown is treated
// as an error rather than assumed safe: an unverifiable security level cannot
// support a fair comparison.
type ErrUnknownCurve struct{ Name string }

func (e ErrUnknownCurve) Error() string {
	return fmt.Sprintf("unknown curve %q (known: %s)", e.Name, strings.Join(KnownCurves(), ", "))
}

// ErrWeakCurve reports a curve below the uniform target level.
type ErrWeakCurve struct {
	Name   string
	Bits   int
	Target int
}

func (e ErrWeakCurve) Error() string {
	msg := fmt.Sprintf(
		"%s provides ~%d-bit security, below the %d-bit target: "+
			"a scheme using it would gain speed from weaker parameters and void the comparison",
		e.Name, e.Bits, e.Target)
	if strings.HasPrefix(e.Name, "BN") {
		msg += ". BN curves were quoted at 128-bit before the Kim-Barbulescu exTNFS " +
			"attack (2016); BLS12-381 is the standard 128-bit replacement"
	}
	return msg
}

// CurveBits returns the effective security level of a curve.
func CurveBits(name string) (int, error) {
	bits, ok := curveBits[name]
	if !ok {
		return 0, ErrUnknownCurve{Name: name}
	}
	return bits, nil
}

// RequireCurve reports an error unless the curve is known and meets target bits.
//
// Called from every scheme's Setup so a misconfigured level fails at startup
// rather than producing a full set of results that cannot be used.
func RequireCurve(name string, target int) error {
	bits, err := CurveBits(name)
	if err != nil {
		return err
	}
	if bits < target {
		return ErrWeakCurve{Name: name, Bits: bits, Target: target}
	}
	return nil
}

// RequirePairingCurve additionally checks pairing capability.
func RequirePairingCurve(name string, target int) error {
	if err := RequireCurve(name, target); err != nil {
		return err
	}
	if !pairingCapable[name] {
		return fmt.Errorf("curve %s does not support pairings, required by the Ref[13] baseline", name)
	}
	return nil
}

// pairingImplemented lists the pairing curves this codebase can actually
// operate on, as distinct from the ones the registry can describe.
//
// WHY THE DISTINCTION MATTERS. pairingCapable above answers "does this curve
// support pairings at all", which is a fact about mathematics. This answers
// "would selecting it change what runs", which is a fact about our code — and
// the two diverge. pkg/zk pins BLS12-381 in a constant, and Ref[13]'s BAT and
// vector commitments import gnark-crypto's bls12-381 package directly, so the
// curve is compiled in at both consumers.
//
// Without this check, security.pairing_curve: BLS12-377 passes every gate — it
// is 128-bit and pairing-capable — while both consumers keep running
// BLS12-381. That is not merely a stale setting: pkg/results embeds the
// resolved config in every output file, so the divergence would be RECORDED as
// fact, and a reader would have a results file naming a curve the measurement
// never used.
//
// The same shape as SignatureCurve refusing a registered curve with no
// standard-library implementation, and as RequireHash refusing a
// security.hash the challenge does not compute.
var pairingImplemented = map[string]bool{
	CurveBLS12381: true,
}

// RequireImplementedPairingCurve reports an error unless the named curve is one
// this codebase actually operates on.
//
// Enforced at the config gate rather than at each point of use: today there is
// no genuine choice to bind, because only one pairing curve is implemented. If
// a second one is ever added, move this to the consumers, where the choice
// would then be real.
func RequireImplementedPairingCurve(name string) error {
	if pairingImplemented[name] {
		return nil
	}
	return fmt.Errorf(
		"pairing curve %s has no implementation here (implemented: %s); "+
			"pkg/zk pins its curve in a constant and Ref[13] imports one directly, so "+
			"selecting %s would change the recorded config without changing what runs",
		name, strings.Join(ImplementedPairingCurves(), ", "), name)
}

// ImplementedPairingCurves lists the pairing curves with an implementation,
// sorted.
func ImplementedPairingCurves() []string {
	out := make([]string, 0, len(pairingImplemented))
	for k := range pairingImplemented {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// KnownCurves lists registered curve names, sorted.
func KnownCurves() []string {
	out := make([]string, 0, len(curveBits))
	for k := range curveBits {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// -----------------------------------------------------------------------------
// RSA / accumulator sizing
// -----------------------------------------------------------------------------

// RSABits returns the approximate symmetric-equivalent security of an RSA-style
// modulus, following the NIST SP 800-57 equivalences. Used for Ref[22]'s
// trapdoorless universal accumulator.
func RSABits(modulusBits int) int {
	switch {
	case modulusBits >= 15360:
		return 256
	case modulusBits >= 7680:
		return 192
	case modulusBits >= 3072:
		return 128
	case modulusBits >= 2048:
		return 112
	default:
		return 80
	}
}

// RequireRSA reports an error unless the modulus meets target bits.
func RequireRSA(modulusBits, target int) error {
	if got := RSABits(modulusBits); got < target {
		return fmt.Errorf(
			"RSA modulus of %d bits provides ~%d-bit security, below the %d-bit target "+
				"(3072 bits is the 128-bit equivalence)",
			modulusBits, got, target)
	}
	return nil
}

// -----------------------------------------------------------------------------
// Proof systems
// -----------------------------------------------------------------------------

// ProofSystem names a ZK backend.
type ProofSystem string

const (
	Groth16 ProofSystem = "groth16"
	Plonk   ProofSystem = "plonk"
)

// SupportsBatchVerification reports whether a proof system can verify several
// proofs over the same circuit together.
//
// Exp 1 sweeps native batch verification on and off to test the Phase 3 claim
// that sharding provides parallelism independently of it. Selecting a backend
// without batch support would leave half that grid unmeasurable, so the runner
// checks this before starting rather than discovering it mid-sweep.
func (p ProofSystem) SupportsBatchVerification() bool {
	switch p {
	case Groth16:
		// Groth16 proofs over one circuit batch via random linear combination.
		return true
	case Plonk:
		return false
	default:
		return false
	}
}

// Valid reports whether the proof system is recognised.
func (p ProofSystem) Valid() bool {
	return p == Groth16 || p == Plonk
}
