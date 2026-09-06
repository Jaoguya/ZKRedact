package zk

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"zkredact/pkg/crypto"
)

// Curve is the only curve this package will instantiate.
//
// Named rather than taken as a parameter so there is no path that quietly
// selects another. BN254 is the trap the project guards against: still the
// default in much ZK tooling, and roughly 100-110 bits since Kim-Barbulescu
// exTNFS (2016). Setup re-checks it against the configured target anyway.
const Curve = crypto.CurveBLS12381

// System describes the proof system in results, so no number can be read as
// coming from a scheme it did not.
const System = "Groth16"

// Params are the compiled circuit and its keys.
type Params struct {
	CCS constraint.ConstraintSystem
	PK  groth16.ProvingKey
	VK  groth16.VerifyingKey

	// PredicateDepth and TreeDepth are the shape the circuit was compiled for.
	// Recorded so a proof cannot be verified against a circuit of a different
	// shape without the mismatch being visible.
	PredicateDepth int
	TreeDepth      int

	// Constraints and PublicInputs are MEASUREMENTS, not settings. They are
	// what config/experiment.yaml's zkredact.circuit fields must be filled from
	// after `make build-zk`.
	//
	// PublicInputs excludes gnark's constant ONE wire, which
	// GetNbPublicVariables counts as public. Recording the raw count would
	// overstate the circuit's public interface by one and, since Groth16
	// verification costs one scalar multiplication per public input, misreport
	// the Exp 1 verification floor.
	Constraints  int
	PublicInputs int
}

// oneWire is gnark's constant ONE, which occupies a public variable slot but is
// not an input to the statement.
const oneWire = 1

// Setup compiles the circuit and runs the Groth16 trusted setup.
//
// targetBits is checked against the curve rather than assumed: a curve below
// the shared security level would make ZK-Redact's verification cheaper than
// every baseline's for a reason unrelated to its design.
func Setup(predicateDepth, treeDepth, targetBits int) (*Params, error) {
	if err := crypto.RequirePairingCurve(Curve, targetBits); err != nil {
		return nil, fmt.Errorf("zk: %w", err)
	}

	circuit, err := NewAuthorizationCircuit(predicateDepth, treeDepth)
	if err != nil {
		return nil, err
	}

	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return nil, fmt.Errorf("zk: compile circuit: %w", err)
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, fmt.Errorf("zk: groth16 setup: %w", err)
	}

	return &Params{
		CCS:            ccs,
		PK:             pk,
		VK:             vk,
		PredicateDepth: predicateDepth,
		TreeDepth:      treeDepth,
		Constraints:    ccs.GetNbConstraints(),
		PublicInputs:   ccs.GetNbPublicVariables() - oneWire,
	}, nil
}

// Assignment is one concrete instance of the relation.
//
// Field names mirror the circuit's, so a reader can check the statement against
// the manuscript's x_i and w_i without a translation table.
type Assignment struct {
	// Public
	StatementDigest []byte
	RegistryRoot    []byte

	// Statement components (private, bound by StatementDigest)
	TxID          []byte
	TxVersion     uint64
	Loc           uint64
	Mod           []byte
	PolicyID      []byte
	PolicyVersion uint64
	Timestamp     uint64
	Nonce         []byte

	// Witness
	Attributes   [NumAttributes]uint64
	CredSecret   []byte
	PathElements [][]byte
	PathBits     []uint64

	PolicyTerms    []uint64
	PolicyOps      []uint64
	PolicyScope    uint64
	PolicyValidity uint64
	ScopeLow       uint64
	ScopeHigh      uint64
}

// Proof carries a proof and the public inputs it was made against.
type Proof struct {
	Proof   groth16.Proof
	Witness witness.Witness // public part only
}

// Prove produces pi_i for one assignment.
func Prove(p *Params, a *Assignment) (*Proof, error) {
	full, err := a.witness(p)
	if err != nil {
		return nil, err
	}
	pub, err := full.Public()
	if err != nil {
		return nil, fmt.Errorf("zk: extract public witness: %w", err)
	}

	proof, err := groth16.Prove(p.CCS, p.PK, full)
	if err != nil {
		return nil, fmt.Errorf("zk: prove: %w", err)
	}
	return &Proof{Proof: proof, Witness: pub}, nil
}

// Verify checks one proof. This is the operation Exp 1 measures.
func Verify(p *Params, pr *Proof) error {
	if pr == nil || pr.Proof == nil {
		return fmt.Errorf("zk: nil proof")
	}
	if err := groth16.Verify(pr.Proof, p.VK, pr.Witness); err != nil {
		return fmt.Errorf("zk: verify: %w", err)
	}
	return nil
}

// NativeBatchVerify reports whether this package implements the proof system's
// own batch verification.
//
// TRUE: batch.go implements the aggregated pairing check. The two
// zkredact.proof_batch.native_batch_verify arms therefore run genuinely
// different code — per-record verification against aggregated batch
// verification — which is what makes that ablation a comparison rather than the
// same measurement twice.
const NativeBatchVerify = true

// BatchVerify verifies a batch and reports each result INDEPENDENTLY.
//
// WHAT GROTH16 CAN DO, stated accurately because the earlier comment here got
// it wrong. Verification is
//
//	e(A, B) = e(alpha, beta) * e(L, gamma) * e(C, delta)
//
// with e(alpha, beta) precomputed in the verifying key, so one proof costs
// three pairings. Batching n proofs with random scalars r_i gives
//
//	PROD_i e(A_i, B_i)^{r_i}
//	    = e(alpha,beta)^{SUM r_i} * e(SUM r_i L_i, gamma) * e(SUM r_i C_i, delta)
//
// Only e(A_i, B_i) stays per-proof, because both arguments vary; gamma and
// delta are fixed, so those two pairings aggregate across the whole batch. That
// is n+2 pairings instead of 3n — roughly a 3x constant-factor saving, and it
// holds for DISTINCT public inputs, which is what a batch of authorizations is.
//
// It is NOT sublinear, and that was the only correct part of what this comment
// used to say. It was the wrong reason to leave batching unimplemented.
//
// gnark 0.16.3 exposes no batch-verification API, so the aggregation is written
// against gnark-crypto's BLS12-381 primitives directly; see batch.go.
//
// FAILURE ISOLATION IS PRESERVED, which Phase 3 Step 4 requires. The aggregated
// check yields one verdict for the whole batch, so a failure falls back to
// per-proof verification to find the offender. The manuscript describes
// recursive bisection as the fallback; a full re-verify is the simpler form of
// the same thing and costs 3n on top of the n+3 already spent.
//
// THE COST ASYMMETRY IS REAL AND MUST NOT BE HIDDEN. An all-valid batch costs
// n+3 pairings; a batch with one bad proof costs n+3 THEN 3n. That is the
// honest price of isolation. It must never be "optimised" by returning a single
// verdict or by exiting on the first failure — either would make a batch of
// invalid proofs the fastest path through the system.
func BatchVerify(p *Params, proofs []*Proof) []error {
	out := make([]error, len(proofs))

	// One proof is not a batch: aggregation would add two pairings for nothing.
	if len(proofs) < 2 {
		for i, pr := range proofs {
			out[i] = Verify(p, pr)
		}
		return out
	}

	ok, err := batchVerifyAggregated(p, proofs)
	if err == nil && ok {
		return out // every entry nil: the whole batch verified
	}

	// Either the batch failed or aggregation could not be applied. Fall back to
	// per-proof verification, which is what says WHICH proof is bad.
	for i, pr := range proofs {
		out[i] = Verify(p, pr)
	}
	return out
}

// witness converts an Assignment into a gnark witness.
func (a *Assignment) witness(p *Params) (witness.Witness, error) {
	if len(a.PolicyTerms) != p.PredicateDepth {
		return nil, fmt.Errorf("zk: %d policy terms, circuit compiled for %d",
			len(a.PolicyTerms), p.PredicateDepth)
	}
	if len(a.PolicyOps) != p.PredicateDepth-1 {
		return nil, fmt.Errorf("zk: %d policy operators, circuit compiled for %d",
			len(a.PolicyOps), p.PredicateDepth-1)
	}
	if len(a.PathElements) != p.TreeDepth || len(a.PathBits) != p.TreeDepth {
		return nil, fmt.Errorf("zk: merkle path of %d/%d, circuit compiled for %d",
			len(a.PathElements), len(a.PathBits), p.TreeDepth)
	}

	c, err := NewAuthorizationCircuit(p.PredicateDepth, p.TreeDepth)
	if err != nil {
		return nil, err
	}

	c.StatementDigest = new(big.Int).SetBytes(a.StatementDigest)
	c.RegistryRoot = new(big.Int).SetBytes(a.RegistryRoot)

	c.TxID = new(big.Int).SetBytes(a.TxID)
	c.TxVersion = a.TxVersion
	c.Loc = a.Loc
	c.Mod = new(big.Int).SetBytes(a.Mod)
	c.PolicyID = new(big.Int).SetBytes(a.PolicyID)
	c.PolicyVersion = a.PolicyVersion
	c.Timestamp = a.Timestamp
	c.Nonce = new(big.Int).SetBytes(a.Nonce)

	for i := 0; i < NumAttributes; i++ {
		c.Attributes[i] = a.Attributes[i]
	}
	c.CredSecret = new(big.Int).SetBytes(a.CredSecret)

	for i := range a.PathElements {
		c.PathElements[i] = new(big.Int).SetBytes(a.PathElements[i])
		c.PathBits[i] = a.PathBits[i]
	}
	for i := range a.PolicyTerms {
		c.PolicyTerms[i] = a.PolicyTerms[i]
	}
	for i := range a.PolicyOps {
		c.PolicyOps[i] = a.PolicyOps[i]
	}
	c.PolicyScope = a.PolicyScope
	c.PolicyValidity = a.PolicyValidity
	c.ScopeLow = a.ScopeLow
	c.ScopeHigh = a.ScopeHigh

	w, err := frontend.NewWitness(c, ecc.BLS12_381.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("zk: build witness: %w", err)
	}
	return w, nil
}

// -----------------------------------------------------------------------------
// Host-side MiMC, matching the in-circuit hash
// -----------------------------------------------------------------------------

// Hash computes MiMC over BLS12-381's scalar field, the same hash the circuit
// uses.
//
// The prover must derive eta_i and the registry root with EXACTLY the hash the
// circuit recomputes; SHA-256 here would make every proof fail with an
// unsatisfiable constraint, which reads as a circuit bug. Kept beside the
// circuit for that reason.
func Hash(inputs ...[]byte) []byte {
	h := mimc.NewMiMC()
	for _, in := range inputs {
		h.Write(FieldBytes(in))
	}
	return h.Sum(nil)
}

// FieldBytes reduces arbitrary bytes into one field element's canonical
// encoding.
//
// MiMC consumes whole field elements: a short or over-long write is rejected or
// silently split. Reducing here keeps host and circuit agreeing on what "one
// input" means.
func FieldBytes(b []byte) []byte {
	var e bls.Element
	e.SetBytes(b)
	out := e.Bytes()
	return out[:]
}

// Uint64Bytes encodes a uint64 as one field element.
func Uint64Bytes(v uint64) []byte {
	var e bls.Element
	e.SetUint64(v)
	out := e.Bytes()
	return out[:]
}

// RandomFieldElement draws a uniform field element, for credential openings.
func RandomFieldElement() ([]byte, error) {
	var e bls.Element
	if _, err := e.SetRandom(); err != nil {
		return nil, fmt.Errorf("zk: random field element: %w", err)
	}
	out := e.Bytes()
	return out[:], nil
}

// MarshalProof serialises a proof for transport and for the audit-evidence
// store Phase 6 verifies against.
func MarshalProof(pr *Proof) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := pr.Proof.WriteTo(&buf); err != nil {
		return nil, fmt.Errorf("zk: marshal proof: %w", err)
	}
	return buf.Bytes(), nil
}
