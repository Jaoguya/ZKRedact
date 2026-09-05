// Package zk implements ZK-Redact's Phase 2 authorization relation as a
// Groth16 circuit over BLS12-381.
//
// WHAT THE CIRCUIT PROVES. The manuscript's relation R_red(x_i, w_i) = 1 holds
// iff the requester's credential is registered, its private attributes satisfy
// the policy committed in C_P, the requested (Loc, M) is within the policy's
// scope, and the transaction and policy versions are current. The proof carries
// all of that while revealing none of the attributes.
//
// WHY THE ATTRIBUTES MUST STAY PRIVATE. That privacy is the scheme's claim.
// A circuit that took the attributes as public inputs would verify faster, cost
// fewer constraints, and produce a complete set of plausible Exp 1 numbers —
// while proving nothing the scheme promises. TestAttributesAreNotPublicInputs
// is what stops that from passing silently.
package zk

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// Attribute slots, in the order the circuit consumes them.
//
// The first three are Ref[10]'s boolean roles, which the shared dataset also
// carries (pkg/workload assigns sender/receiver/validator as booleans). Role is
// a small enumeration rather than a bit because the policy language compares it
// by value.
const (
	AttrSender = iota
	AttrReceiver
	AttrValidator
	AttrRole
	NumAttributes
)

// Role values, matching the strings pkg/workload generates.
const (
	RoleOperator = 0
	RoleAuditor  = 1
	RoleAdmin    = 2
)

// Predicate terms, matching pkg/workload.buildPredicate's term list exactly.
//
// The circuit selects among these by index. If the generator's list changes,
// TestTermSetMatchesWorkloadGenerator fails — the two must not drift, because a
// term the circuit cannot express would make some policies unprovable and the
// denial would look like a policy decision rather than a missing feature.
const (
	TermSender = iota
	TermReceiver
	TermValidator
	TermRoleOperator
	TermRoleAdmin
	NumTerms
)

// Boolean operators joining predicate terms.
const (
	OpAnd = 0
	OpOr  = 1
)

// AuthorizationCircuit is the Phase 2 relation.
//
// PUBLIC INPUTS ARE DELIBERATELY TWO. Groth16 verification cost grows with the
// number of public inputs — it is one scalar multiplication each — and Exp 1
// measures exactly that verification. Everything the verifier needs about the
// request is folded into StatementDigest, which is the manuscript's own
// eta_i = H(x_i); the verifier recomputes it from the request it already holds.
// RegistryRoot is separate because it is system state, not request state, and
// so is not part of x_i.
type AuthorizationCircuit struct {
	// -------- public --------

	// StatementDigest is eta_i = H(x_i): the compact binding digest over
	// (TID, v, Loc, M, PID, v_P, C_P, t, nu). Binding the whole statement to
	// one field element is what stops a proof for one request being replayed
	// against another.
	StatementDigest frontend.Variable `gnark:",public"`

	// RegistryRoot anchors credentials. Without it the circuit would prove
	// "some attributes satisfy the policy" rather than "MY attributes do", and
	// any prover could invent a satisfying assignment.
	RegistryRoot frontend.Variable `gnark:",public"`

	// -------- private witness: the statement's components --------
	//
	// Public information, carried privately and bound by StatementDigest. The
	// verifier already has these; passing them as public inputs would add
	// verification cost for no gain.
	TxID          frontend.Variable
	TxVersion     frontend.Variable
	Loc           frontend.Variable
	Mod           frontend.Variable
	PolicyID      frontend.Variable
	PolicyVersion frontend.Variable
	Timestamp     frontend.Variable
	Nonce         frontend.Variable

	// -------- private witness: w_i = (Cred, A, rho) --------

	// Attributes is A_i. Never public; see the package comment.
	Attributes [NumAttributes]frontend.Variable

	// CredSecret is rho_i, the credential's opening. It makes the credential
	// leaf unforgeable by anyone who has only seen the tree.
	CredSecret frontend.Variable

	// Merkle authentication path proving the credential leaf is in the
	// registry. PathBits[i] is 0 when the sibling is on the right.
	PathElements []frontend.Variable
	PathBits     []frontend.Variable

	// -------- private witness: the policy, opened against C_P --------
	//
	// The policy is public data, but carrying it as witness and checking it
	// against the committed C_P keeps the public input count at two while still
	// binding the proof to one specific registered policy.
	PolicyTerms    []frontend.Variable // term index per slot
	PolicyOps      []frontend.Variable // OpAnd / OpOr, one fewer than terms
	PolicyScope    frontend.Variable
	PolicyValidity frontend.Variable

	// Scope check: the requested location must be inside the policy's
	// permitted scope. Carried as the opening of the scope commitment.
	ScopeLow  frontend.Variable
	ScopeHigh frontend.Variable

	// depth is the predicate arity; not a circuit variable.
	depth int
	// treeDepth is the registry Merkle depth; not a circuit variable.
	treeDepth int
}

// NewAuthorizationCircuit builds a circuit shaped for one configuration.
//
// Both dimensions come from config/experiment.yaml — predicate depth from
// dataset.policies.predicate_depth, tree depth from dataset.identities.count —
// rather than being fixed here. A circuit hardcoded to one shape would silently
// stop matching the dataset it is supposed to be proving about.
func NewAuthorizationCircuit(predicateDepth, treeDepth int) (*AuthorizationCircuit, error) {
	if predicateDepth < 1 {
		return nil, fmt.Errorf("zk: predicate depth must be >= 1, got %d", predicateDepth)
	}
	if treeDepth < 1 {
		return nil, fmt.Errorf("zk: registry tree depth must be >= 1, got %d", treeDepth)
	}
	return &AuthorizationCircuit{
		PathElements: make([]frontend.Variable, treeDepth),
		PathBits:     make([]frontend.Variable, treeDepth),
		PolicyTerms:  make([]frontend.Variable, predicateDepth),
		PolicyOps:    make([]frontend.Variable, predicateDepth-1),
		depth:        predicateDepth,
		treeDepth:    treeDepth,
	}, nil
}

// Define states R_red as constraints.
func (c *AuthorizationCircuit) Define(api frontend.API) error {
	if c.depth == 0 {
		c.depth = len(c.PolicyTerms)
	}
	if c.treeDepth == 0 {
		c.treeDepth = len(c.PathElements)
	}
	if c.depth < 1 || len(c.PolicyOps) != c.depth-1 {
		return fmt.Errorf("zk: %d terms need %d operators, have %d",
			c.depth, c.depth-1, len(c.PolicyOps))
	}

	// Attributes are booleans, except Role which is an enumeration. Without
	// these the prover could supply 2 for a boolean and satisfy an AND that
	// should have failed.
	api.AssertIsBoolean(c.Attributes[AttrSender])
	api.AssertIsBoolean(c.Attributes[AttrReceiver])
	api.AssertIsBoolean(c.Attributes[AttrValidator])
	api.AssertIsLessOrEqual(c.Attributes[AttrRole], RoleAdmin)

	// ---- 1. C_P: recompute the policy commitment from the witness ----
	//
	// C_{P_j} = H(PID ‖ A ‖ C ‖ S ‖ V) in the manuscript. The predicate is the
	// authorization part A, so the terms and operators hash in alongside the
	// scope and validity period.
	policyHasher, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	policyHasher.Write(c.PolicyID)
	for i := 0; i < c.depth; i++ {
		policyHasher.Write(c.PolicyTerms[i])
	}
	for i := 0; i < c.depth-1; i++ {
		policyHasher.Write(c.PolicyOps[i])
	}
	policyHasher.Write(c.ScopeLow, c.ScopeHigh, c.PolicyScope, c.PolicyValidity)
	policyCommitment := policyHasher.Sum()

	// ---- 2. eta_i = H(x_i): bind the whole statement ----
	stmtHasher, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	stmtHasher.Write(
		c.TxID, c.TxVersion, c.Loc, c.Mod,
		c.PolicyID, c.PolicyVersion, policyCommitment,
		c.Timestamp, c.Nonce,
	)
	api.AssertIsEqual(stmtHasher.Sum(), c.StatementDigest)

	// ---- 3. Credential membership in the registry ----
	//
	// leaf = H(rho ‖ A). Binding the attributes into the leaf is what makes the
	// policy check about THIS requester: a prover who swaps in a satisfying
	// attribute set produces a leaf that is not in the tree.
	leafHasher, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	leafHasher.Write(c.CredSecret)
	for i := 0; i < NumAttributes; i++ {
		leafHasher.Write(c.Attributes[i])
	}
	node := leafHasher.Sum()

	for i := 0; i < c.treeDepth; i++ {
		api.AssertIsBoolean(c.PathBits[i])

		// Order the pair by the path bit without branching: a branch on a
		// witness value is not expressible, and selecting is one constraint.
		left := api.Select(c.PathBits[i], c.PathElements[i], node)
		right := api.Select(c.PathBits[i], node, c.PathElements[i])

		h, err := mimc.NewMiMC(api)
		if err != nil {
			return err
		}
		h.Write(left, right)
		node = h.Sum()
	}
	api.AssertIsEqual(node, c.RegistryRoot)

	// ---- 4. Policy satisfaction over the private attributes ----
	acc := c.termValue(api, c.PolicyTerms[0])
	for i := 1; i < c.depth; i++ {
		term := c.termValue(api, c.PolicyTerms[i])

		and := api.Mul(acc, term)
		or := api.Sub(api.Add(acc, term), and)

		api.AssertIsBoolean(c.PolicyOps[i-1])
		acc = api.Select(c.PolicyOps[i-1], or, and)
	}
	// The predicate must be SATISFIED. Asserting equality with 1 rather than
	// merely computing it is the whole point: a circuit that left acc
	// unconstrained would prove nothing about authorization at all.
	api.AssertIsEqual(acc, 1)

	// ---- 5. Scope: the requested location lies inside the policy's range ----
	api.AssertIsLessOrEqual(c.ScopeLow, c.Loc)
	api.AssertIsLessOrEqual(c.Loc, c.ScopeHigh)

	return nil
}

// termValue evaluates one predicate term against the private attributes.
//
// The term index is itself a witness, so selection is arithmetic rather than a
// branch: value = SUM_j (index == j) * value_j. Exactly one indicator is 1,
// which api.IsZero guarantees.
func (c *AuthorizationCircuit) termValue(api frontend.API, idx frontend.Variable) frontend.Variable {
	roleIsOperator := api.IsZero(api.Sub(c.Attributes[AttrRole], RoleOperator))
	roleIsAdmin := api.IsZero(api.Sub(c.Attributes[AttrRole], RoleAdmin))

	values := [NumTerms]frontend.Variable{
		TermSender:       c.Attributes[AttrSender],
		TermReceiver:     c.Attributes[AttrReceiver],
		TermValidator:    c.Attributes[AttrValidator],
		TermRoleOperator: roleIsOperator,
		TermRoleAdmin:    roleIsAdmin,
	}

	var out frontend.Variable = 0
	for j := 0; j < NumTerms; j++ {
		selected := api.IsZero(api.Sub(idx, j))
		out = api.Add(out, api.Mul(selected, values[j]))
	}
	return out
}
