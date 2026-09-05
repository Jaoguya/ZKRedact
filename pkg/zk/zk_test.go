package zk

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	"zkredact/pkg/scheme"
)

// The test circuit is deliberately small. Depth 3 matches
// dataset.policies.predicate_depth; tree depth 3 holds 8 credentials, enough to
// exercise both path directions at every level.
const (
	testPredicateDepth = 3
	testTreeDepth      = 3
)

// -----------------------------------------------------------------------------
// Fixtures
// -----------------------------------------------------------------------------

func testPolicy(t *testing.T, predicate string) *Policy {
	t.Helper()
	p, err := CompilePolicy(
		scheme.Policy{ID: "pol-0000", Version: 1, Predicate: predicate},
		testPredicateDepth, 512)
	if err != nil {
		t.Fatalf("CompilePolicy(%q): %v", predicate, err)
	}
	return p
}

func testRegistry(t *testing.T, leaf []byte) *Registry {
	t.Helper()
	leaves := [][]byte{
		Hash(Uint64Bytes(11)), Hash(Uint64Bytes(12)),
		leaf,
		Hash(Uint64Bytes(13)), Hash(Uint64Bytes(14)),
	}
	reg, err := NewRegistry(leaves, testTreeDepth)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return reg
}

func testRequest() *scheme.Request {
	return &scheme.Request{
		ID:          "req-0001",
		RequesterID: "id-000000",
		TargetTxID:  "tx-00000003",
		NewContent:  []byte("redacted"),
		PolicyID:    "pol-0000",
		Timestamp:   time.Unix(1750000000, 0),
		Nonce:       []byte("nonce-1"),
	}
}

// satisfyingAssignment builds a valid instance: attributes that satisfy the
// predicate, a credential in the registry, and a location inside scope.
func satisfyingAssignment(t *testing.T, predicate string) (*Assignment, *Policy) {
	t.Helper()

	pol := testPolicy(t, predicate)
	attrs := [NumAttributes]uint64{
		AttrSender: 1, AttrReceiver: 1, AttrValidator: 1, AttrRole: RoleAdmin,
	}
	if !pol.Satisfies(attrs) {
		t.Fatalf("fixture attributes do not satisfy %q", predicate)
	}

	credSecret := Uint64Bytes(424242)
	reg := testRegistry(t, CredentialLeaf(credSecret, attrs))

	st, err := BuildStatement(testRequest(), pol, 0, 128)
	if err != nil {
		t.Fatalf("BuildStatement: %v", err)
	}
	a, err := NewAssignment(st, pol, attrs, credSecret, reg)
	if err != nil {
		t.Fatalf("NewAssignment: %v", err)
	}
	return a, pol
}

// circuitFor returns an empty circuit of the test shape.
func circuitFor(t *testing.T) *AuthorizationCircuit {
	t.Helper()
	c, err := NewAuthorizationCircuit(testPredicateDepth, testTreeDepth)
	if err != nil {
		t.Fatalf("NewAuthorizationCircuit: %v", err)
	}
	return c
}

// witnessCircuit fills a circuit struct from an assignment, for gnark's
// constraint-level test harness (which is far faster than a full Groth16 setup).
func witnessCircuit(t *testing.T, a *Assignment) *AuthorizationCircuit {
	t.Helper()
	c := circuitFor(t)

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
	return c
}

// -----------------------------------------------------------------------------
// The relation holds, and only for satisfying instances
// -----------------------------------------------------------------------------

func TestCircuitAcceptsASatisfyingInstance(t *testing.T) {
	a, _ := satisfyingAssignment(t, "((sender OR receiver) AND validator)")
	test.NewAssert(t).SolvingSucceeded(
		circuitFor(t), witnessCircuit(t, a),
		test.WithCurves(ecc.BLS12_381),
		test.WithBackends(backend.GROTH16),
	)
}

// Each of these mutations must make the circuit unsatisfiable. They are the
// tests that would fail if the circuit stopped constraining anything: a
// relation that accepts everything verifies fastest of all and produces a
// complete, plausible set of Exp 1 numbers.
func TestCircuitRejectsTamperedInstances(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(c *AuthorizationCircuit)
		why    string
	}{
		{
			name:   "attributes swapped for a satisfying set",
			mutate: func(c *AuthorizationCircuit) { c.Attributes[AttrValidator] = 0 },
			why:    "the credential leaf binds the attributes, so substituting them leaves the registry",
		},
		{
			name:   "credential opening guessed",
			mutate: func(c *AuthorizationCircuit) { c.CredSecret = big.NewInt(7) },
			why:    "membership must require rho, or anyone who has seen the tree can prove",
		},
		{
			name:   "statement digest altered",
			mutate: func(c *AuthorizationCircuit) { c.StatementDigest = big.NewInt(1) },
			why:    "a proof must not be replayable against a different request",
		},
		{
			name:   "registry root altered",
			mutate: func(c *AuthorizationCircuit) { c.RegistryRoot = big.NewInt(1) },
			why:    "the anchor is what makes the credential a real registration",
		},
		{
			name:   "merkle sibling altered",
			mutate: func(c *AuthorizationCircuit) { c.PathElements[0] = big.NewInt(9) },
			why:    "a forged path must not authenticate",
		},
		{
			name:   "path direction flipped",
			mutate: func(c *AuthorizationCircuit) { c.PathBits[0] = api1minus(c.PathBits[0]) },
			why:    "hashing the pair in the wrong order must not reach the same root",
		},
		{
			name:   "policy term substituted",
			mutate: func(c *AuthorizationCircuit) { c.PolicyTerms[0] = TermRoleAdmin },
			why:    "the policy is bound by C_P inside the digest; a different policy is a different statement",
		},
		{
			name:   "policy operator flipped",
			mutate: func(c *AuthorizationCircuit) { c.PolicyOps[0] = OpAnd },
			why:    "swapping OR for AND is the cheapest way to weaken a predicate",
		},
		{
			name:   "location below scope",
			mutate: func(c *AuthorizationCircuit) { c.Loc = 0; c.ScopeLow = 10 },
			why:    "redacting outside the permitted region must not prove",
		},
		{
			name:   "location above scope",
			mutate: func(c *AuthorizationCircuit) { c.Loc = 999; c.ScopeHigh = 512 },
			why:    "the upper scope bound must bind too",
		},
		{
			name:   "non-boolean attribute",
			mutate: func(c *AuthorizationCircuit) { c.Attributes[AttrSender] = 2 },
			why:    "a value of 2 would satisfy an AND that should have failed",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := satisfyingAssignment(t, "((sender OR receiver) AND validator)")
			w := witnessCircuit(t, a)
			tc.mutate(w)

			test.NewAssert(t).SolvingFailed(
				circuitFor(t), w,
				test.WithCurves(ecc.BLS12_381),
				test.WithBackends(backend.GROTH16),
			)
		})
	}
}

// api1minus flips a 0/1 witness value.
func api1minus(v frontend.Variable) frontend.Variable {
	if n, ok := v.(uint64); ok {
		return 1 - n
	}
	if n, ok := v.(int); ok {
		return 1 - n
	}
	if n, ok := v.(*big.Int); ok {
		return new(big.Int).Sub(big.NewInt(1), n)
	}
	return 0
}

// TestUnsatisfiedPolicyIsRefusedBeforeProving pins that a denial is reported as
// a denial. Attempting the proof instead would surface it as a solver failure,
// which in a run is indistinguishable from a broken circuit.
func TestUnsatisfiedPolicyIsRefusedBeforeProving(t *testing.T) {
	pol := testPolicy(t, "((sender AND receiver) AND validator)")
	attrs := [NumAttributes]uint64{AttrSender: 1, AttrRole: RoleOperator}
	if pol.Satisfies(attrs) {
		t.Fatal("fixture should not satisfy the predicate")
	}

	credSecret := Uint64Bytes(1)
	reg := testRegistry(t, CredentialLeaf(credSecret, attrs))
	st, err := BuildStatement(testRequest(), pol, 0, 128)
	if err != nil {
		t.Fatalf("BuildStatement: %v", err)
	}

	_, err = NewAssignment(st, pol, attrs, credSecret, reg)
	if !errors.Is(err, ErrPolicyNotSatisfied) {
		t.Fatalf("got %v, want ErrPolicyNotSatisfied", err)
	}
}

func TestOutOfScopeLocationIsRefusedBeforeProving(t *testing.T) {
	pol := testPolicy(t, "((sender OR receiver) AND validator)")
	attrs := [NumAttributes]uint64{
		AttrSender: 1, AttrReceiver: 1, AttrValidator: 1, AttrRole: RoleAdmin,
	}
	credSecret := Uint64Bytes(2)
	reg := testRegistry(t, CredentialLeaf(credSecret, attrs))

	st, err := BuildStatement(testRequest(), pol, 0, 100000)
	if err != nil {
		t.Fatalf("BuildStatement: %v", err)
	}
	if _, err := NewAssignment(st, pol, attrs, credSecret, reg); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("got %v, want ErrOutOfScope", err)
	}
}

// -----------------------------------------------------------------------------
// Privacy — the scheme's actual claim
// -----------------------------------------------------------------------------

// TestAttributesAreNotPublicInputs is the test that stops the scheme quietly
// ceasing to be privacy-preserving.
//
// Moving the attributes to public inputs would leave every functional test
// passing, make verification cheaper, and produce a full set of Exp 1 numbers
// for a scheme that no longer hides anything — the exact silent failure this
// project exists to prevent.
//
// Checked semantically rather than by counting: two DIFFERENT requesters, with
// different attributes and different credentials, proving the same statement
// must produce byte-identical public witnesses. If any part of the witness
// distinguishes them, it is public, and the proof leaks who proved it.
func TestAttributesAreNotPublicInputs(t *testing.T) {
	pol := testPolicy(t, "((sender OR receiver) AND validator)")

	// Two requesters that satisfy the same predicate by different routes.
	alice := [NumAttributes]uint64{
		AttrSender: 1, AttrReceiver: 0, AttrValidator: 1, AttrRole: RoleAdmin,
	}
	bob := [NumAttributes]uint64{
		AttrSender: 0, AttrReceiver: 1, AttrValidator: 1, AttrRole: RoleOperator,
	}
	if !pol.Satisfies(alice) || !pol.Satisfies(bob) {
		t.Fatal("both fixtures must satisfy the predicate")
	}
	if alice == bob {
		t.Fatal("the two fixtures must differ")
	}

	aliceSecret, bobSecret := Uint64Bytes(1111), Uint64Bytes(2222)
	reg, err := NewRegistry([][]byte{
		CredentialLeaf(aliceSecret, alice),
		CredentialLeaf(bobSecret, bob),
	}, testTreeDepth)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	st, err := BuildStatement(testRequest(), pol, 0, 128)
	if err != nil {
		t.Fatalf("BuildStatement: %v", err)
	}

	aAlice, err := NewAssignment(st, pol, alice, aliceSecret, reg)
	if err != nil {
		t.Fatalf("assignment for alice: %v", err)
	}
	aBob, err := NewAssignment(st, pol, bob, bobSecret, reg)
	if err != nil {
		t.Fatalf("assignment for bob: %v", err)
	}

	params := &Params{PredicateDepth: testPredicateDepth, TreeDepth: testTreeDepth}

	pubOf := func(a *Assignment) []byte {
		full, err := a.witness(params)
		if err != nil {
			t.Fatalf("witness: %v", err)
		}
		pub, err := full.Public()
		if err != nil {
			t.Fatalf("public witness: %v", err)
		}
		raw, err := pub.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal public witness: %v", err)
		}
		return raw
	}

	if !bytes.Equal(pubOf(aAlice), pubOf(aBob)) {
		t.Fatal("two requesters with different attributes produce different public " +
			"witnesses: something identifying is public, so the proof does not " +
			"hide who satisfied the policy. Every Exp 1 number would then be " +
			"measuring a scheme that is not privacy-preserving.")
	}

	// And the public witness is exactly the two values the design specifies.
	c := circuitFor(t)
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, c)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	got := ccs.GetNbPublicVariables() - oneWire
	const want = 2 // StatementDigest, RegistryRoot
	if got != want {
		t.Fatalf("circuit has %d public inputs, want %d (StatementDigest, RegistryRoot); "+
			"anything more means part of the witness became public", got, want)
	}
}

// -----------------------------------------------------------------------------
// Host and circuit must agree
// -----------------------------------------------------------------------------

// TestHostEvaluationMatchesCircuit checks Policy.Satisfies against the circuit
// over EVERY attribute assignment.
//
// Satisfies decides whether a proof is even attempted, so a disagreement would
// show up as requests denied that the circuit would have proved, or as solver
// failures on requests the host thought were fine.
func TestHostEvaluationMatchesCircuit(t *testing.T) {
	predicates := []string{
		"((sender OR receiver) AND validator)",
		"((sender AND role=admin) OR validator)",
		"((role=operator OR role=admin) AND sender)",
	}

	for _, pred := range predicates {
		pol := testPolicy(t, pred)
		for s := uint64(0); s <= 1; s++ {
			for r := uint64(0); r <= 1; r++ {
				for v := uint64(0); v <= 1; v++ {
					for role := uint64(RoleOperator); role <= RoleAdmin; role++ {
						attrs := [NumAttributes]uint64{
							AttrSender: s, AttrReceiver: r, AttrValidator: v, AttrRole: role,
						}
						host := pol.Satisfies(attrs)

						credSecret := Uint64Bytes(5)
						reg := testRegistry(t, CredentialLeaf(credSecret, attrs))
						st, err := BuildStatement(testRequest(), pol, 0, 128)
						if err != nil {
							t.Fatalf("BuildStatement: %v", err)
						}
						_, err = NewAssignment(st, pol, attrs, credSecret, reg)
						circuit := err == nil

						if host != circuit {
							t.Errorf("%s with s=%d r=%d v=%d role=%d: host says %v, assignment says %v",
								pred, s, r, v, role, host, circuit)
						}
					}
				}
			}
		}
	}
}

// TestTermSetMatchesWorkloadGenerator pins the term vocabulary against the one
// pkg/workload emits. A term the circuit cannot express would make some
// policies unprovable, and the denial would look like a policy decision.
func TestTermSetMatchesWorkloadGenerator(t *testing.T) {
	// The list in pkg/workload.buildPredicate.
	generated := []string{"sender", "receiver", "validator", "role=operator", "role=admin"}

	if len(termIndex) != len(generated) {
		t.Fatalf("circuit knows %d terms, the generator emits %d", len(termIndex), len(generated))
	}
	for _, term := range generated {
		if _, ok := termIndex[term]; !ok {
			t.Errorf("generator emits %q but the circuit cannot express it", term)
		}
	}
}

func TestParsePredicateHandlesTheGeneratedShape(t *testing.T) {
	cases := []struct {
		expr  string
		terms []uint64
		ops   []uint64
	}{
		{"sender", []uint64{TermSender}, nil},
		{"(sender AND validator)", []uint64{TermSender, TermValidator}, []uint64{OpAnd}},
		{"((sender OR receiver) AND validator)",
			[]uint64{TermSender, TermReceiver, TermValidator}, []uint64{OpOr, OpAnd}},
		{"((role=operator OR role=admin) OR sender)",
			[]uint64{TermRoleOperator, TermRoleAdmin, TermSender}, []uint64{OpOr, OpOr}},
	}

	for _, tc := range cases {
		terms, ops, err := parsePredicate(tc.expr)
		if err != nil {
			t.Errorf("%s: %v", tc.expr, err)
			continue
		}
		if fmt.Sprint(terms) != fmt.Sprint(tc.terms) {
			t.Errorf("%s: terms %v, want %v", tc.expr, terms, tc.terms)
		}
		if fmt.Sprint(ops) != fmt.Sprint(tc.ops) {
			t.Errorf("%s: ops %v, want %v", tc.expr, ops, tc.ops)
		}
	}
}

func TestParsePredicateRejectsUnknownTerms(t *testing.T) {
	if _, _, err := parsePredicate("(sender AND wizard)"); err == nil {
		t.Fatal("an unmodelled term was accepted; it would silently evaluate false")
	}
}

// -----------------------------------------------------------------------------
// Registry
// -----------------------------------------------------------------------------

func TestRegistryPathAuthenticatesEveryLeaf(t *testing.T) {
	var leaves [][]byte
	for i := 0; i < 8; i++ {
		leaves = append(leaves, Hash(Uint64Bytes(uint64(i))))
	}
	reg, err := NewRegistry(leaves, 3)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	for i, leaf := range leaves {
		path, bits, err := reg.Path(leaf)
		if err != nil {
			t.Fatalf("leaf %d: %v", i, err)
		}
		node := leaf
		for l := range path {
			if bits[l] == 1 {
				node = Hash(path[l], node)
			} else {
				node = Hash(node, path[l])
			}
		}
		if string(node) != string(reg.Root()) {
			t.Errorf("leaf %d does not authenticate to the root", i)
		}
	}
}

func TestRegistryRefusesOverfullTree(t *testing.T) {
	var leaves [][]byte
	for i := 0; i < 9; i++ {
		leaves = append(leaves, Hash(Uint64Bytes(uint64(i))))
	}
	if _, err := NewRegistry(leaves, 3); err == nil {
		t.Fatal("9 leaves were accepted into a depth-3 tree; the overflow would " +
			"drop credentials and read as unregistered requesters")
	}
}

func TestTreeDepthFor(t *testing.T) {
	for _, tc := range []struct{ n, want int }{
		{1, 1}, {2, 1}, {3, 2}, {8, 3}, {100, 7}, {128, 7}, {129, 8},
	} {
		if got := TreeDepthFor(tc.n); got != tc.want {
			t.Errorf("TreeDepthFor(%d) = %d, want %d", tc.n, got, tc.want)
		}
	}
}

// -----------------------------------------------------------------------------
// Statement binding
// -----------------------------------------------------------------------------

// TestDigestBindsEveryStatementField pins that eta_i actually binds x_i. A field
// left out of the hash could be changed after proving without invalidating the
// proof.
func TestDigestBindsEveryStatementField(t *testing.T) {
	base := func() *Statement {
		pol := testPolicy(t, "((sender OR receiver) AND validator)")
		st, err := BuildStatement(testRequest(), pol, 3, 128)
		if err != nil {
			t.Fatalf("BuildStatement: %v", err)
		}
		return st
	}

	mutations := map[string]func(*Statement){
		"TxID":             func(s *Statement) { s.TxID = FieldBytes([]byte("tx-00000004")) },
		"TxVersion":        func(s *Statement) { s.TxVersion++ },
		"Loc":              func(s *Statement) { s.Loc++ },
		"Mod":              func(s *Statement) { s.Mod = FieldBytes([]byte("other")) },
		"PolicyID":         func(s *Statement) { s.PolicyID = FieldBytes([]byte("pol-0001")) },
		"PolicyVersion":    func(s *Statement) { s.PolicyVersion++ },
		"Timestamp":        func(s *Statement) { s.Timestamp++ },
		"Nonce":            func(s *Statement) { s.Nonce = FieldBytes([]byte("nonce-2")) },
		"PolicyCommitment": func(s *Statement) { s.PolicyCommitment = Hash(Uint64Bytes(99)) },
	}

	original := string(base().Digest())
	for field, mutate := range mutations {
		st := base()
		mutate(st)
		if string(st.Digest()) == original {
			t.Errorf("changing %s does not change eta_i; it is not bound and could "+
				"be altered after proving", field)
		}
	}
}

func TestBuildStatementRefusesAPolicyMismatch(t *testing.T) {
	pol := testPolicy(t, "((sender OR receiver) AND validator)")
	pol.ID = "pol-9999"
	if _, err := BuildStatement(testRequest(), pol, 0, 0); err == nil {
		t.Fatal("a statement was built against a policy the request does not name")
	}
}
