package zk

import (
	"fmt"

	"zkredact/pkg/scheme"
)

// Statement is the manuscript's x_i, in the form both host and circuit use.
type Statement struct {
	TxID          []byte
	TxVersion     uint64
	Loc           uint64
	Mod           []byte
	PolicyID      []byte
	PolicyVersion uint64
	Timestamp     uint64
	Nonce         []byte

	// PolicyCommitment is C_P, part of x_i.
	PolicyCommitment []byte
}

// Digest is eta_i = H(x_i), the single public value binding the request.
//
// Field order here MUST match the circuit's stmtHasher writes. A reordering
// would make every proof fail as unsatisfiable, which reads as a broken circuit
// rather than as a mismatched encoding — so the two are written to be read side
// by side.
func (s *Statement) Digest() []byte {
	return Hash(
		s.TxID,
		Uint64Bytes(s.TxVersion),
		Uint64Bytes(s.Loc),
		s.Mod,
		s.PolicyID,
		Uint64Bytes(s.PolicyVersion),
		s.PolicyCommitment,
		Uint64Bytes(s.Timestamp),
		s.Nonce,
	)
}

// BuildStatement assembles x_i from a request and its policy.
//
// loc is the redaction location within the redactable payload. It is bound into
// the statement and range-checked in-circuit against the policy scope, which is
// the manuscript's "(Loc_i, M_i) is within the permitted scope".
func BuildStatement(req *scheme.Request, pol *Policy, txVersion, loc uint64) (*Statement, error) {
	if req == nil {
		return nil, fmt.Errorf("zk: nil request")
	}
	if pol == nil {
		return nil, fmt.Errorf("zk: nil policy")
	}
	if req.PolicyID != pol.ID {
		return nil, fmt.Errorf("zk: request names policy %s but %s was supplied",
			req.PolicyID, pol.ID)
	}
	return &Statement{
		TxID:             FieldBytes([]byte(req.TargetTxID)),
		TxVersion:        txVersion,
		Loc:              loc,
		Mod:              FieldBytes(req.NewContent),
		PolicyID:         FieldBytes([]byte(pol.ID)),
		PolicyVersion:    pol.Version,
		Timestamp:        uint64(req.Timestamp.UnixNano()),
		Nonce:            FieldBytes(req.Nonce),
		PolicyCommitment: pol.Commitment(),
	}, nil
}

// NewAssignment binds a statement, a credential and a policy into a provable
// instance.
//
// It refuses an unsatisfied policy rather than attempting the proof. A prover
// cannot produce a proof for attributes that do not satisfy the predicate, and
// letting it try would surface the denial as a constraint-solver failure —
// indistinguishable, in a run, from a broken circuit.
func NewAssignment(
	st *Statement,
	pol *Policy,
	attrs [NumAttributes]uint64,
	credSecret []byte,
	reg *Registry,
) (*Assignment, error) {

	if !pol.Satisfies(attrs) {
		return nil, fmt.Errorf("zk: %w", ErrPolicyNotSatisfied)
	}
	if st.Loc < pol.ScopeLow || st.Loc > pol.ScopeHigh {
		return nil, fmt.Errorf("zk: %w: location %d outside [%d, %d]",
			ErrOutOfScope, st.Loc, pol.ScopeLow, pol.ScopeHigh)
	}

	leaf := CredentialLeaf(credSecret, attrs)
	path, bits, err := reg.Path(leaf)
	if err != nil {
		return nil, fmt.Errorf("zk: %w", err)
	}

	return &Assignment{
		StatementDigest: st.Digest(),
		RegistryRoot:    reg.Root(),

		TxID:          st.TxID,
		TxVersion:     st.TxVersion,
		Loc:           st.Loc,
		Mod:           st.Mod,
		PolicyID:      st.PolicyID,
		PolicyVersion: st.PolicyVersion,
		Timestamp:     st.Timestamp,
		Nonce:         st.Nonce,

		Attributes:   attrs,
		CredSecret:   credSecret,
		PathElements: path,
		PathBits:     bits,

		PolicyTerms:    pol.Terms,
		PolicyOps:      pol.Ops,
		PolicyScope:    pol.Scope,
		PolicyValidity: pol.Validity,
		ScopeLow:       pol.ScopeLow,
		ScopeHigh:      pol.ScopeHigh,
	}, nil
}
