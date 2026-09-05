package zk

import (
	"fmt"
	"strconv"
	"strings"

	"zkredact/pkg/scheme"
)

// Policy is a dataset predicate compiled into the form the circuit evaluates.
//
// pkg/workload emits predicates as left-nested strings over a fixed term set,
// e.g. "((sender OR role=admin) AND validator)". The circuit cannot parse
// strings, so this is where the translation happens — once, outside the
// measured path, because parsing inside Authorize would charge ZK-Redact for
// work its design does not include.
type Policy struct {
	ID       string
	Version  uint64
	Terms    []uint64
	Ops      []uint64
	ScopeLow uint64
	// ScopeHigh bounds the redactable region. The dataset does not carry one,
	// so callers supply the payload size; see CompilePolicy.
	ScopeHigh uint64
	Scope     uint64
	Validity  uint64
}

// Commitment is C_P = H(PID ‖ terms ‖ ops ‖ scope ‖ validity), computed the
// same way the circuit recomputes it.
func (p *Policy) Commitment() []byte {
	in := make([][]byte, 0, len(p.Terms)+len(p.Ops)+5)
	in = append(in, FieldBytes([]byte(p.ID)))
	for _, t := range p.Terms {
		in = append(in, Uint64Bytes(t))
	}
	for _, o := range p.Ops {
		in = append(in, Uint64Bytes(o))
	}
	in = append(in,
		Uint64Bytes(p.ScopeLow),
		Uint64Bytes(p.ScopeHigh),
		Uint64Bytes(p.Scope),
		Uint64Bytes(p.Validity),
	)
	return Hash(in...)
}

// termIndex maps pkg/workload's term strings onto the circuit's term constants.
//
// Kept as one table so the two cannot drift silently: an unrecognised term is
// an error, not a term that quietly evaluates false. A false-by-default term
// would make some policies unsatisfiable and the resulting denials would look
// like policy decisions.
var termIndex = map[string]uint64{
	"sender":        TermSender,
	"receiver":      TermReceiver,
	"validator":     TermValidator,
	"role=operator": TermRoleOperator,
	"role=admin":    TermRoleAdmin,
}

// CompilePolicy parses one dataset predicate into circuit form.
//
// scopeHigh is the upper bound of the redactable region — the redactable
// payload size from config. It is a parameter rather than a constant because
// the payload size is configured, and a hardcoded bound here would silently
// reject valid locations on a differently sized corpus.
func CompilePolicy(p scheme.Policy, expectedDepth int, scopeHigh uint64) (*Policy, error) {
	terms, ops, err := parsePredicate(p.Predicate)
	if err != nil {
		return nil, fmt.Errorf("zk: policy %s: %w", p.ID, err)
	}
	if len(terms) != expectedDepth {
		return nil, fmt.Errorf(
			"zk: policy %s has %d terms but the circuit was compiled for %d; "+
				"dataset.policies.predicate_depth and the compiled circuit must agree",
			p.ID, len(terms), expectedDepth)
	}
	return &Policy{
		ID:        p.ID,
		Version:   p.Version,
		Terms:     terms,
		Ops:       ops,
		ScopeLow:  0,
		ScopeHigh: scopeHigh,
		Scope:     scopeHigh,
		Validity:  p.Version,
	}, nil
}

// parsePredicate reads the left-nested form pkg/workload.buildPredicate emits.
//
// Grammar, by construction of the generator:
//
//	depth 1:  term
//	depth n:  "(" <depth n-1> " " OP " " term ")"
//
// Parsed by stripping one layer of parentheses at a time from the outside,
// which is exactly the shape the generator builds and nothing more. A general
// boolean parser would accept expressions the circuit cannot evaluate.
func parsePredicate(expr string) (terms []uint64, ops []uint64, err error) {
	e := strings.TrimSpace(expr)

	// Peel from the outside: each layer contributes its trailing term and
	// operator, so collect them and reverse at the end.
	var revTerms, revOps []uint64
	for {
		if !strings.HasPrefix(e, "(") {
			idx, ok := termIndex[e]
			if !ok {
				return nil, nil, fmt.Errorf("unknown predicate term %q", e)
			}
			revTerms = append(revTerms, idx)
			break
		}
		if !strings.HasSuffix(e, ")") {
			return nil, nil, fmt.Errorf("unbalanced predicate %q", expr)
		}
		inner := e[1 : len(e)-1]

		// The last " AND " / " OR " at depth 0 splits the left-nested body from
		// its trailing term.
		leftEnd, rightStart, op, err := splitLast(inner)
		if err != nil {
			return nil, nil, fmt.Errorf("in %q: %w", expr, err)
		}
		right := strings.TrimSpace(inner[rightStart:])
		idx, ok := termIndex[right]
		if !ok {
			return nil, nil, fmt.Errorf("unknown predicate term %q", right)
		}
		revTerms = append(revTerms, idx)
		revOps = append(revOps, op)
		e = strings.TrimSpace(inner[:leftEnd])
	}

	terms = make([]uint64, len(revTerms))
	for i, t := range revTerms {
		terms[len(revTerms)-1-i] = t
	}
	ops = make([]uint64, len(revOps))
	for i, o := range revOps {
		ops[len(revOps)-1-i] = o
	}
	return terms, ops, nil
}

// splitLast finds the final top-level operator in a predicate body.
//
// Returns where the left operand ENDS and where the right operand BEGINS. Two
// indices, not one: the operator sits between them, and returning a single cut
// leaves the operator glued to whichever side it is measured from — which
// parses as a term named "sender AND".
func splitLast(s string) (leftEnd, rightStart int, op uint64, err error) {
	depth := 0
	leftEnd = -1
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
		case ' ':
			if depth != 0 {
				continue
			}
			if strings.HasPrefix(s[i:], " AND ") {
				leftEnd, rightStart, op = i, i+len(" AND "), OpAnd
			} else if strings.HasPrefix(s[i:], " OR ") {
				leftEnd, rightStart, op = i, i+len(" OR "), OpOr
			}
		}
	}
	if leftEnd < 0 {
		return 0, 0, 0, fmt.Errorf("no top-level operator in %q", s)
	}
	return leftEnd, rightStart, op, nil
}

// CompileAttributes converts a dataset identity's attributes into the circuit's
// fixed slots.
//
// An attribute the circuit does not model is an error rather than a default:
// silently defaulting an unknown role to operator would change which policies
// the identity satisfies, and the resulting approval rate would look like a
// property of the workload.
func CompileAttributes(id scheme.Identity) ([NumAttributes]uint64, error) {
	var out [NumAttributes]uint64

	boolAt := func(key string) (uint64, error) {
		v, ok := id.Attributes[key]
		if !ok {
			return 0, fmt.Errorf("identity %s has no %q attribute", id.ID, key)
		}
		b, err := strconv.ParseBool(v)
		if err != nil {
			return 0, fmt.Errorf("identity %s: %q = %q is not a boolean", id.ID, key, v)
		}
		if b {
			return 1, nil
		}
		return 0, nil
	}

	var err error
	if out[AttrSender], err = boolAt("sender"); err != nil {
		return out, err
	}
	if out[AttrReceiver], err = boolAt("receiver"); err != nil {
		return out, err
	}
	if out[AttrValidator], err = boolAt("validator"); err != nil {
		return out, err
	}

	role, ok := id.Attributes["role"]
	if !ok {
		return out, fmt.Errorf("identity %s has no \"role\" attribute", id.ID)
	}
	switch role {
	case "operator":
		out[AttrRole] = RoleOperator
	case "auditor":
		out[AttrRole] = RoleAuditor
	case "admin":
		out[AttrRole] = RoleAdmin
	default:
		return out, fmt.Errorf("identity %s has unmodelled role %q", id.ID, role)
	}
	return out, nil
}

// Satisfies evaluates the compiled policy outside the circuit.
//
// Used to decide whether a request is provable BEFORE proving it: a prover
// cannot produce a proof for an unsatisfied policy, and attempting it would
// surface as a constraint failure rather than as a denial. It must agree
// exactly with the circuit — TestHostEvaluationMatchesCircuit checks that over
// every attribute assignment.
func (p *Policy) Satisfies(attrs [NumAttributes]uint64) bool {
	term := func(idx uint64) bool {
		switch idx {
		case TermSender:
			return attrs[AttrSender] == 1
		case TermReceiver:
			return attrs[AttrReceiver] == 1
		case TermValidator:
			return attrs[AttrValidator] == 1
		case TermRoleOperator:
			return attrs[AttrRole] == RoleOperator
		case TermRoleAdmin:
			return attrs[AttrRole] == RoleAdmin
		}
		return false
	}

	acc := term(p.Terms[0])
	for i := 1; i < len(p.Terms); i++ {
		if p.Ops[i-1] == OpOr {
			acc = acc || term(p.Terms[i])
		} else {
			acc = acc && term(p.Terms[i])
		}
	}
	return acc
}

// ParsePredicateArity reports how many terms and operators a predicate uses,
// without compiling it.
//
// Used to derive the circuit's shape from the dataset rather than from a
// configured constant: the circuit is compiled for one arity, and a corpus
// carrying a different one would produce policies that could never be proved.
func ParsePredicateArity(expr string) (terms, ops int, err error) {
	t, o, err := parsePredicate(expr)
	if err != nil {
		return 0, 0, err
	}
	return len(t), len(o), nil
}
