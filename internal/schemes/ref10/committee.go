package ref10

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"math/rand"
	"sort"
	"strings"

	"zkredact/pkg/crypto"
	"zkredact/pkg/scheme"
)

// Committee selection and the attribute policy A_r (Ref[10] Algorithm 3, Eq. 7).
//
//	RS_SHA256( addr(con_k), N_all, A_r ) -> N_auth
//
// Two properties the fidelity checklist requires, and what enforces them here:
//
//   - Selection is genuinely hash-based over the FULL node set, not a fixed
//     list. selectCommittee ranks every eligible node by SHA-256 over the
//     contract address and takes the lowest. A fixed list would make committee
//     membership independent of the contract, and Exp 1's per-request cost
//     would stop including selection entirely.
//   - A_r is genuinely evaluated per requester. evalPolicy parses the
//     expression from config; it is not a constant true.
//
// Selection is per-contract, and each redaction request instantiates its own
// contract con_k (Ref[10].md:384). So this cost falls INSIDE Exp 1's
// measurement boundary and is paid per request, which is a real part of what
// makes this baseline's authorization more expensive than a trapdoor check.

// member is one authorized node holding a voting key.
type member struct {
	Identity scheme.Identity
	Key      *crypto.SchnorrPrivateKey
}

// registry holds every node in the network N_all with its voting key.
//
// Keys are derived from the run seed so a repeat run produces the same
// committee and the same signatures — reproducibility is a project rule, and a
// committee that differed between runs would make Exp 1 unrepeatable.
type registry struct {
	nodes []*member
	byID  map[string]*member
	curve elliptic.Curve
}

// lookup resolves a node's voting key.
//
// Algorithm 3 stores the public keys pk_j of the authorized committee in the
// contract con_k, so an auditor genuinely has this mapping available when
// re-verifying a stored Sigma.
func (r *registry) lookup(id string) (*member, bool) {
	m, ok := r.byID[id]
	return m, ok
}

func newRegistry(identities []scheme.Identity, curve elliptic.Curve, seed int64) (*registry, error) {
	if len(identities) == 0 {
		return nil, fmt.Errorf("ref10: dataset has no identities to form N_all")
	}
	r := &registry{
		nodes: make([]*member, 0, len(identities)),
		byID:  make(map[string]*member, len(identities)),
		curve: curve,
	}

	// A deterministic stream, distinct from the dataset's own streams, so key
	// material does not shift when unrelated dataset parameters change.
	src := rand.New(rand.NewSource(seed + 0x1010))
	for _, id := range identities {
		k, err := crypto.SchnorrKeyGen(curve, src)
		if err != nil {
			return nil, fmt.Errorf("ref10: voting key for %s: %w", id.ID, err)
		}
		m := &member{Identity: id, Key: k}
		r.nodes = append(r.nodes, m)
		r.byID[id.ID] = m
	}
	return r, nil
}

// eligible returns the nodes satisfying A_r.
func (r *registry) eligible(policy string) ([]*member, error) {
	out := make([]*member, 0, len(r.nodes))
	for _, n := range r.nodes {
		ok, err := evalPolicy(policy, n.Identity.Attributes)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, n)
		}
	}
	return out, nil
}

// selectCommittee implements RS_SHA256 (Eq. 7).
//
// Ranking is by SHA-256 over the contract address concatenated with the node
// ID, so a different contract yields a different committee from the same node
// set. Ties break on node ID, which cannot occur with distinct IDs but keeps
// the ordering total and therefore reproducible.
func (r *registry) selectCommittee(contractAddr string, policy string, size int) ([]*member, error) {
	pool, err := r.eligible(policy)
	if err != nil {
		return nil, err
	}
	if len(pool) < size {
		return nil, fmt.Errorf(
			"ref10: policy %q leaves %d eligible nodes, below committee_size=%d; "+
				"a committee smaller than its configured size would weaken the threshold "+
				"this baseline is measured under",
			policy, len(pool), size)
	}

	type ranked struct {
		m    *member
		rank [sha256.Size]byte
	}
	rs := make([]ranked, len(pool))
	for i, m := range pool {
		// H(addr || 0x1f || id). The separator is not decoration: without it
		// addr="a"+id="bc" and addr="ab"+id="c" hash identically, so two
		// different rounds could draw the same ranking.
		//
		// It must also match network/chaincode/redaction exactly. The contract
		// recomputes N_auth independently, and when the two orderings diverge
		// the peer rejects honest votes as "not on the committee" — which reads
		// as a membership bug rather than a hashing difference.
		// TestCommitteeSelectionMatchesChaincode pins the agreement.
		h := sha256.New()
		h.Write([]byte(contractAddr))
		h.Write([]byte{0x1f})
		h.Write([]byte(m.Identity.ID))
		var sum [sha256.Size]byte
		copy(sum[:], h.Sum(nil))
		rs[i] = ranked{m: m, rank: sum}
	}
	sort.Slice(rs, func(i, j int) bool {
		if c := bytes.Compare(rs[i].rank[:], rs[j].rank[:]); c != 0 {
			return c < 0
		}
		return rs[i].m.Identity.ID < rs[j].m.Identity.ID
	})

	out := make([]*member, size)
	for i := 0; i < size; i++ {
		out[i] = rs[i].m
	}
	return out, nil
}

// contractAddress derives addr(con_k) for a request.
//
// Each redaction request instantiates its own contract instance, so the address
// varies per request and the committee varies with it.
func contractAddress(requestID string) string {
	sum := sha256.Sum256([]byte("con_k|" + requestID))
	return fmt.Sprintf("%x", sum[:20])
}

// -----------------------------------------------------------------------------
// A_r evaluation
// -----------------------------------------------------------------------------

// attrTerms maps the paper's attribute symbols to dataset attribute names.
//
// Ref[10] writes A_r over {S, R, V} — sender, receiver, validator (§IV-C). The
// shared dataset carries exactly those as boolean attributes, so the mapping is
// direct and no attribute has to be invented for this baseline.
var attrTerms = map[string]string{
	"S": "sender",
	"R": "receiver",
	"V": "validator",
}

// evalPolicy evaluates an A_r expression against one identity's attributes.
//
// Supports the symbols S, R and V, the operators AND and OR, and parentheses —
// which covers the paper's stated default "S OR R OR V" and anything stricter a
// reviewer might ask for. Precedence is AND over OR, as usual.
//
// An unrecognised token is an ERROR, not false. A policy silently evaluating to
// false would empty the committee; a policy silently evaluating to true would
// remove the check that this baseline is supposed to perform. Both are the kind
// of quiet degradation this project is built to refuse.
func evalPolicy(expr string, attrs map[string]string) (bool, error) {
	toks, err := tokenizePolicy(expr)
	if err != nil {
		return false, err
	}
	p := &policyParser{toks: toks, attrs: attrs}
	v, err := p.parseOr()
	if err != nil {
		return false, err
	}
	if p.pos != len(p.toks) {
		return false, fmt.Errorf("ref10: trailing tokens in attribute policy %q", expr)
	}
	return v, nil
}

func tokenizePolicy(expr string) ([]string, error) {
	if strings.TrimSpace(expr) == "" {
		return nil, fmt.Errorf("ref10: attribute policy is empty")
	}
	spaced := strings.ReplaceAll(strings.ReplaceAll(expr, "(", " ( "), ")", " ) ")
	toks := strings.Fields(spaced)
	if len(toks) == 0 {
		return nil, fmt.Errorf("ref10: attribute policy %q has no tokens", expr)
	}
	return toks, nil
}

type policyParser struct {
	toks  []string
	pos   int
	attrs map[string]string
}

func (p *policyParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *policyParser) parseOr() (bool, error) {
	v, err := p.parseAnd()
	if err != nil {
		return false, err
	}
	for strings.EqualFold(p.peek(), "OR") {
		p.pos++
		rhs, err := p.parseAnd()
		if err != nil {
			return false, err
		}
		v = v || rhs
	}
	return v, nil
}

func (p *policyParser) parseAnd() (bool, error) {
	v, err := p.parseTerm()
	if err != nil {
		return false, err
	}
	for strings.EqualFold(p.peek(), "AND") {
		p.pos++
		rhs, err := p.parseTerm()
		if err != nil {
			return false, err
		}
		v = v && rhs
	}
	return v, nil
}

func (p *policyParser) parseTerm() (bool, error) {
	if p.pos >= len(p.toks) {
		return false, fmt.Errorf("ref10: attribute policy ended mid-expression")
	}
	tok := p.toks[p.pos]
	p.pos++

	if tok == "(" {
		v, err := p.parseOr()
		if err != nil {
			return false, err
		}
		if p.peek() != ")" {
			return false, fmt.Errorf("ref10: unclosed parenthesis in attribute policy")
		}
		p.pos++
		return v, nil
	}

	// key=value form, e.g. role=operator.
	if name, want, found := strings.Cut(tok, "="); found {
		return p.attrs[name] == want, nil
	}

	attr, ok := attrTerms[strings.ToUpper(tok)]
	if !ok {
		return false, fmt.Errorf(
			"ref10: unknown attribute term %q in policy; known symbols are S, R, V "+
				"(Ref[10] §IV-C) or an explicit key=value", tok)
	}
	return p.attrs[attr] == "true", nil
}
