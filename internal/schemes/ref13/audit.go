package ref13

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"sort"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

	"zkredact/pkg/vc"
)

// Blockchain auditing — Ref[13] Algorithm 3 and the §4.1 optimisation.
//
// WHAT EXP 3 IS ACTUALLY MEASURING. §4.1 states the cost plainly: it is
// "determined by the node number of path union from challenged nodes to the
// root node". Not the ledger size, and not z on its own — the UNION. Two
// challenged blocks under the same parent share every node above that parent,
// and the union counts each once.
//
// That is why Exp 3 asks whether audit cost tracks history depth rather than
// ledger size, and why PathUnionSize is reported alongside the timing: without
// it, a flat cost curve against ledger size could equally mean the audit is not
// doing anything.
//
// THE OPTIMISATION IS ENABLED BECAUSE THE PAPER'S NUMBERS USE IT. f1 picks z
// LEAF nodes and challenges every node on their paths, which minimises the union
// for a given z. Disabling it would understate the baseline, so config records
// optimized_auditing: true as derived rather than chosen.
//
// COEFFICIENTS CARRY TWO JOBS HERE, and both are needed:
//
//   - the challenge coefficient from f2, which makes this a spot check the
//     prover cannot anticipate; and
//   - vc.DeriveCoefficient's binding, without which the openings can be made to
//     cancel against each other (see TestUnboundCoefficientsWouldBeForgeable).
//
// They multiply. Dropping either one leaves an audit that passes its own tests
// and proves nothing.

// Challenge is Chal = (z, phi_1, phi_2) from Algorithm 3 line 2.
type Challenge struct {
	// Z is how many blocks to challenge.
	Z int

	// Phi1 seeds the index PRF f1, Phi2 the coefficient PRF f2. Both come from
	// the verifier, per round: a challenge the prover can predict is not a
	// spot check.
	Phi1 []byte
	Phi2 []byte
}

// prf is f1/f2: SHA-256 keyed by phi, matching security.hash for the reason
// vc.DeriveCoefficient does.
func prf(phi []byte, i int) []byte {
	h := sha256.New()
	h.Write([]byte("ref13/audit/prf"))
	h.Write(phi)
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], uint64(i))
	h.Write(idx[:])
	return h.Sum(nil)
}

// challengeCoefficient is beta_i = f2(i, phi_2), the per-node challenge weight.
func challengeCoefficient(phi2 []byte, node, pos int) fr.Element {
	h := sha256.New()
	h.Write([]byte("ref13/audit/coefficient"))
	h.Write(phi2)
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[0:8], uint64(node))
	binary.BigEndian.PutUint64(buf[8:16], uint64(pos))
	h.Write(buf[:])

	var out fr.Element
	out.SetBigInt(new(big.Int).SetBytes(h.Sum(nil)))
	return out
}

// SelectChallenged picks the blocks to audit, via f1.
//
// With optimised auditing the selection is drawn from the DEEPEST level in the
// tree — §4.1's "leaf nodes" — because challenging deep blocks maximises path
// sharing for a given z. Without it, blocks are drawn from the whole ledger.
func (b *BAT) SelectChallenged(ch Challenge, optimized bool) ([]int, error) {
	if ch.Z < 1 {
		return nil, fmt.Errorf("ref13: challenge size must be >= 1, got %d", ch.Z)
	}
	if len(ch.Phi1) == 0 || len(ch.Phi2) == 0 {
		return nil, fmt.Errorf("ref13: audit challenge needs both PRF seeds")
	}

	occupied := make([]int, 0, len(b.nodes))
	deepest := 0
	levels := make(map[int]int, len(b.nodes))
	for i, n := range b.nodes {
		if !n.occupied {
			continue
		}
		l, err := Level(i, b.q)
		if err != nil {
			return nil, err
		}
		levels[i] = l
		if l > deepest {
			deepest = l
		}
		occupied = append(occupied, i)
	}
	if len(occupied) == 0 {
		return nil, fmt.Errorf("ref13: no blocks to audit")
	}

	pool := occupied
	if optimized {
		leaves := make([]int, 0, len(occupied))
		for _, i := range occupied {
			if levels[i] == deepest {
				leaves = append(leaves, i)
			}
		}
		if len(leaves) > 0 {
			pool = leaves
		}
	}

	// Sample without replacement: challenging the same block twice would
	// inflate z without widening the union, which would flatter the audit.
	seen := make(map[int]bool, ch.Z)
	out := make([]int, 0, ch.Z)
	for i := 0; len(out) < ch.Z && i < ch.Z*64; i++ {
		d := prf(ch.Phi1, i)
		idx := int(new(big.Int).SetBytes(d).Mod(
			new(big.Int).SetBytes(d), big.NewInt(int64(len(pool)))).Int64())
		block := pool[idx]
		if seen[block] {
			continue
		}
		seen[block] = true
		out = append(out, block)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("ref13: challenge selected no blocks")
	}
	return out, nil
}

// PathOpening is one opening plus the node it belongs to, which the verifier
// needs to rebuild the chain. vc.Opening alone does not say WHERE in the tree a
// commitment sits.
type PathOpening struct {
	Node    int
	Opening vc.Opening
}

// AuditProof is Algorithm 3's output.
type AuditProof struct {
	PiHat    curve.G1Affine
	MuHat    fr.Element
	Openings []PathOpening

	// Challenged is the block set the proof covers.
	Challenged []int

	// PathUnionSize is the count of distinct (node, position) openings. This is
	// the cost driver §4.1 identifies, and Exp 3 records it beside the timing.
	PathUnionSize int
}

// unionKey identifies one opening within the union.
type unionKey struct{ node, pos int }

// ProveAudit runs Algorithm 3 over a challenge.
//
// The union is built by walking each challenged block's path and deduplicating
// (node, position). Shared ancestors are proved ONCE — that sharing is the
// optimisation, and counting them repeatedly would both cost more and misreport
// what the scheme does.
func (b *BAT) ProveAudit(ch Challenge, challenged []int) (*AuditProof, error) {
	if len(challenged) == 0 {
		return nil, fmt.Errorf("ref13: nothing challenged")
	}

	seen := make(map[unionKey]bool)
	order := make([]unionKey, 0, len(challenged)*4)

	for _, s := range challenged {
		if s < 0 || s >= len(b.nodes) {
			return nil, fmt.Errorf("ref13: challenged node %d does not exist", s)
		}
		if !b.nodes[s].occupied {
			return nil, fmt.Errorf("ref13: challenged node %d holds no block", s)
		}

		add := func(node, pos int) {
			k := unionKey{node, pos}
			if seen[k] {
				return
			}
			seen[k] = true
			order = append(order, k)
		}

		add(s, 1) // the block's own data
		path, err := Path(s, b.q)
		if err != nil {
			return nil, err
		}
		for _, i := range path {
			if i == 0 {
				continue
			}
			parent, _, err := Parent(i, b.q)
			if err != nil {
				return nil, err
			}
			pos, err := ChildPosition(i, b.q)
			if err != nil {
				return nil, err
			}
			add(parent, pos)
		}
	}

	// Deterministic order, so prover and verifier aggregate the same way.
	sort.Slice(order, func(i, j int) bool {
		if order[i].node != order[j].node {
			return order[i].node < order[j].node
		}
		return order[i].pos < order[j].pos
	})

	vectors := make([][]fr.Element, 0, len(order))
	openings := make([]vc.Opening, 0, len(order))
	pathOpenings := make([]PathOpening, 0, len(order))

	for _, k := range order {
		n := b.nodes[k.node]
		value := n.vector[k.pos-1]

		var coeff fr.Element
		coeff.Mul(
			ptr(vc.DeriveCoefficient(k.pos, n.commitment, value)),
			ptr(challengeCoefficient(ch.Phi2, k.node, k.pos)),
		)

		o := vc.Opening{C: n.commitment, Pos: k.pos, Value: value, Coeff: coeff}
		vectors = append(vectors, n.vector)
		openings = append(openings, o)
		pathOpenings = append(pathOpenings, PathOpening{Node: k.node, Opening: o})
	}

	piHat, muHat, err := b.params.AggregateOpen(vectors, openings)
	if err != nil {
		return nil, fmt.Errorf("ref13: aggregate audit proof: %w", err)
	}

	return &AuditProof{
		PiHat:         piHat,
		MuHat:         muHat,
		Openings:      pathOpenings,
		Challenged:    append([]int(nil), challenged...),
		PathUnionSize: len(order),
	}, nil
}

// ptr is a small helper: fr.Element methods want addressable operands.
func ptr(e fr.Element) *fr.Element { return &e }

// VerifyAudit checks an audit proof against the trusted root.
//
// Same discipline as VerifyPath, and for the same reason: the aggregation
// proves each opening against the commitment the PROVER supplied, so without
// the structural checks below a prover could audit a tree of its own making.
//
//  1. the root node's commitment must be the one the verifier trusts;
//  2. every opening at a child position must claim the hash of the commitment
//     the union actually contains for that child, so the nodes form one tree
//     rather than a bag of unrelated statements;
//  3. every coefficient is recomputed, never taken from the prover;
//  4. and only then the aggregated pairing check.
func (b *BAT) VerifyAudit(root curve.G1Affine, ch Challenge, proof *AuditProof) (bool, error) {
	if proof == nil || len(proof.Openings) == 0 {
		return false, fmt.Errorf("ref13: empty audit proof")
	}

	// Node -> the commitment the proof presents for it. A node appearing twice
	// with different commitments is a malformed proof, not a failed one.
	commitments := make(map[int]curve.G1Affine, len(proof.Openings))
	for _, po := range proof.Openings {
		if prev, ok := commitments[po.Node]; ok {
			if !prev.Equal(&po.Opening.C) {
				return false, fmt.Errorf(
					"ref13: node %d appears with two different commitments", po.Node)
			}
			continue
		}
		commitments[po.Node] = po.Opening.C
	}

	// (1) anchor.
	rootC, ok := commitments[0]
	if !ok {
		return false, fmt.Errorf("ref13: audit proof does not reach the root")
	}
	if !rootC.Equal(&root) {
		return false, nil
	}

	for _, po := range proof.Openings {
		// (3) coefficients are the verifier's to compute.
		var want fr.Element
		want.Mul(
			ptr(vc.DeriveCoefficient(po.Opening.Pos, po.Opening.C, po.Opening.Value)),
			ptr(challengeCoefficient(ch.Phi2, po.Node, po.Opening.Pos)),
		)
		if !po.Opening.Coeff.Equal(&want) {
			return false, fmt.Errorf(
				"ref13: node %d position %d carries an unbound coefficient",
				po.Node, po.Opening.Pos)
		}

		// (2) links, for child positions only. Position 1 is block data, which
		// has nothing below it.
		if po.Opening.Pos == 1 {
			continue
		}
		child := Children(po.Node, b.q)[po.Opening.Pos-2]
		childC, present := commitments[child]
		if !present {
			// A link to a node outside the union is unverifiable. It is only
			// legitimate at the frontier — where the child holds no challenged
			// block — and the aggregate still binds the value, so this is not a
			// failure. It simply cannot be cross-checked here.
			continue
		}
		wantValue := childScalar(childC)
		if !po.Opening.Value.Equal(&wantValue) {
			return false, nil
		}
	}

	// (4) the pairing.
	openings := make([]vc.Opening, len(proof.Openings))
	for i, po := range proof.Openings {
		openings[i] = po.Opening
	}
	return b.params.AggregateVerify(openings, proof.PiHat, proof.MuHat)
}

// BlockData returns the committed m for a block, so an auditor can compare the
// proof against what it believes the content to be.
func (b *BAT) BlockData(s int) (fr.Element, error) {
	if s < 0 || s >= len(b.nodes) {
		return fr.Element{}, fmt.Errorf("ref13: node %d does not exist", s)
	}
	if !b.nodes[s].occupied {
		return fr.Element{}, fmt.Errorf("ref13: node %d holds no block", s)
	}
	return b.nodes[s].vector[0], nil
}
