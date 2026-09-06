package ref13

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

	"zkredact/pkg/vc"
)

// The blockchain authentication tree — Ref[13] §2.2 and §3.2.2.
//
// SHAPE. A q-ary tree over block indices, root at 0, node i's children at
// qi+1 … qi+q. Each node commits to a vector of length N = q+1:
//
//	v_i = (m_i, C_{a_2}, …, C_{a_{q+1}})
//
// position 1 holding the block's own Merkle root and positions 2…q+1 holding
// its children's commitments (Eq. 6). That is where N = q+1 comes from, and why
// config records it as derived rather than independent.
//
// WHAT THE TREE BUYS. A redaction changes m_s, so C_s changes, so every
// commitment from s to the root changes — Algorithm 1. A verifier who trusts
// only the root commitment can then be convinced of any block's content by one
// aggregated opening along that path (Algorithm 2), which is Eq. 11 and the
// property Exp 3 measures.
//
// ---------------------------------------------------------------------------
// AN UNDER-SPECIFICATION IN THE PAPER, AND HOW IT IS RESOLVED
// ---------------------------------------------------------------------------
//
// Eq. 6 writes `C_i = g1^{gamma_i + m_i a + C_{a_2} a^2 + … }`, putting the
// child COMMITMENTS — group elements — in scalar position. A G1 point cannot be
// an exponent, so the equation cannot be read literally.
//
// `childScalar` resolves it by hashing the child commitment into the scalar
// field. The alternative reading is that the vector holds the trapdoors
// `kappa_{a_j} = H2(x || a_j)` rather than the commitments `C_{a_j} =
// g1^{kappa_{a_j}}` — but that cannot be right either, because Algorithm 1
// line 7 propagates `(C' - C_i)` (a difference of COMMITMENTS) through the same
// position during redaction. Only the hashing reading makes both equations
// consistent.
//
// This matters for fidelity, not for cost: either reading commits to one field
// element per child, so the commitment, the opening and the path update all cost
// exactly the same. Recorded in docs/baselines/ref13-vrbc.md.
//
// ---------------------------------------------------------------------------

// Level returns the depth of node s, with the root at 0.
func Level(s, q int) (int, error) {
	if q < 2 {
		return 0, fmt.Errorf("ref13: arity q must be >= 2, got %d", q)
	}
	if s < 0 {
		return 0, fmt.Errorf("ref13: node index must be >= 0, got %d", s)
	}
	level := 0
	for s > 0 {
		s = (s - 1) / q
		level++
	}
	return level, nil
}

// Parent returns node s's parent. The root is its own parent, reported by ok.
func Parent(s, q int) (parent int, isRoot bool, err error) {
	if q < 2 {
		return 0, false, fmt.Errorf("ref13: arity q must be >= 2, got %d", q)
	}
	if s < 0 {
		return 0, false, fmt.Errorf("ref13: node index must be >= 0, got %d", s)
	}
	if s == 0 {
		return 0, true, nil
	}
	return (s - 1) / q, false, nil
}

// ChildPosition is #Child(i, q): which slot of its parent's vector node i
// occupies.
//
// Positions are 1-indexed to match the paper, and children start at 2 because
// position 1 always holds the node's own m_i.
func ChildPosition(i, q int) (int, error) {
	if q < 2 {
		return 0, fmt.Errorf("ref13: arity q must be >= 2, got %d", q)
	}
	if i < 1 {
		return 0, fmt.Errorf("ref13: the root has no parent, so no child position")
	}
	return (i-1)%q + 2, nil
}

// Children returns node i's child indices, in vector-position order.
func Children(i, q int) []int {
	out := make([]int, q)
	for c := 0; c < q; c++ {
		out[c] = q*i + c + 1
	}
	return out
}

// Path returns Path(s, q): s, then each ancestor, ending at the root.
//
// Algorithm 2 walks this to build the aggregate, and Algorithm 1 walks it in
// the same order to update commitments after a redaction.
func Path(s, q int) ([]int, error) {
	if q < 2 {
		return nil, fmt.Errorf("ref13: arity q must be >= 2, got %d", q)
	}
	if s < 0 {
		return nil, fmt.Errorf("ref13: node index must be >= 0, got %d", s)
	}
	path := []int{s}
	for s > 0 {
		s = (s - 1) / q
		path = append(path, s)
	}
	return path, nil
}

// childScalar maps a child commitment into the scalar field, resolving the
// under-specification described above. Domain-separated so it can never collide
// with vc.DeriveCoefficient, which hashes overlapping inputs.
func childScalar(c curve.G1Affine) fr.Element {
	h := sha256.New()
	h.Write([]byte("ref13/bat/child"))
	cb := c.Bytes()
	h.Write(cb[:])
	sum := h.Sum(nil)

	var out fr.Element
	out.SetBigInt(new(big.Int).SetBytes(sum))
	return out
}

// placeholderScalar is kappa_{a_j} = H2(x || a_j): the value a node commits to
// for a child that does not exist yet.
//
// The paper derives these from the master secret so a node can be committed
// before its children are appended — which is the whole point of the
// "verification value" and of appending without rebuilding the tree.
func placeholderScalar(secret []byte, index int) fr.Element {
	h := sha256.New()
	h.Write([]byte("ref13/bat/placeholder"))
	h.Write(secret)

	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], uint64(index))
	h.Write(idx[:])
	sum := h.Sum(nil)

	var out fr.Element
	out.SetBigInt(new(big.Int).SetBytes(sum))
	return out
}

// node is one BAT node: the vector it commits to, and that commitment.
type node struct {
	// vector is v_i, length N = q+1. Position 0 (paper position 1) is m_i;
	// the rest are child commitments, or placeholders until a child exists.
	vector []fr.Element

	// commitment is C_i over vector.
	commitment curve.G1Affine

	// occupied reports whether a real block has been bound here. An unoccupied
	// node still has a commitment, over placeholders.
	occupied bool
}

// BAT is the tree.
type BAT struct {
	q      int
	params *vc.Params
	secret []byte

	// nodes is indexed by block index. Sparse growth: appending block i
	// materialises every node up to i, since a q-ary tree by index has no gaps.
	nodes []*node
}

// NewBAT builds a tree with the genesis node in place (Eq. 4).
func NewBAT(q int, params *vc.Params, secret []byte) (*BAT, error) {
	if q < 2 {
		return nil, fmt.Errorf("ref13: arity q must be >= 2, got %d", q)
	}
	if params == nil {
		return nil, fmt.Errorf("ref13: BAT needs vector commitment parameters")
	}
	if params.N != q+1 {
		// N = q+1 is derived, not independent. A mismatch means the config and
		// the tree disagree about how many children a node has, and every
		// commitment would be over the wrong width.
		return nil, fmt.Errorf(
			"ref13: vector dimension N=%d but arity q=%d requires N=q+1=%d",
			params.N, q, q+1)
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("ref13: BAT needs a master secret for child placeholders")
	}

	b := &BAT{q: q, params: params, secret: append([]byte(nil), secret...)}
	if _, err := b.ensure(0); err != nil {
		return nil, err
	}
	return b, nil
}

// ensure materialises node i, and every node before it, with placeholder
// children and a zero m_i until a block is bound.
func (b *BAT) ensure(i int) (*node, error) {
	for len(b.nodes) <= i {
		idx := len(b.nodes)
		n := &node{vector: make([]fr.Element, b.params.N)}

		// Position 1 (index 0) is m_i, zero until bound. Positions 2…q+1 are
		// the children's placeholders.
		for c, child := range Children(idx, b.q) {
			n.vector[c+1] = placeholderScalar(b.secret, child)
		}

		c, err := b.params.Commit(n.vector)
		if err != nil {
			return nil, fmt.Errorf("ref13: commit node %d: %w", idx, err)
		}
		n.commitment = c
		b.nodes = append(b.nodes, n)

		// A newly materialised node changes its parent's vector, so the parent
		// must be refreshed — except for the root, which has no parent.
		if idx > 0 {
			if err := b.refreshPath(idx); err != nil {
				return nil, err
			}
		}
	}
	return b.nodes[i], nil
}

// Bind sets node s's block data and updates every commitment from s to the
// root. This is Commitment binding (§3.2.2) on append, and Algorithm 1's
// Update.Com on redaction — the same walk either way, which is why one function
// serves both.
func (b *BAT) Bind(s int, m fr.Element) error {
	n, err := b.ensure(s)
	if err != nil {
		return err
	}
	n.vector[0] = m
	n.occupied = true

	c, err := b.params.Commit(n.vector)
	if err != nil {
		return fmt.Errorf("ref13: commit node %d: %w", s, err)
	}
	n.commitment = c

	return b.refreshPath(s)
}

// refreshPath re-commits every ancestor of s, in order, so each parent's vector
// holds its child's current commitment. Algorithm 1 lines 3-11.
//
// The paper updates incrementally — C'_b = C_b · g1^{(C'-C_i) a^c} — which is
// one exponentiation per level. Recommitting is one MSM of width N=q+1 per
// level instead. At q <= 10 the two are within a small constant of each other,
// and recommitting cannot drift out of step with the vector it is supposed to
// commit to. The COST DIFFERENCE IS REAL AND FAVOURS THE PAPER, so it is
// recorded as a deviation rather than glossed.
func (b *BAT) refreshPath(s int) error {
	for i := s; i > 0; {
		parent, isRoot, err := Parent(i, b.q)
		if err != nil {
			return err
		}
		if isRoot {
			break
		}
		pos, err := ChildPosition(i, b.q)
		if err != nil {
			return err
		}

		pn, err := b.ensure(parent)
		if err != nil {
			return err
		}
		pn.vector[pos-1] = childScalar(b.nodes[i].commitment)

		c, err := b.params.Commit(pn.vector)
		if err != nil {
			return fmt.Errorf("ref13: recommit node %d: %w", parent, err)
		}
		pn.commitment = c

		i = parent
	}
	return nil
}

// Root returns the root commitment, the only value a light node has to trust.
func (b *BAT) Root() curve.G1Affine { return b.nodes[0].commitment }

// Len reports how many nodes are materialised.
func (b *BAT) Len() int { return len(b.nodes) }

// Commitment returns node i's commitment.
func (b *BAT) Commitment(i int) (curve.G1Affine, error) {
	if i < 0 || i >= len(b.nodes) {
		return curve.G1Affine{}, fmt.Errorf("ref13: node %d does not exist", i)
	}
	return b.nodes[i].commitment, nil
}

// ProvePath builds the aggregated opening for block s — Algorithm 2.
//
// The chain it proves: C_s opens to m_s at position 1, and for every node on the
// path, the parent's commitment opens to that node's commitment at the child
// position. A verifier holding only the root can follow it down to m_s.
func (b *BAT) ProvePath(s int) (curve.G1Affine, fr.Element, []vc.Opening, error) {
	var piHat curve.G1Affine
	var muHat fr.Element

	if s < 0 || s >= len(b.nodes) {
		return piHat, muHat, nil, fmt.Errorf("ref13: node %d does not exist", s)
	}
	if !b.nodes[s].occupied {
		return piHat, muHat, nil, fmt.Errorf("ref13: node %d holds no block", s)
	}

	path, err := Path(s, b.q)
	if err != nil {
		return piHat, muHat, nil, err
	}

	vectors := make([][]fr.Element, 0, len(path))
	openings := make([]vc.Opening, 0, len(path))

	// The block itself, at position 1.
	add := func(nodeIdx, pos int) error {
		n := b.nodes[nodeIdx]
		value := n.vector[pos-1]
		vectors = append(vectors, n.vector)
		openings = append(openings, vc.Opening{
			C:     n.commitment,
			Pos:   pos,
			Value: value,
			Coeff: vc.DeriveCoefficient(pos, n.commitment, value),
		})
		return nil
	}
	if err := add(s, 1); err != nil {
		return piHat, muHat, nil, err
	}

	// Then each parent, opened at the position holding the child we came from.
	for _, i := range path {
		if i == 0 {
			continue
		}
		parent, _, err := Parent(i, b.q)
		if err != nil {
			return piHat, muHat, nil, err
		}
		pos, err := ChildPosition(i, b.q)
		if err != nil {
			return piHat, muHat, nil, err
		}
		if err := add(parent, pos); err != nil {
			return piHat, muHat, nil, err
		}
	}

	piHat, muHat, err = b.params.AggregateOpen(vectors, openings)
	if err != nil {
		return piHat, muHat, nil, err
	}
	return piHat, muHat, openings, nil
}

// VerifyPath checks an aggregated path proof against the root commitment.
//
// Checking the pairing alone is NOT enough, and this is the trap the whole
// structure invites: the aggregate proves each opening against the commitment
// the PROVER supplied, so a prover who supplies its own root would have every
// opening verify against a tree the verifier never agreed to. The link to the
// trusted root has to be checked separately, and it is checked first here.
func (b *BAT) VerifyPath(root curve.G1Affine, s int, m fr.Element, piHat curve.G1Affine, muHat fr.Element, openings []vc.Opening) (bool, error) {
	if len(openings) == 0 {
		return false, fmt.Errorf("ref13: no openings to verify")
	}

	// The last opening must be against the root the verifier trusts.
	if !openings[len(openings)-1].C.Equal(&root) {
		return false, nil
	}

	// The first opening must be the claimed block content at position 1.
	if openings[0].Pos != 1 || !openings[0].Value.Equal(&m) {
		return false, nil
	}

	// Each opening's claimed value must be the hash of the NEXT commitment down
	// the chain, or the links are unconnected and the aggregate proves a set of
	// unrelated statements.
	for i := 1; i < len(openings); i++ {
		want := childScalar(openings[i-1].C)
		if !openings[i].Value.Equal(&want) {
			return false, nil
		}
	}

	// Coefficients must be the bound ones, not whatever the prover sent.
	for i, o := range openings {
		want := vc.DeriveCoefficient(o.Pos, o.C, o.Value)
		if !o.Coeff.Equal(&want) {
			return false, fmt.Errorf(
				"ref13: opening %d carries an unbound coefficient", i)
		}
	}

	return b.params.AggregateVerify(openings, piHat, muHat)
}
