// Package merkle implements a binary Merkle tree with inclusion proofs.
//
// Used by three of the systems under test, which is why it lives in pkg rather
// than inside any one of them:
//
//   - ZK-Redact's PAI authenticates provenance histories against an anchored
//     root, and builds the batch-result commitment R_B.
//   - Ref[10]'s EMT is a Merkle tree with two branches per transaction.
//   - Ref[13] uses a Merkle root over block transactions.
//
// DOMAIN SEPARATION. Leaves are hashed as H(0x00 || leaf) and internal nodes as
// H(0x01 || left || right), following RFC 6962. Without the prefixes an internal
// node's hash is indistinguishable from a leaf's, so a prover can present an
// internal node as though it were a leaf and produce a shorter proof for data
// that was never committed. That is a real second-preimage attack, not a
// theoretical one, and it costs one byte to prevent.
//
// ODD NODES. An unpaired node is promoted to the next level unchanged. It is NOT
// duplicated and paired with itself, which is what Bitcoin does and what gives
// rise to CVE-2012-2459: duplicating the last node makes two distinct leaf sets
// produce the same root.
package merkle

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
)

// Domain separation prefixes (RFC 6962).
const (
	leafPrefix     byte = 0x00
	internalPrefix byte = 0x01
)

// Size is the length of a node hash in bytes.
const Size = sha256.Size

var (
	// ErrEmptyTree reports an operation on a tree with no leaves.
	ErrEmptyTree = errors.New("merkle: tree is empty")

	// ErrIndexOutOfRange reports a proof requested for a nonexistent leaf.
	ErrIndexOutOfRange = errors.New("merkle: leaf index out of range")
)

// Tree is an immutable Merkle tree over a fixed leaf set.
type Tree struct {
	// levels[0] holds leaf hashes; the last level holds the single root.
	levels [][][]byte
	nLeaf  int
}

// Proof is an inclusion proof for one leaf.
type Proof struct {
	// Index is the leaf's position, needed to know sibling sides.
	Index int

	// Siblings are the hashes needed to recompute the root, ordered from the
	// leaf's level upward. A level where the node was promoted unpaired
	// contributes no sibling.
	Siblings [][]byte

	// Left records, for each sibling, whether it sits on the left. Recording
	// this explicitly rather than deriving it from Index at verification time
	// keeps promoted levels unambiguous.
	Left []bool
}

// Len returns the number of sibling hashes, i.e. the proof's path length.
func (p *Proof) Len() int { return len(p.Siblings) }

// Bytes returns the total wire size of the proof. Exp 3 reports proof size
// alongside verification time, since a scheme can trade one for the other.
func (p *Proof) Bytes() int {
	n := 0
	for _, s := range p.Siblings {
		n += len(s)
	}
	return n
}

// HashLeaf returns the domain-separated hash of leaf data.
func HashLeaf(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	h.Write(data)
	return h.Sum(nil)
}

// HashInternal returns the domain-separated hash of two child hashes.
func HashInternal(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{internalPrefix})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// New builds a tree over the given leaves.
//
// Leaf data is hashed internally; callers pass raw data, not digests. The
// returned tree does not alias the input slices.
func New(leaves [][]byte) (*Tree, error) {
	if len(leaves) == 0 {
		return nil, ErrEmptyTree
	}

	level := make([][]byte, len(leaves))
	for i, l := range leaves {
		level[i] = HashLeaf(l)
	}

	t := &Tree{levels: [][][]byte{level}, nLeaf: len(leaves)}
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				next = append(next, HashInternal(level[i], level[i+1]))
			} else {
				// Promote unpaired: no self-pairing, no duplication.
				next = append(next, level[i])
			}
		}
		t.levels = append(t.levels, next)
		level = next
	}
	return t, nil
}

// NewFromHashes builds a tree over pre-computed leaf hashes.
//
// Needed by Ref[10]'s EMT, whose leaves are already the transaction hashes
// H_c and H_w rather than raw payloads. Callers are responsible for having
// applied domain separation themselves.
func NewFromHashes(leafHashes [][]byte) (*Tree, error) {
	if len(leafHashes) == 0 {
		return nil, ErrEmptyTree
	}
	level := make([][]byte, len(leafHashes))
	for i, h := range leafHashes {
		level[i] = append([]byte(nil), h...)
	}

	t := &Tree{levels: [][][]byte{level}, nLeaf: len(leafHashes)}
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				next = append(next, HashInternal(level[i], level[i+1]))
			} else {
				next = append(next, level[i])
			}
		}
		t.levels = append(t.levels, next)
		level = next
	}
	return t, nil
}

// Root returns the tree root.
func (t *Tree) Root() []byte {
	if t == nil || len(t.levels) == 0 {
		return nil
	}
	top := t.levels[len(t.levels)-1]
	if len(top) == 0 {
		return nil
	}
	return append([]byte(nil), top[0]...)
}

// LeafCount returns the number of leaves.
func (t *Tree) LeafCount() int {
	if t == nil {
		return 0
	}
	return t.nLeaf
}

// Depth returns the number of levels, root included.
func (t *Tree) Depth() int {
	if t == nil {
		return 0
	}
	return len(t.levels)
}

// LeafHash returns the stored hash of leaf i.
func (t *Tree) LeafHash(i int) ([]byte, error) {
	if t == nil || len(t.levels) == 0 {
		return nil, ErrEmptyTree
	}
	if i < 0 || i >= t.nLeaf {
		return nil, fmt.Errorf("%w: %d not in [0,%d)", ErrIndexOutOfRange, i, t.nLeaf)
	}
	return append([]byte(nil), t.levels[0][i]...), nil
}

// Proof builds an inclusion proof for leaf i.
func (t *Tree) Proof(i int) (*Proof, error) {
	if t == nil || len(t.levels) == 0 {
		return nil, ErrEmptyTree
	}
	if i < 0 || i >= t.nLeaf {
		return nil, fmt.Errorf("%w: %d not in [0,%d)", ErrIndexOutOfRange, i, t.nLeaf)
	}

	p := &Proof{Index: i}
	idx := i
	for level := 0; level < len(t.levels)-1; level++ {
		nodes := t.levels[level]

		if idx%2 == 0 {
			if idx+1 < len(nodes) {
				p.Siblings = append(p.Siblings, append([]byte(nil), nodes[idx+1]...))
				p.Left = append(p.Left, false) // sibling on the right
			}
			// else: promoted unpaired, no sibling contributed at this level
		} else {
			p.Siblings = append(p.Siblings, append([]byte(nil), nodes[idx-1]...))
			p.Left = append(p.Left, true) // sibling on the left
		}
		idx /= 2
	}
	return p, nil
}

// Verify recomputes the root from a leaf and its proof.
//
// Returns a bool rather than an error: a failed proof is a normal, expected
// outcome that the audit path must be able to report, not a fault.
func Verify(root, leaf []byte, p *Proof) bool {
	if p == nil || root == nil {
		return false
	}
	return verifyFrom(root, HashLeaf(leaf), p)
}

// VerifyHash is Verify for a caller that already holds the leaf hash, used by
// schemes whose leaves are pre-hashed.
func VerifyHash(root, leafHash []byte, p *Proof) bool {
	if p == nil || root == nil {
		return false
	}
	return verifyFrom(root, append([]byte(nil), leafHash...), p)
}

func verifyFrom(root, cur []byte, p *Proof) bool {
	if len(p.Siblings) != len(p.Left) {
		// A malformed proof, not merely an invalid one. Reject rather than
		// index past the end.
		return false
	}
	for i, sib := range p.Siblings {
		if len(sib) != Size {
			return false
		}
		if p.Left[i] {
			cur = HashInternal(sib, cur)
		} else {
			cur = HashInternal(cur, sib)
		}
	}
	return bytes.Equal(cur, root)
}
