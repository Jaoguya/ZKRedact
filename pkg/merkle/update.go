package merkle

import "fmt"

// UpdateLeaf replaces leaf i and recomputes only the path from it to the root.
//
// WHY THIS EXISTS. ZK-Redact's Phase 5 Step 3 recomputes the PAI root over
// EVERY indexed transaction after each redaction round:
//
//	R_PAI^(e) = MerkleRoot({A_i^(v_i)}_{i in I^(e)})
//
// Rebuilding from scratch is O(|I|) hashes per round. Exp 3 runs ledgers of
// 10,000 blocks x 100 transactions, so a round would cost a million hashes and
// the untimed history construction alone would take minutes per point — and
// Exp 2 charges the rebuild to LedgerTime, where it would swamp the
// amortisation the experiment is trying to measure.
//
// The root this produces is IDENTICAL to New()'s over the same leaf set. That
// is the property worth stating, because it is what makes this an
// implementation of the equation rather than a different commitment: the
// promotion rule for unpaired nodes is reproduced exactly, so no leaf set
// exists for which the two disagree. TestUpdateMatchesRebuild asserts it over
// randomised leaf counts and update sequences.
//
// The leaf set is FIXED. This changes a leaf's value, never the tree's shape —
// a scheme that appends must build a new tree, because the promotion structure
// depends on the count.
//
// NOT SAFE FOR CONCURRENT USE with itself or with Proof/Root. The tree mutates
// in place; callers hold their own lock. internal/pai does.
func (t *Tree) UpdateLeaf(i int, leaf []byte) error {
	return t.UpdateLeafHash(i, HashLeaf(leaf))
}

// UpdateLeafHash is UpdateLeaf for a caller that already holds the leaf hash,
// matching NewFromHashes.
func (t *Tree) UpdateLeafHash(i int, leafHash []byte) error {
	if t == nil || len(t.levels) == 0 {
		return ErrEmptyTree
	}
	if i < 0 || i >= t.nLeaf {
		return fmt.Errorf("%w: %d not in [0,%d)", ErrIndexOutOfRange, i, t.nLeaf)
	}
	if len(leafHash) != Size {
		return fmt.Errorf("merkle: leaf hash is %d bytes, want %d", len(leafHash), Size)
	}

	t.levels[0][i] = append([]byte(nil), leafHash...)

	// Recompute the ancestors, reproducing New's pairing and promotion rules
	// level by level. Deriving the parent as idx/2 is only correct because an
	// unpaired node is PROMOTED rather than duplicated: promotion keeps the
	// level width at ceil(n/2) with no shift, so index arithmetic survives.
	idx := i
	for level := 0; level < len(t.levels)-1; level++ {
		nodes := t.levels[level]
		parent := idx / 2

		var v []byte
		switch {
		case idx%2 == 1:
			v = HashInternal(nodes[idx-1], nodes[idx])
		case idx+1 < len(nodes):
			v = HashInternal(nodes[idx], nodes[idx+1])
		default:
			// Unpaired: promoted unchanged, exactly as New does.
			v = append([]byte(nil), nodes[idx]...)
		}
		t.levels[level+1][parent] = v
		idx = parent
	}
	return nil
}
