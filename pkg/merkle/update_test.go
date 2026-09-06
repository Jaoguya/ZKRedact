package merkle

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
)

func leafSet(n int, tag string) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = []byte(fmt.Sprintf("%s-leaf-%d", tag, i))
	}
	return out
}

// TestUpdateMatchesRebuild is the property the PAI depends on: an incrementally
// updated root equals the root a full rebuild would produce.
//
// If these ever diverge, R_PAI^(e) stops being the Merkle root the manuscript
// defines and every audit against it verifies a commitment to nothing. The
// awkward leaf counts are deliberate — 3, 5, 7, 9 exercise the promotion of an
// unpaired node at several levels at once, which is where an index-arithmetic
// error would hide.
func TestUpdateMatchesRebuild(t *testing.T) {
	for _, n := range []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 31, 33, 100} {
		n := n
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			leaves := leafSet(n, "base")
			tree, err := New(leaves)
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			rng := rand.New(rand.NewSource(int64(n)))
			for step := 0; step < 3*n; step++ {
				i := rng.Intn(n)
				repl := []byte(fmt.Sprintf("updated-%d-%d", i, step))

				leaves[i] = repl
				if err := tree.UpdateLeaf(i, repl); err != nil {
					t.Fatalf("UpdateLeaf(%d): %v", i, err)
				}

				want, err := New(leaves)
				if err != nil {
					t.Fatalf("rebuild: %v", err)
				}
				if !bytes.Equal(tree.Root(), want.Root()) {
					t.Fatalf("step %d, leaf %d: incremental root %x, rebuild %x",
						step, i, tree.Root(), want.Root())
				}
			}
		})
	}
}

// TestUpdateKeepsProofsValid checks the other half: after an update, inclusion
// proofs must verify against the NEW root for every leaf, not only the changed
// one. A stale ancestor would leave most proofs passing and a few failing,
// which in Exp 3 would read as an intermittent audit failure.
func TestUpdateKeepsProofsValid(t *testing.T) {
	const n = 13
	leaves := leafSet(n, "proof")
	tree, err := New(leaves)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	leaves[6] = []byte("changed")
	if err := tree.UpdateLeaf(6, leaves[6]); err != nil {
		t.Fatalf("UpdateLeaf: %v", err)
	}

	root := tree.Root()
	for i := 0; i < n; i++ {
		p, err := tree.Proof(i)
		if err != nil {
			t.Fatalf("Proof(%d): %v", i, err)
		}
		if !Verify(root, leaves[i], p) {
			t.Errorf("leaf %d does not verify against the updated root", i)
		}
	}

	// The old value must no longer verify, or the update did not take.
	p, err := tree.Proof(6)
	if err != nil {
		t.Fatalf("Proof(6): %v", err)
	}
	if Verify(root, []byte("proof-leaf-6"), p) {
		t.Error("the replaced leaf still verifies; the update did not reach the root")
	}
}

func TestUpdateLeafRejectsBadInput(t *testing.T) {
	tree, err := New(leafSet(4, "bad"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := tree.UpdateLeaf(-1, []byte("x")); err == nil {
		t.Error("negative index accepted")
	}
	if err := tree.UpdateLeaf(4, []byte("x")); err == nil {
		t.Error("index past the end accepted")
	}
	if err := tree.UpdateLeafHash(0, []byte("too short")); err == nil {
		t.Error("a leaf hash of the wrong length was accepted; it would corrupt the tree silently")
	}
	var nilTree *Tree
	if err := nilTree.UpdateLeaf(0, []byte("x")); err == nil {
		t.Error("nil tree accepted an update")
	}
}

// TestUpdateLeafHashMatchesNewFromHashes covers the pre-hashed entry point
// against its own constructor, since it uses a different promotion path at
// level 0 than New does.
func TestUpdateLeafHashMatchesNewFromHashes(t *testing.T) {
	const n = 11
	hashes := make([][]byte, n)
	for i := range hashes {
		hashes[i] = HashLeaf([]byte(fmt.Sprintf("h-%d", i)))
	}
	tree, err := NewFromHashes(hashes)
	if err != nil {
		t.Fatalf("NewFromHashes: %v", err)
	}

	for i := 0; i < n; i++ {
		hashes[i] = HashLeaf([]byte(fmt.Sprintf("h-%d-v2", i)))
		if err := tree.UpdateLeafHash(i, hashes[i]); err != nil {
			t.Fatalf("UpdateLeafHash(%d): %v", i, err)
		}
		want, err := NewFromHashes(hashes)
		if err != nil {
			t.Fatalf("rebuild: %v", err)
		}
		if !bytes.Equal(tree.Root(), want.Root()) {
			t.Fatalf("after updating %d: %x != %x", i, tree.Root(), want.Root())
		}
	}
}
