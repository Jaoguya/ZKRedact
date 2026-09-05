package merkle

import (
	"bytes"
	"fmt"
	"testing"
)

func leaves(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = []byte(fmt.Sprintf("leaf-%04d", i))
	}
	return out
}

func TestEmptyTreeRejected(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Errorf("New accepted an empty leaf set")
	}
	if _, err := NewFromHashes(nil); err == nil {
		t.Errorf("NewFromHashes accepted an empty leaf set")
	}
}

func TestSingleLeaf(t *testing.T) {
	tr, err := New(leaves(1))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if tr.LeafCount() != 1 {
		t.Errorf("LeafCount = %d, want 1", tr.LeafCount())
	}
	if !bytes.Equal(tr.Root(), HashLeaf(leaves(1)[0])) {
		t.Errorf("root of a single-leaf tree must be that leaf's hash")
	}

	p, err := tr.Proof(0)
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}
	if p.Len() != 0 {
		t.Errorf("single-leaf proof should be empty, got %d siblings", p.Len())
	}
	if !Verify(tr.Root(), leaves(1)[0], p) {
		t.Errorf("single-leaf proof failed to verify")
	}
}

// TestAllProofsVerify sweeps sizes including odd ones, where the promotion rule
// applies and off-by-one path errors surface.
func TestAllProofsVerify(t *testing.T) {
	for _, n := range []int{1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 100, 1000} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			ls := leaves(n)
			tr, err := New(ls)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			root := tr.Root()

			for i := 0; i < n; i++ {
				p, err := tr.Proof(i)
				if err != nil {
					t.Fatalf("Proof(%d): %v", i, err)
				}
				if !Verify(root, ls[i], p) {
					t.Errorf("proof for leaf %d of %d failed to verify", i, n)
				}
			}
		})
	}
}

func TestTamperedLeafFails(t *testing.T) {
	ls := leaves(8)
	tr, _ := New(ls)
	p, _ := tr.Proof(3)

	if Verify(tr.Root(), []byte("not-the-leaf"), p) {
		t.Errorf("a proof verified against the wrong leaf data")
	}
}

func TestTamperedProofFails(t *testing.T) {
	ls := leaves(8)
	tr, _ := New(ls)
	root := tr.Root()

	t.Run("flipped sibling bit", func(t *testing.T) {
		p, _ := tr.Proof(3)
		p.Siblings[0][0] ^= 0x01
		if Verify(root, ls[3], p) {
			t.Errorf("verified with a corrupted sibling")
		}
	})

	t.Run("flipped direction", func(t *testing.T) {
		p, _ := tr.Proof(3)
		p.Left[0] = !p.Left[0]
		if Verify(root, ls[3], p) {
			t.Errorf("verified with a flipped direction")
		}
	})

	t.Run("truncated path", func(t *testing.T) {
		p, _ := tr.Proof(3)
		p.Siblings = p.Siblings[:len(p.Siblings)-1]
		p.Left = p.Left[:len(p.Left)-1]
		if Verify(root, ls[3], p) {
			t.Errorf("verified with a truncated path")
		}
	})

	t.Run("mismatched lengths", func(t *testing.T) {
		p, _ := tr.Proof(3)
		p.Left = p.Left[:len(p.Left)-1]
		if Verify(root, ls[3], p) {
			t.Errorf("verified a malformed proof")
		}
	})

	t.Run("wrong sibling size", func(t *testing.T) {
		p, _ := tr.Proof(3)
		p.Siblings[0] = []byte{0x01, 0x02}
		if Verify(root, ls[3], p) {
			t.Errorf("verified with an undersized sibling hash")
		}
	})
}

// TestSecondPreimageResistance is the reason for the domain-separation
// prefixes. Without them an internal node's hash equals a leaf's hash over the
// same bytes, so a prover could present an internal node as a leaf and prove
// inclusion of data that was never committed.
func TestSecondPreimageResistance(t *testing.T) {
	ls := leaves(4)
	tr, _ := New(ls)
	root := tr.Root()

	// Reconstruct the internal node covering leaves 0 and 1.
	internal := HashInternal(HashLeaf(ls[0]), HashLeaf(ls[1]))

	// Present that internal node as though it were leaf data, with the proof
	// that would be valid at its level.
	forged := &Proof{
		Index:    0,
		Siblings: [][]byte{HashInternal(HashLeaf(ls[2]), HashLeaf(ls[3]))},
		Left:     []bool{false},
	}
	if Verify(root, internal, forged) {
		t.Errorf("an internal node was accepted as a leaf; domain separation is not working")
	}

	// Sanity check that the same shape verifies when treated as a node hash,
	// confirming the test targets the prefix rather than a broken path.
	if !VerifyHash(root, internal, forged) {
		t.Errorf("VerifyHash should accept the internal node at its own level")
	}
}

// TestOddNodeNotDuplicated guards against the Bitcoin duplication bug
// (CVE-2012-2459), where duplicating an unpaired node lets two distinct leaf
// sets produce the same root.
func TestOddNodeNotDuplicated(t *testing.T) {
	three := leaves(3)

	// The leaf set that a duplicating implementation would collide with.
	four := [][]byte{three[0], three[1], three[2], three[2]}

	t3, _ := New(three)
	t4, _ := New(four)

	if bytes.Equal(t3.Root(), t4.Root()) {
		t.Errorf("3-leaf and 4-leaf (last duplicated) trees share a root; "+
			"the unpaired node is being duplicated\n root %x", t3.Root())
	}
}

func TestDistinctLeafSetsGiveDistinctRoots(t *testing.T) {
	a, _ := New(leaves(8))
	b := leaves(8)
	b[5] = []byte("changed")
	c, _ := New(b)

	if bytes.Equal(a.Root(), c.Root()) {
		t.Errorf("changing a leaf did not change the root")
	}
}

func TestProofIndexBounds(t *testing.T) {
	tr, _ := New(leaves(4))
	for _, i := range []int{-1, 4, 100} {
		if _, err := tr.Proof(i); err == nil {
			t.Errorf("Proof(%d) succeeded on a 4-leaf tree", i)
		}
	}
}

func TestProofDoesNotAliasTree(t *testing.T) {
	ls := leaves(8)
	tr, _ := New(ls)
	root := tr.Root()

	p, _ := tr.Proof(0)
	p.Siblings[0][0] ^= 0xff // mutate the returned proof

	// Mutating a proof must not corrupt the tree it came from.
	p2, _ := tr.Proof(0)
	if !Verify(root, ls[0], p2) {
		t.Errorf("mutating one proof corrupted the tree's internal state")
	}
}

func TestRootDoesNotAliasTree(t *testing.T) {
	tr, _ := New(leaves(4))
	r1 := tr.Root()
	r1[0] ^= 0xff
	if bytes.Equal(tr.Root(), r1) {
		t.Errorf("Root returned an alias of internal state")
	}
}

func TestNewFromHashesMatchesNew(t *testing.T) {
	ls := leaves(7)
	a, _ := New(ls)

	hashes := make([][]byte, len(ls))
	for i, l := range ls {
		hashes[i] = HashLeaf(l)
	}
	b, _ := NewFromHashes(hashes)

	if !bytes.Equal(a.Root(), b.Root()) {
		t.Errorf("New and NewFromHashes disagree on the root")
	}
}

func TestProofPathLengthIsLogarithmic(t *testing.T) {
	// Exp 3 claims audit cost tracks history depth rather than ledger size, and
	// that rests on proof length growing logarithmically.
	for _, n := range []int{16, 256, 4096} {
		tr, _ := New(leaves(n))
		p, _ := tr.Proof(0)
		maxLen := 0
		for m := n; m > 1; m = (m + 1) / 2 {
			maxLen++
		}
		if p.Len() > maxLen {
			t.Errorf("n=%d: proof length %d exceeds ceil(log2) bound %d", n, p.Len(), maxLen)
		}
	}
}

func BenchmarkNew1000(b *testing.B) {
	ls := leaves(1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := New(ls); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkProof(b *testing.B) {
	tr, _ := New(leaves(4096))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := tr.Proof(i % 4096); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	ls := leaves(4096)
	tr, _ := New(ls)
	root := tr.Root()
	p, _ := tr.Proof(1234)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !Verify(root, ls[1234], p) {
			b.Fatal("verification failed")
		}
	}
}
