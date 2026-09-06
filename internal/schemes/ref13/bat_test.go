package ref13

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

	"zkredact/pkg/vc"
)

func newTestBAT(t *testing.T, q int) *BAT {
	t.Helper()
	params, err := vc.Setup(q + 1)
	if err != nil {
		t.Fatalf("vc.Setup: %v", err)
	}
	b, err := NewBAT(q, params, []byte("test-master-secret"))
	if err != nil {
		t.Fatalf("NewBAT: %v", err)
	}
	return b
}

func scalar(n uint64) fr.Element {
	var e fr.Element
	e.SetUint64(n)
	return e
}

// --- tree arithmetic -------------------------------------------------------

// TestTreeArithmeticIsSelfConsistent pins Parent, ChildPosition, Children,
// Level and Path against each other. An off-by-one in any of them puts a
// commitment in the wrong vector slot, which still verifies against itself.
func TestTreeArithmeticIsSelfConsistent(t *testing.T) {
	for _, q := range []int{2, 5, 10} {
		t.Run(fmt.Sprintf("q=%d", q), func(t *testing.T) {
			for i := 1; i < 200; i++ {
				parent, isRoot, err := Parent(i, q)
				if err != nil {
					t.Fatalf("Parent(%d): %v", i, err)
				}
				if isRoot {
					t.Fatalf("node %d reported as root", i)
				}

				// i must appear among its parent's children, at the slot
				// ChildPosition claims.
				pos, err := ChildPosition(i, q)
				if err != nil {
					t.Fatalf("ChildPosition(%d): %v", i, err)
				}
				kids := Children(parent, q)
				if got := kids[pos-2]; got != i {
					t.Errorf("q=%d node %d: parent %d child slot %d holds %d",
						q, i, parent, pos, got)
				}

				// Levels must increase by exactly one from parent to child.
				lp, err := Level(parent, q)
				if err != nil {
					t.Fatal(err)
				}
				li, err := Level(i, q)
				if err != nil {
					t.Fatal(err)
				}
				if li != lp+1 {
					t.Errorf("q=%d node %d: level %d, parent %d level %d", q, i, li, parent, lp)
				}

				// Path must start at i, end at the root, and have one entry
				// per level.
				path, err := Path(i, q)
				if err != nil {
					t.Fatal(err)
				}
				if path[0] != i || path[len(path)-1] != 0 {
					t.Errorf("q=%d node %d: path %v does not run from node to root", q, i, path)
				}
				if len(path) != li+1 {
					t.Errorf("q=%d node %d: path length %d, level %d", q, i, len(path), li)
				}
			}
		})
	}
}

// TestChildPositionsStayInsideTheVector is the guard against the error that
// would silently corrupt commitments: a child slot outside [2, q+1] would index
// past the committed vector, or overwrite m_i at position 1.
func TestChildPositionsStayInsideTheVector(t *testing.T) {
	for _, q := range []int{2, 5, 10} {
		for i := 1; i < 500; i++ {
			pos, err := ChildPosition(i, q)
			if err != nil {
				t.Fatalf("ChildPosition(%d, %d): %v", i, q, err)
			}
			if pos < 2 || pos > q+1 {
				t.Fatalf("q=%d node %d: child position %d outside [2, %d]", q, i, pos, q+1)
			}
		}
	}
}

func TestRootHasNoParentOrChildPosition(t *testing.T) {
	if _, isRoot, err := Parent(0, 5); err != nil || !isRoot {
		t.Errorf("Parent(0) = root %v, err %v", isRoot, err)
	}
	if _, err := ChildPosition(0, 5); err == nil {
		t.Error("the root was given a child position")
	}
}

// --- binding and paths -----------------------------------------------------

// TestNIsTiedToArity pins the derived relation. A mismatch means the tree and
// the commitment parameters disagree about how wide a node is.
func TestNIsTiedToArity(t *testing.T) {
	params, err := vc.Setup(7) // N=7 implies q=6
	if err != nil {
		t.Fatalf("vc.Setup: %v", err)
	}
	if _, err := NewBAT(5, params, []byte("s")); err == nil {
		t.Error("a BAT was built with N != q+1")
	}
}

// TestPathProofVerifiesAgainstTheRoot is the property the whole structure
// exists for: a verifier trusting only the root can be convinced of a block.
func TestPathProofVerifiesAgainstTheRoot(t *testing.T) {
	for _, q := range []int{2, 5, 10} {
		t.Run(fmt.Sprintf("q=%d", q), func(t *testing.T) {
			b := newTestBAT(t, q)

			for i := 1; i <= 30; i++ {
				if err := b.Bind(i, scalar(uint64(1000+i))); err != nil {
					t.Fatalf("Bind(%d): %v", i, err)
				}
			}

			for _, s := range []int{1, 7, 23, 30} {
				piHat, muHat, openings, err := b.ProvePath(s)
				if err != nil {
					t.Fatalf("ProvePath(%d): %v", s, err)
				}
				ok, err := b.VerifyPath(b.Root(), s, scalar(uint64(1000+s)), piHat, muHat, openings)
				if err != nil {
					t.Fatalf("VerifyPath(%d): %v", s, err)
				}
				if !ok {
					t.Errorf("q=%d: valid path proof for block %d rejected", q, s)
				}
			}
		})
	}
}

// TestRedactionChangesTheRoot is the point of the tree: revoking block data
// must be visible at the root, or a light node could be shown the old version.
func TestRedactionChangesTheRoot(t *testing.T) {
	b := newTestBAT(t, 5)
	for i := 1; i <= 20; i++ {
		if err := b.Bind(i, scalar(uint64(1000+i))); err != nil {
			t.Fatalf("Bind: %v", err)
		}
	}
	before := b.Root()

	if err := b.Bind(13, scalar(999999)); err != nil {
		t.Fatalf("redact: %v", err)
	}
	after := b.Root()

	if before.Equal(&after) {
		t.Error("redacting a block left the root commitment unchanged; the tree " +
			"is not binding the block data it is supposed to bind")
	}
}

// TestStaleProofFailsAfterRedaction is the attack VRBC exists to stop: a full
// node serving the pre-redaction version to a light node.
func TestStaleProofFailsAfterRedaction(t *testing.T) {
	b := newTestBAT(t, 5)
	for i := 1; i <= 20; i++ {
		if err := b.Bind(i, scalar(uint64(1000+i))); err != nil {
			t.Fatalf("Bind: %v", err)
		}
	}

	stalePi, staleMu, staleOpenings, err := b.ProvePath(13)
	if err != nil {
		t.Fatalf("ProvePath: %v", err)
	}

	if err := b.Bind(13, scalar(999999)); err != nil {
		t.Fatalf("redact: %v", err)
	}

	ok, err := b.VerifyPath(b.Root(), 13, scalar(1013), stalePi, staleMu, staleOpenings)
	if err == nil && ok {
		t.Error("a pre-redaction proof still verified against the new root")
	}
}

// TestVerifyPathRejectsAForeignRoot is the trap the aggregation invites.
//
// AggregateVerify checks each opening against the commitment the PROVER
// supplied. A prover who supplies its own tree therefore has every opening
// verify — the pairing check alone proves nothing about the verifier's chain.
// VerifyPath must anchor the top opening to the trusted root, and this test
// fails if that anchor is ever removed.
func TestVerifyPathRejectsAForeignRoot(t *testing.T) {
	honest := newTestBAT(t, 5)
	for i := 1; i <= 10; i++ {
		if err := honest.Bind(i, scalar(uint64(1000+i))); err != nil {
			t.Fatalf("Bind: %v", err)
		}
	}

	// A second, internally consistent tree with different content.
	forged := newTestBAT(t, 5)
	for i := 1; i <= 10; i++ {
		if err := forged.Bind(i, scalar(uint64(5000+i))); err != nil {
			t.Fatalf("Bind: %v", err)
		}
	}

	piHat, muHat, openings, err := forged.ProvePath(7)
	if err != nil {
		t.Fatalf("ProvePath: %v", err)
	}

	// The forged proof is internally valid — confirm that, so the test is
	// about the anchor and not about a broken proof.
	ok, err := forged.VerifyPath(forged.Root(), 7, scalar(5007), piHat, muHat, openings)
	if err != nil {
		t.Fatalf("VerifyPath on its own tree: %v", err)
	}
	if !ok {
		t.Fatal("the forged tree's own proof did not verify; this test proves nothing")
	}

	// Against the honest root it must fail.
	ok, err = honest.VerifyPath(honest.Root(), 7, scalar(5007), piHat, muHat, openings)
	if err == nil && ok {
		t.Error("a proof from a different tree verified against the honest root")
	}
}

// TestVerifyPathRejectsABrokenChain catches openings that each verify but do
// not link: the aggregate would prove a set of unrelated statements.
func TestVerifyPathRejectsABrokenChain(t *testing.T) {
	b := newTestBAT(t, 5)
	for i := 1; i <= 40; i++ {
		if err := b.Bind(i, scalar(uint64(1000+i))); err != nil {
			t.Fatalf("Bind: %v", err)
		}
	}

	piHat, muHat, openings, err := b.ProvePath(38)
	if err != nil {
		t.Fatalf("ProvePath: %v", err)
	}
	if len(openings) < 3 {
		t.Fatalf("need a path of at least 3 to break a link, got %d", len(openings))
	}

	// Replace a middle link with an opening from elsewhere in the tree.
	other, err := b.ProvePathOpeningsFor(t, 12)
	if err != nil {
		t.Fatalf("second path: %v", err)
	}
	broken := make([]vc.Opening, len(openings))
	copy(broken, openings)
	broken[1] = other[1]

	ok, err := b.VerifyPath(b.Root(), 38, scalar(1038), piHat, muHat, broken)
	if err == nil && ok {
		t.Error("a path with a broken link verified")
	}
}

// TestVerifyPathRejectsUnboundCoefficients pins that the verifier rebinds
// rather than trusting what it is sent — without it, vc's cancellation forgery
// is available through this layer.
func TestVerifyPathRejectsUnboundCoefficients(t *testing.T) {
	b := newTestBAT(t, 5)
	for i := 1; i <= 10; i++ {
		if err := b.Bind(i, scalar(uint64(1000+i))); err != nil {
			t.Fatalf("Bind: %v", err)
		}
	}
	piHat, muHat, openings, err := b.ProvePath(7)
	if err != nil {
		t.Fatalf("ProvePath: %v", err)
	}

	tampered := make([]vc.Opening, len(openings))
	copy(tampered, openings)
	tampered[0].Coeff = scalar(2)

	if _, err := b.VerifyPath(b.Root(), 7, scalar(1007), piHat, muHat, tampered); err == nil {
		t.Error("an unbound coefficient was accepted")
	}
}

// ProvePathOpeningsFor is a test helper: the openings for another block, used
// to splice a foreign link into a path.
func (b *BAT) ProvePathOpeningsFor(t *testing.T, s int) ([]vc.Opening, error) {
	t.Helper()
	_, _, openings, err := b.ProvePath(s)
	return openings, err
}
