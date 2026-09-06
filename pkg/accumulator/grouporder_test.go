package accumulator

import (
	"fmt"
	"math/big"
	"testing"
)

const orderTestBits = 1024

// The two deletion paths must produce IDENTICAL state.
//
// This is the test that makes the trapdoor path safe to use: it is a cost
// optimisation only if it computes the same thing. If it did not, Ref[22] would
// be measured on an accumulator that is cheaper because it is wrong, which is
// worse than the O(n) rebuild it replaces.
func TestTrapdoorDeleteMatchesTheRebuild(t *testing.T) {
	n, phi, err := GenerateUntrustedWithOrder(orderTestBits)
	if err != nil {
		t.Fatalf("GenerateUntrustedWithOrder: %v", err)
	}

	withTrapdoor, err := New(Config{Bits: orderTestBits, Modulus: n, GroupOrder: phi})
	if err != nil {
		t.Fatalf("New (trapdoor): %v", err)
	}
	rebuild, err := New(Config{Bits: orderTestBits, Modulus: n})
	if err != nil {
		t.Fatalf("New (rebuild): %v", err)
	}
	if !withTrapdoor.HasGroupOrder() {
		t.Fatal("accumulator with GroupOrder reports it has none")
	}
	if rebuild.HasGroupOrder() {
		t.Fatal("accumulator without GroupOrder reports it has one")
	}

	elems := make([][]byte, 12)
	for i := range elems {
		elems[i] = []byte(fmt.Sprintf("block-%03d", i))
		for _, a := range []*Accumulator{withTrapdoor, rebuild} {
			if _, err := a.Add(elems[i]); err != nil {
				t.Fatalf("Add: %v", err)
			}
		}
	}
	if withTrapdoor.State().Cmp(rebuild.State()) != 0 {
		t.Fatal("states diverged before any deletion")
	}

	// Delete a scattered subset, checking agreement after every step so a
	// divergence is attributed to the deletion that caused it.
	for _, i := range []int{3, 0, 11, 7} {
		for _, a := range []*Accumulator{withTrapdoor, rebuild} {
			if err := a.Delete(elems[i]); err != nil {
				t.Fatalf("Delete(%d): %v", i, err)
			}
		}
		if withTrapdoor.State().Cmp(rebuild.State()) != 0 {
			t.Fatalf("states diverged after deleting element %d:\n trapdoor %s\n rebuild  %s",
				i, withTrapdoor.State(), rebuild.State())
		}
	}
}

// Witnesses generated after a trapdoor deletion must still verify, and a
// deleted element must still be provably absent.
func TestWitnessesSurviveTrapdoorDelete(t *testing.T) {
	n, phi, err := GenerateUntrustedWithOrder(orderTestBits)
	if err != nil {
		t.Fatalf("GenerateUntrustedWithOrder: %v", err)
	}
	a, err := New(Config{Bits: orderTestBits, Modulus: n, GroupOrder: phi})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	kept := []byte("kept")
	gone := []byte("gone")
	for _, x := range [][]byte{kept, gone, []byte("other")} {
		if _, err := a.Add(x); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	if err := a.Delete(gone); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	w, err := a.MembershipWitness(kept)
	if err != nil {
		t.Fatalf("MembershipWitness: %v", err)
	}
	ok, err := VerifyMembership(a.Modulus(), a.State(), w, kept)
	if err != nil || !ok {
		t.Errorf("surviving element does not verify after a trapdoor delete (ok=%v, err=%v)", ok, err)
	}

	aCoef, d, err := a.NonMembershipWitness(gone)
	if err != nil {
		t.Fatalf("NonMembershipWitness: %v", err)
	}
	ok, err = VerifyNonMembership(a.Modulus(), a.Generator(), a.State(), aCoef, d, gone)
	if err != nil || !ok {
		t.Errorf("deleted element is not provably absent after a trapdoor delete (ok=%v, err=%v)", ok, err)
	}
}

// The reversion attack must still be caught on the trapdoor path — that is
// Ref[22]'s central security claim, and a faster deletion must not weaken it.
func TestTrapdoorDeleteStillDetectsReversion(t *testing.T) {
	n, phi, err := GenerateUntrustedWithOrder(orderTestBits)
	if err != nil {
		t.Fatalf("GenerateUntrustedWithOrder: %v", err)
	}
	a, err := New(Config{Bits: orderTestBits, Modulus: n, GroupOrder: phi})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	oldVersion := []byte("block-7-v1")
	if _, err := a.Add(oldVersion); err != nil {
		t.Fatalf("Add: %v", err)
	}
	staleWitness, err := a.MembershipWitness(oldVersion)
	if err != nil {
		t.Fatalf("MembershipWitness: %v", err)
	}
	if _, err := a.Add([]byte("block-8-v1")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := a.Delete(oldVersion); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	ok, err := VerifyMembership(a.Modulus(), a.State(), staleWitness, oldVersion)
	if err == nil && ok {
		t.Errorf("a superseded version still verifies after deletion; reversion is undetectable")
	}
}

// A non-invertible prime must be refused rather than silently rebuilding: the
// two paths differ by a factor of n, and Exp 2 measures that difference.
func TestNonInvertiblePrimeIsRefusedNotDowngraded(t *testing.T) {
	a := &Accumulator{
		n:     big.NewInt(3 * 5),
		g:     big.NewInt(2),
		phi:   big.NewInt(8), // (3-1)(5-1)
		state: big.NewInt(2),
	}
	// 2 shares a factor with phi = 8, so it has no inverse.
	if err := a.recomputeAfterDelete(big.NewInt(2)); err == nil {
		t.Errorf("silently accepted a prime with no inverse mod phi(N)")
	}
}
