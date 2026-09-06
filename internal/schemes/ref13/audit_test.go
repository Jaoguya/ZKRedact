package ref13

import (
	"fmt"
	"testing"
)

func filledBAT(t *testing.T, q, blocks int) *BAT {
	t.Helper()
	b := newTestBAT(t, q)
	for i := 1; i <= blocks; i++ {
		if err := b.Bind(i, scalar(uint64(1000+i))); err != nil {
			t.Fatalf("Bind(%d): %v", i, err)
		}
	}
	return b
}

func testChallenge(z int) Challenge {
	return Challenge{Z: z, Phi1: []byte("phi-one"), Phi2: []byte("phi-two")}
}

// TestAuditVerifies is the correctness property of Algorithm 3.
func TestAuditVerifies(t *testing.T) {
	for _, q := range []int{2, 5, 10} {
		t.Run(fmt.Sprintf("q=%d", q), func(t *testing.T) {
			b := filledBAT(t, q, 120)
			ch := testChallenge(8)

			challenged, err := b.SelectChallenged(ch, true)
			if err != nil {
				t.Fatalf("SelectChallenged: %v", err)
			}
			proof, err := b.ProveAudit(ch, challenged)
			if err != nil {
				t.Fatalf("ProveAudit: %v", err)
			}
			ok, err := b.VerifyAudit(b.Root(), ch, proof)
			if err != nil {
				t.Fatalf("VerifyAudit: %v", err)
			}
			if !ok {
				t.Error("a valid audit proof was rejected")
			}
		})
	}
}

// TestAuditDetectsATamperedBlock is the fidelity checklist's most important
// item: "A tampered block is actually DETECTED".
//
// The prover audits honestly, then a block is changed underneath. The old proof
// must not verify against the new root — otherwise the audit is decorative.
func TestAuditDetectsATamperedBlock(t *testing.T) {
	b := filledBAT(t, 5, 100)
	ch := testChallenge(6)

	challenged, err := b.SelectChallenged(ch, true)
	if err != nil {
		t.Fatalf("SelectChallenged: %v", err)
	}
	proof, err := b.ProveAudit(ch, challenged)
	if err != nil {
		t.Fatalf("ProveAudit: %v", err)
	}

	// Tamper with a block the audit actually covers.
	target := challenged[0]
	if err := b.Bind(target, scalar(424242)); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	ok, err := b.VerifyAudit(b.Root(), ch, proof)
	if err == nil && ok {
		t.Error("an audit proof from before the tampering still verified")
	}
}

// TestAuditRejectsAForeignRoot is the same anchor check VerifyPath needs, and
// for the same reason: the aggregation proves openings against the prover's own
// commitments.
func TestAuditRejectsAForeignRoot(t *testing.T) {
	honest := filledBAT(t, 5, 60)
	forged := filledBAT(t, 5, 60)
	ch := testChallenge(5)

	challenged, err := forged.SelectChallenged(ch, true)
	if err != nil {
		t.Fatalf("SelectChallenged: %v", err)
	}
	proof, err := forged.ProveAudit(ch, challenged)
	if err != nil {
		t.Fatalf("ProveAudit: %v", err)
	}

	if ok, err := forged.VerifyAudit(forged.Root(), ch, proof); err != nil || !ok {
		t.Fatalf("the forged tree's own audit did not verify (%v); this test proves nothing", err)
	}
	if ok, err := honest.VerifyAudit(honest.Root(), ch, proof); err == nil && ok {
		t.Error("an audit from a different tree verified against the honest root")
	}
}

// TestAuditRejectsUnboundCoefficients keeps vc's cancellation forgery from being
// reachable through the audit path.
func TestAuditRejectsUnboundCoefficients(t *testing.T) {
	b := filledBAT(t, 5, 40)
	ch := testChallenge(4)

	challenged, err := b.SelectChallenged(ch, true)
	if err != nil {
		t.Fatalf("SelectChallenged: %v", err)
	}
	proof, err := b.ProveAudit(ch, challenged)
	if err != nil {
		t.Fatalf("ProveAudit: %v", err)
	}
	proof.Openings[0].Opening.Coeff = scalar(3)

	if _, err := b.VerifyAudit(b.Root(), ch, proof); err == nil {
		t.Error("an unbound coefficient was accepted")
	}
}

// TestAuditIsADifferentChallengeEachRound pins that the challenge is a real
// spot check. A selection that ignored phi_1 would let a prover precompute.
func TestAuditIsADifferentChallengeEachRound(t *testing.T) {
	b := filledBAT(t, 5, 200)

	a, err := b.SelectChallenged(Challenge{Z: 10, Phi1: []byte("round-1"), Phi2: []byte("c")}, true)
	if err != nil {
		t.Fatalf("SelectChallenged: %v", err)
	}
	c, err := b.SelectChallenged(Challenge{Z: 10, Phi1: []byte("round-2"), Phi2: []byte("c")}, true)
	if err != nil {
		t.Fatalf("SelectChallenged: %v", err)
	}

	same := true
	for i := range a {
		if a[i] != c[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("two different challenge seeds selected the same blocks")
	}
}

// TestChallengeSamplesWithoutReplacement pins that z distinct blocks are
// challenged. Repeats would raise z without widening the union, which would
// make the audit look cheaper per challenged block than it is.
func TestChallengeSamplesWithoutReplacement(t *testing.T) {
	b := filledBAT(t, 5, 200)
	sel, err := b.SelectChallenged(testChallenge(12), true)
	if err != nil {
		t.Fatalf("SelectChallenged: %v", err)
	}
	seen := map[int]bool{}
	for _, s := range sel {
		if seen[s] {
			t.Fatalf("block %d challenged twice", s)
		}
		seen[s] = true
	}
}

// TestPathUnionIsSmallerThanIndependentPaths is §4.1's claim, measured rather
// than assumed: sharing is where the optimisation comes from, so if the union
// equalled the sum of the path lengths there would be no optimisation.
func TestPathUnionIsSmallerThanIndependentPaths(t *testing.T) {
	b := filledBAT(t, 5, 300)
	ch := testChallenge(16)

	challenged, err := b.SelectChallenged(ch, true)
	if err != nil {
		t.Fatalf("SelectChallenged: %v", err)
	}
	proof, err := b.ProveAudit(ch, challenged)
	if err != nil {
		t.Fatalf("ProveAudit: %v", err)
	}

	independent := 0
	for _, s := range challenged {
		p, err := Path(s, b.q)
		if err != nil {
			t.Fatal(err)
		}
		independent += len(p) // one opening per node, plus the block itself
	}

	if proof.PathUnionSize >= independent {
		t.Errorf("union %d openings vs %d for independent paths — no sharing, so "+
			"the §4.1 optimisation is not happening", proof.PathUnionSize, independent)
	}
	t.Logf("z=%d: union %d openings against %d independent",
		len(challenged), proof.PathUnionSize, independent)
}

// TestOptimizedSelectionChallengesLeavesOnly pins what §4.1 actually does, and
// records what it does NOT do.
//
// The mechanism is f1's range: (q(1-q^{l-1})/(1-q), q(1-q^l)/(1-q)], which for
// q=5, l=4 is (155, 780] — exactly the level-4 node indices. So the optimisation
// restricts challenges to LEAVES. That is what this test asserts.
//
// WHAT IT DOES NOT DO IS SHRINK THE UNION AGAINST A UNIFORM SAMPLE, and an
// earlier version of this test wrongly asserted that it does. At q=5 with 400
// blocks the deepest level already holds 245 of them, so a uniform sample draws
// some SHALLOW blocks, whose paths are shorter — and the uniform union comes out
// slightly smaller (measured: 55 against 56). The optimisation buys full-depth
// coverage per challenge and a union bounded by depth, not a smaller union than
// uniform sampling.
//
// This matters for how Exp 3 reports the arm: presenting "optimised" as the
// cheaper configuration would be wrong. It is the configuration the paper
// measures, which is why it is enabled — not a cost win over uniform sampling.
func TestOptimizedSelectionChallengesLeavesOnly(t *testing.T) {
	const q, blocks = 5, 400
	b := filledBAT(t, q, blocks)
	ch := testChallenge(16)

	sel, err := b.SelectChallenged(ch, true)
	if err != nil {
		t.Fatalf("SelectChallenged: %v", err)
	}

	deepest, err := Level(blocks, q)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sel {
		l, err := Level(s, q)
		if err != nil {
			t.Fatal(err)
		}
		if l != deepest {
			t.Errorf("optimised auditing challenged block %d at level %d, not the "+
				"leaf level %d; f1's range is the leaf level exactly", s, l, deepest)
		}
	}

	// The union must still be bounded by depth rather than by z.
	proof, err := b.ProveAudit(ch, sel)
	if err != nil {
		t.Fatalf("ProveAudit: %v", err)
	}
	if maxUnion := len(sel) * (deepest + 1); proof.PathUnionSize > maxUnion {
		t.Errorf("union %d exceeds z*(depth+1) = %d", proof.PathUnionSize, maxUnion)
	}

	// Recorded, deliberately not asserted — see the comment above.
	plainSel, err := b.SelectChallenged(ch, false)
	if err != nil {
		t.Fatalf("SelectChallenged(false): %v", err)
	}
	plainProof, err := b.ProveAudit(ch, plainSel)
	if err != nil {
		t.Fatalf("ProveAudit: %v", err)
	}
	t.Logf("union size: optimised %d (all at level %d), uniform %d — the "+
		"optimisation buys full-depth coverage, not a smaller union",
		proof.PathUnionSize, deepest, plainProof.PathUnionSize)
}

// TestAuditCostTracksUnionNotLedgerSize is Exp 3's central claim in miniature.
// Ten times the ledger, same challenge size: the union must not grow with the
// ledger, only with depth.
func TestAuditCostTracksUnionNotLedgerSize(t *testing.T) {
	ch := testChallenge(8)

	union := func(blocks int) (int, int) {
		b := filledBAT(t, 5, blocks)
		sel, err := b.SelectChallenged(ch, true)
		if err != nil {
			t.Fatalf("SelectChallenged: %v", err)
		}
		proof, err := b.ProveAudit(ch, sel)
		if err != nil {
			t.Fatalf("ProveAudit: %v", err)
		}
		depth, err := Level(blocks, 5)
		if err != nil {
			t.Fatal(err)
		}
		return proof.PathUnionSize, depth
	}

	small, dSmall := union(50)
	large, dLarge := union(500)
	t.Logf("50 blocks (depth %d): union %d | 500 blocks (depth %d): union %d",
		dSmall, small, dLarge, large)

	// The ledger grew 10x. The union may grow with DEPTH, which grows
	// logarithmically, but must not grow anywhere near linearly.
	if large > small*3 {
		t.Errorf("union grew from %d to %d for a 10x larger ledger; audit cost "+
			"is tracking ledger size, which is the opposite of Ref[13]'s claim",
			small, large)
	}
}

// TestVerifyAuditRejectsAMalformedProof covers the same node appearing with two
// different commitments — a proof that is not describing one tree.
func TestVerifyAuditRejectsAMalformedProof(t *testing.T) {
	b := filledBAT(t, 5, 60)
	ch := testChallenge(6)

	challenged, err := b.SelectChallenged(ch, true)
	if err != nil {
		t.Fatalf("SelectChallenged: %v", err)
	}
	proof, err := b.ProveAudit(ch, challenged)
	if err != nil {
		t.Fatalf("ProveAudit: %v", err)
	}

	// Find two openings on the same node and give one a different commitment.
	byNode := map[int][]int{}
	for i, po := range proof.Openings {
		byNode[po.Node] = append(byNode[po.Node], i)
	}
	var idx int = -1
	for _, ids := range byNode {
		if len(ids) >= 2 {
			idx = ids[1]
			break
		}
	}
	if idx < 0 {
		t.Skip("no node appeared twice in this union")
	}
	other, err := b.Commitment(0)
	if err != nil {
		t.Fatal(err)
	}
	proof.Openings[idx].Opening.C = other

	if _, err := b.VerifyAudit(b.Root(), ch, proof); err == nil {
		t.Error("a proof presenting two commitments for one node was accepted")
	}
}
