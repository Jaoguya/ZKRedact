package ref22

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"zkredact/pkg/accumulator"
	"zkredact/pkg/ch"
)

// A small modulus keeps the suite fast. The configured 3072-bit path is checked
// in pkg/accumulator, and Setup refuses anything below it.
const testAccBits = 512

func testLedger(t *testing.T, blocks int) *ledger {
	t.Helper()

	curve := elliptic.P256()
	key, err := ch.DoubleTrapdoorKeyGen(curve, rand.Reader)
	if err != nil {
		t.Fatalf("DoubleTrapdoorKeyGen: %v", err)
	}
	n, err := accumulator.GenerateUntrusted(testAccBits)
	if err != nil {
		t.Fatalf("GenerateUntrusted: %v", err)
	}
	acc, err := accumulator.New(accumulator.Config{Bits: testAccBits, Modulus: n})
	if err != nil {
		t.Fatalf("accumulator.New: %v", err)
	}

	l := newLedger(curve, key, acc)
	for i := 0; i < blocks; i++ {
		if _, err := l.Append(
			[]byte(fmt.Sprintf("merkle-%d", i)),
			[]byte(fmt.Sprintf("payload-%d", i)),
		); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	if err := l.Finalize(); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	return l
}

// -----------------------------------------------------------------------------
// Algorithms 1 and 2
// -----------------------------------------------------------------------------

func TestAppendedBlocksValidate(t *testing.T) {
	l := testLedger(t, 5)
	for _, b := range l.blocks {
		if err := l.ValApp(b); err != nil {
			t.Errorf("ValApp(block %d): %v", b.Seq, err)
		}
	}
}

func TestChainLinkageHolds(t *testing.T) {
	l := testLedger(t, 5)
	visited, err := l.ValChain()
	if err != nil {
		t.Fatalf("ValChain: %v", err)
	}
	if visited != 5 {
		t.Errorf("ValChain visited %d blocks, want 5", visited)
	}
}

// TestTamperedBlockIsRejected is the negative control: without it a ValApp that
// always returned nil would pass everything above.
func TestTamperedBlockIsRejected(t *testing.T) {
	l := testLedger(t, 3)
	l.blocks[1].Payload = []byte("tampered")

	if err := l.ValApp(l.blocks[1]); err == nil {
		t.Fatal("a block edited outside CH.Adapt validated; the chameleon hash is " +
			"not binding anything")
	}
}

// -----------------------------------------------------------------------------
// Algorithms 5 and 6 — Modify, and the reversion it must prevent
// -----------------------------------------------------------------------------

func TestModifyProducesAValidChain(t *testing.T) {
	l := testLedger(t, 5)
	if err := l.Modify(2, []byte("redacted")); err != nil {
		t.Fatalf("Modify: %v", err)
	}
	if _, err := l.ValChain(); err != nil {
		t.Fatalf("ValChain after Modify: %v", err)
	}
	if string(l.blocks[2].Payload) != "redacted" {
		t.Error("the payload was not replaced")
	}
}

// TestModifyInvalidatesTheSupersededVersion is the fidelity check that carries
// the most weight for this baseline.
//
// If UA.Del does not genuinely invalidate, an adversary presents the OLD block
// with its OLD witness and the redaction is silently undone. A hash-set stand-in
// for the accumulator passes every other test in this file.
func TestModifyInvalidatesTheSupersededVersion(t *testing.T) {
	l := testLedger(t, 5)

	target := l.blocks[2]
	supersededElement := target.element()
	staleWitness := append([]byte(nil), target.Witness...)

	if err := l.Modify(2, []byte("redacted")); err != nil {
		t.Fatalf("Modify: %v", err)
	}

	// The pre-redaction witness must no longer verify.
	ok, err := accumulator.VerifyMembership(
		l.acc.Modulus(), l.acc.State(), bigFromBytes(staleWitness), supersededElement)
	if err != nil {
		t.Fatalf("VerifyMembership: %v", err)
	}
	if ok {
		t.Fatal("the superseded version still verifies against the accumulator: a " +
			"reverted block would be accepted and the redaction undone")
	}

	// And ValMod must be able to PROVE it is gone.
	if err := l.ValMod(l.blocks[2], supersededElement); err != nil {
		t.Fatalf("ValMod cannot prove the superseded version was removed: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Algorithms 7 and 8 — Delete
// -----------------------------------------------------------------------------

// TestDeleteSetStructureDrivesAdaptationCount pins the cost model Exp 2 sweeps:
// one CH.Adapt per CONSECUTIVE run, not one per block.
//
// A implementation that adapted once per block would make consecutive and
// inconsecutive delete sets cost the same, erasing the distinction the
// experiment is built to measure.
func TestDeleteSetStructureDrivesAdaptationCount(t *testing.T) {
	cases := []struct {
		name      string
		positions []uint64
		want      int
	}{
		{"one consecutive run of 4", []uint64{1, 2, 3, 4}, 1},
		{"four isolated blocks", []uint64{1, 3, 5, 7}, 4},
		{"two runs", []uint64{1, 2, 5, 6}, 2},
		{"unsorted input, one run", []uint64{4, 2, 3, 1}, 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := testLedger(t, 10)
			got, err := l.Delete(tc.positions)
			if err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if got != tc.want {
				t.Errorf("%d CH.Adapt calls, want %d — the delete-set structure is "+
					"not driving the cost, so Exp 2's consecutive/inconsecutive "+
					"sweep would measure nothing", got, tc.want)
			}
		})
	}
}

func TestDeletedBlocksAreExcisedAndTheChainRelinks(t *testing.T) {
	l := testLedger(t, 8)

	gone := [][]byte{l.blocks[2].element(), l.blocks[3].element()}

	if _, err := l.Delete([]uint64{2, 3}); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Positive evidence that each removed version is provably gone.
	for i, el := range gone {
		if err := l.ValDel(el); err != nil {
			t.Errorf("ValDel(deleted %d): %v", i, err)
		}
	}

	// The survivors must relink: the block behind the run was adapted to point
	// past it, so the chain still verifies end to end.
	visited, err := l.ValChain()
	if err != nil {
		t.Fatalf("ValChain after Delete: %v", err)
	}
	if visited != 6 {
		t.Errorf("ValChain visited %d blocks after deleting 2 of 8, want 6", visited)
	}
}

// TestValDelRefusesALiveBlock is the negative control: without it a ValDel that
// always returned nil would pass the test above.
func TestValDelRefusesALiveBlock(t *testing.T) {
	l := testLedger(t, 3)
	if err := l.ValDel(l.blocks[1].element()); err == nil {
		t.Fatal("a block that is still in the chain passed ValDel")
	}
}

// -----------------------------------------------------------------------------
// Algorithm 9 — the linear-scan baseline Exp 3 compares against
// -----------------------------------------------------------------------------

// TestValChainCostGrowsWithChainLength is the guard against an accidental cache.
//
// ValChain's linear cost IS the property Exp 3 measures. Memoising it would make
// this baseline look flat, understate ZK-Redact's advantage, and leave no other
// test failing.
func TestValChainCostGrowsWithChainLength(t *testing.T) {
	short := testLedger(t, 4)
	long := testLedger(t, 32)

	sv, err := short.ValChain()
	if err != nil {
		t.Fatalf("ValChain(short): %v", err)
	}
	lv, err := long.ValChain()
	if err != nil {
		t.Fatalf("ValChain(long): %v", err)
	}

	if sv != 4 || lv != 32 {
		t.Fatalf("visited %d and %d blocks, want 4 and 32", sv, lv)
	}

	// Re-running must cost the same again: a cache would make the second pass
	// cheap, and Exp 3 would report a flat curve.
	again, err := long.ValChain()
	if err != nil {
		t.Fatalf("ValChain(long, second pass): %v", err)
	}
	if again != lv {
		t.Errorf("a second ValChain visited %d blocks against %d on the first: "+
			"results are being cached, and the linear cost Exp 3 measures would "+
			"disappear", again, lv)
	}
}

func TestBrokenLinkageIsDetected(t *testing.T) {
	l := testLedger(t, 5)
	l.blocks[3].Prev = []byte("not the predecessor's hash")

	if _, err := l.ValChain(); err == nil {
		t.Fatal("a broken chain linkage validated")
	}
}

// Algorithm 7 lines 17-23 build four non-interactive proofs inside Delete, and
// Algorithm 8's ValDel returns nothing but their conjunction. They were absent:
// the product eta_hat_1 was computed and discarded, and ValDel checked
// something else entirely.
func TestDeleteProducesVerifiableProofs(t *testing.T) {
	l := testLedger(t, 8)

	if _, err := l.Delete([]uint64{2, 3}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if l.lastDeletion == nil {
		t.Fatal("Delete recorded no proof; w_i is empty")
	}
	p := l.lastDeletion
	if p.Q1 == nil || p.Q2 == nil || p.Q3 == nil {
		t.Fatalf("w_i is incomplete: Q1=%v Q2=%v Q3=%v", p.Q1 != nil, p.Q2 != nil, p.Q3 != nil)
	}
	if p.Eta1 == nil || p.Eta1.Sign() <= 0 {
		t.Error("eta_hat_1 was not carried into the proof")
	}

	ok, err := l.VerifyDeletion(p)
	if err != nil {
		t.Fatalf("VerifyDeletion: %v", err)
	}
	if !ok {
		t.Error("a genuine deletion proof failed verification")
	}
}

// The proof must be able to REJECT, or it is decoration on the cost curve.
func TestDeletionProofRejectsTampering(t *testing.T) {
	l := testLedger(t, 8)
	if _, err := l.Delete([]uint64{4}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	genuine := l.lastDeletion

	for _, tc := range []struct {
		name  string
		alter func(*deletionProof) *deletionProof
	}{
		{"Q1 replaced", func(p *deletionProof) *deletionProof {
			c := *p
			c.Q1 = &accumulator.PoE{Q: big.NewInt(2)}
			return &c
		}},
		{"eta_hat_1 altered", func(p *deletionProof) *deletionProof {
			c := *p
			c.Eta1 = new(big.Int).Add(p.Eta1, big.NewInt(1))
			return &c
		}},
		{"Q3 residue altered", func(p *deletionProof) *deletionProof {
			c := *p
			q := *p.Q3
			q.R = new(big.Int).Add(q.R, big.NewInt(1))
			c.Q3 = &q
			return &c
		}},
		{"prior state fabricated", func(p *deletionProof) *deletionProof {
			// The distinction that makes binding to the LEDGER's states matter.
			// A verifier that recomputes w as StateBar^Eta1 accepts any
			// StateBefore, because it never looks at the one it was given —
			// so a deletion could claim to have started from a chain state
			// that never existed.
			c := *p
			c.StateBefore = new(big.Int).Mul(p.StateBefore, big.NewInt(3))
			return &c
		}},
		{"post state fabricated", func(p *deletionProof) *deletionProof {
			c := *p
			c.StateAfter = new(big.Int).Mul(p.StateAfter, big.NewInt(3))
			return &c
		}},
		{"nu altered", func(p *deletionProof) *deletionProof {
			c := *p
			c.Nu = new(big.Int).Add(p.Nu, big.NewInt(1))
			return &c
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := l.VerifyDeletion(tc.alter(genuine))
			if err == nil && ok {
				t.Errorf("accepted a tampered deletion proof")
			}
		})
	}

	if ok, _ := l.VerifyDeletion(nil); ok {
		t.Error("accepted a missing deletion proof")
	}
}

// A larger delete set means a larger eta_hat_1, which is the whole reason the
// proof is succinct rather than a direct exponentiation.
func TestDeletionProofScalesWithTheDeleteSet(t *testing.T) {
	small := testLedger(t, 12)
	large := testLedger(t, 12)

	if _, err := small.Delete([]uint64{3}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := large.Delete([]uint64{3, 5, 7, 9}); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if small.lastDeletion.Eta1.BitLen() >= large.lastDeletion.Eta1.BitLen() {
		t.Errorf("eta_hat_1 did not grow with the delete set: %d bits for 1 block, %d for 4",
			small.lastDeletion.Eta1.BitLen(), large.lastDeletion.Eta1.BitLen())
	}
}
