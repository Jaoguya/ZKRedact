package ref13

import (
	"fmt"

	"zkredact/pkg/ch"
	"zkredact/pkg/vc"
)

// Eq. 12 — the chameleon-hash correctness check.
//
//	ch_s =? (X · Y_s)^{H1(h_{s-1} ‖ m_s, Y_s)} · g1^{r_s}
//
// WHY BOTH CHECKS ARE NEEDED, AND WHAT EACH ONE MISSES ALONE.
//
// Eq. 11 proves that the BAT root commits to m_s. It says nothing about whether
// m_s is a value anyone could legitimately have produced: a prover that invents
// a digest, commits to it, and updates the path has a perfectly valid Eq. 11
// proof for content that was never chameleon-hashed.
//
// Eq. 12 proves the opposite half: that (content, r_s, Y_s) really do hash to
// the ch_s the chain is built on. On its own that is equally insufficient — it
// binds nothing to the tree, so an old valid block could be replayed.
//
// Together they chain: root -> C_s -> m_s -> a chameleon hash that validates.
// docs/baselines/ref13-vrbc.md states the measurement boundary for both Exp 3
// protocols as "Both Eq. 11 and Eq. 12 verified", so stopping at the pairing
// check would report a cheaper verifier than the scheme specifies — the
// "looks fast because it checks less" failure this project guards against.
//
// THE LINK BETWEEN THEM IS LOAD-BEARING. Checking Eq. 12 on some block while
// Eq. 11 proved a different one verifies two unrelated statements. So
// verifyBlock re-derives m_s from the evidence and requires it to equal the
// value the aggregate actually opened.

// blockEvidence is what a prover sends per challenged block: Algorithm 2's
// output (h_{s-1}, ch_s, m_s, Y_s, r_s) for that block.
type blockEvidence struct {
	Seq int

	// PrevHash is h_{s-1}, the context the chameleon hash was bound to.
	PrevHash []byte

	// Core and Redactable are the block content. m_s is re-derived from them
	// rather than taken on trust, so a prover cannot send content that differs
	// from the digest it proved.
	Core       []byte
	Redactable []byte

	// Randomness is (r_s, Y_s); Value is ch_s.
	Randomness ch.EphemeralRandomness
	Value      *ch.Value
}

// evidenceFor collects what a verifier needs for one block.
func (s *Scheme) evidenceFor(seq int) (blockEvidence, error) {
	if seq < 1 || seq > len(s.blocks) {
		return blockEvidence{}, fmt.Errorf("ref13: block %d does not exist", seq)
	}
	b := s.blocks[seq-1]
	return blockEvidence{
		Seq:        b.seq,
		PrevHash:   b.prevHash,
		Core:       b.core,
		Redactable: b.redactable,
		Randomness: b.randomness,
		Value:      b.value,
	}, nil
}

// verifyBlock runs Eq. 12 and ties it to what Eq. 11 opened.
//
// openings is the aggregate's opening set; the value proved for this block is
// the one at (node = seq, position 1).
func (s *Scheme) verifyBlock(ev blockEvidence, openings []PathOpening) (bool, error) {
	// Re-derive m_s from the content. Taking the prover's digest on trust would
	// let it send one thing and prove another.
	digest := blockDigest(ev.Core, ev.Redactable)

	// The digest must be exactly what the aggregate opened for this block, or
	// Eq. 11 and Eq. 12 are about different data.
	var proved *vc.Opening
	for i := range openings {
		if openings[i].Node == ev.Seq && openings[i].Opening.Pos == 1 {
			proved = &openings[i].Opening
			break
		}
	}
	if proved == nil {
		return false, fmt.Errorf(
			"ref13: no opening for block %d, so Eq. 12 would check data the "+
				"aggregate never proved", ev.Seq)
	}
	want := scalarOf(digest)
	if !proved.Value.Equal(&want) {
		return false, nil
	}

	// Eq. 12 itself: does (m_s, r_s, Y_s) hash to ch_s under h_{s-1}?
	blockCtx := blockContext(ev.Seq, ev.PrevHash)
	return s.key.Verify(blockCtx, digest, ev.Randomness, ev.Value), nil
}

// verifyAllBlocks runs Eq. 12 over every challenged block.
//
// One failure fails the audit. It does NOT exit early: the cost of verifying
// every block is the cost the paper's boundary describes, and a verifier that
// stopped at the first bad block would make a corrupted ledger the cheapest
// case in the study.
func (s *Scheme) verifyAllBlocks(evidence []blockEvidence, openings []PathOpening) (bool, error) {
	allOK := true
	for _, ev := range evidence {
		ok, err := s.verifyBlock(ev, openings)
		if err != nil {
			return false, err
		}
		if !ok {
			allOK = false
		}
	}
	return allOK, nil
}
