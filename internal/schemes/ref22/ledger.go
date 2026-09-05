package ref22

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"

	"zkredact/pkg/accumulator"
	"zkredact/pkg/ch"
)

// Block is Ref[22]'s B = <p, m, i, A, w, ctr, xi> (§III-A).
type Block struct {
	Prev   []byte // p — hash of the preceding block
	Merkle []byte // m — Merkle root of transactions
	Seq    uint64 // i — globally unique sequence number
	// AccState (A) and Witness (w) are the accumulator state and witness AS OF
	// THIS BLOCK'S CREATION. They are covered by the chameleon hash and are
	// therefore immutable: refreshing them would change cont and invalidate h,
	// which is what "the chain no longer verifies after an append" looked like
	// before this was separated out.
	//
	// The CURRENT witness — the one membership is actually checked against —
	// lives in the ledger, not the block, because an RSA accumulator
	// invalidates every outstanding witness on any update.
	AccState []byte                    // A
	Witness  []byte                    // w
	Ctr      uint64                    // ctr — PoW counter; see the deviation note on difficulty
	Check    ch.DoubleTrapdoorChecking // xi — chameleon-hash checking string

	// Hash is the chameleon hash h of the block's content. It is part of the
	// block: a redaction produces a COLLISION, so h is unchanged while the
	// content and xi both change. Verification checks that (content, xi) still
	// hash to this h, which is what makes an edit outside CH.Adapt detectable.
	Hash *ch.Value

	// Handle retains the CH adaptation handle. The ledger OWNER holds it; it is
	// not part of the block a verifier sees.
	handle *ch.DoubleTrapdoorHandle

	// Payload is the redactable content the chameleon hash covers.
	Payload []byte

	// Deleted marks a block removed by Algorithm 7. The block stays in the
	// chain — Ref[22] deletes CONTENT, not structure — so the linkage p still
	// resolves and ValChain still traverses it.
	Deleted bool
}

// Content is cont = p ‖ m ‖ i ‖ A ‖ w, the string the chameleon hash covers.
func (b *Block) Content() []byte {
	var seq, ctr [8]byte
	binary.BigEndian.PutUint64(seq[:], b.Seq)
	binary.BigEndian.PutUint64(ctr[:], b.Ctr)

	out := make([]byte, 0, len(b.Prev)+len(b.Merkle)+8+len(b.AccState)+len(b.Witness)+len(b.Payload))
	out = append(out, b.Prev...)
	out = append(out, b.Merkle...)
	out = append(out, seq[:]...)
	out = append(out, b.AccState...)
	out = append(out, b.Witness...)
	out = append(out, b.Payload...)
	return out
}

// element is the accumulator element for a block VERSION.
//
// It binds the sequence number AND the payload, so a redaction produces a
// different element. Binding only the sequence number would make Modify's
// UA.Del/UA.Add pair a no-op — the same element removed and re-added — and a
// reverted block would still verify.
func (b *Block) element() []byte {
	h := sha256.New()
	h.Write([]byte("ref22/block"))
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], b.Seq)
	h.Write(seq[:])
	h.Write(b.Merkle)
	h.Write(b.Payload)
	if b.Deleted {
		h.Write([]byte("deleted"))
	}
	return h.Sum(nil)
}

// hash is the value the successor's linkage field p holds.
//
// IT IS THE CHAMELEON HASH, not a hash of the content. That is the whole point
// of a redactable chain: CH.Adapt produces a COLLISION, so h survives a
// redaction unchanged and every downstream link still resolves.
//
// Hashing the content instead makes the chain break at the block after every
// redaction — which is what happened here, and it reads as a linkage bug rather
// than as the chameleon hash having been bypassed.
func (b *Block) hash() []byte {
	if b.Hash == nil {
		return make([]byte, sha256.Size)
	}
	h := sha256.New()
	h.Write([]byte("ref22/link"))
	h.Write(b.Hash.X.Bytes())
	h.Write(b.Hash.Y.Bytes())
	return h.Sum(nil)
}

// ledger is Ref[22]'s chain plus its accumulator.
type ledger struct {
	curve elliptic.Curve
	key   *ch.DoubleTrapdoorKey
	acc   *accumulator.Accumulator

	blocks []*Block

	// current maps a block's accumulator element to its witness against the
	// CURRENT accumulator state. Maintained by the ledger owner, which is whose
	// job witness upkeep is in an RSA accumulator.
	current map[string]*big.Int
}

// newLedger prepares an empty chain.
func newLedger(curve elliptic.Curve, key *ch.DoubleTrapdoorKey, acc *accumulator.Accumulator) *ledger {
	return &ledger{curve: curve, key: key, acc: acc, current: map[string]*big.Int{}}
}

// Append is Algorithm 1.
//
// Each block is chameleon-hashed over cont and accumulated, and the accumulator
// state it commits to is the chain up to and including itself.
func (l *ledger) Append(merkle, payload []byte) (*Block, error) {
	var prev []byte
	if n := len(l.blocks); n > 0 {
		prev = l.blocks[n-1].hash()
	} else {
		prev = make([]byte, sha256.Size)
	}

	b := &Block{
		Prev:    prev,
		Merkle:  merkle,
		Seq:     uint64(len(l.blocks)),
		Payload: payload,
	}

	// Accumulate the block, then record the state and witness INTO the block.
	// The order matters: A is "the accumulator state of the chain up to B", so
	// it must include B itself.
	witness, err := l.acc.Add(b.element())
	if err != nil {
		return nil, fmt.Errorf("ref22: accumulate block %d: %w", b.Seq, err)
	}
	b.AccState = l.acc.State().Bytes()
	b.Witness = witness.Bytes()

	handle, check, err := l.key.HGen(b.Content(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ref22: chameleon hash for block %d: %w", b.Seq, err)
	}
	b.handle = handle
	b.Check = check
	b.Hash = handle.Hash

	l.blocks = append(l.blocks, b)
	return b, nil
}

// Finalize refreshes every witness after a run of appends.
//
// NOT called from Append. Each Add invalidates every outstanding witness, so
// regenerating inside Append would cost O(n^2 log n) over a chain — building the
// 10,000-block ledger Exp 3 needs would take longer than the experiment. The
// chain is built first and the witnesses computed once, which is the same set
// of witnesses for a fraction of the work.
//
// Redactions still regenerate immediately, because there the cost is real:
// Ref[22]'s Modify genuinely pays witness maintenance on every edit.
func (l *ledger) Finalize() error { return l.regenerateWitnesses() }

// ValApp is Algorithm 2: validate one appended block.
//
// Flat in chain length, which is what the paper reports and what Exp 3
// contrasts with ValChain.
func (l *ledger) ValApp(b *Block) error {
	if b.Hash == nil {
		return fmt.Errorf("ref22: block %d carries no chameleon hash", b.Seq)
	}
	if !l.key.Verify(b.Hash, b.Content(), b.Check) {
		return fmt.Errorf("ref22: block %d: chameleon hash does not verify", b.Seq)
	}
	w, ok := l.current[string(b.element())]
	if !ok {
		return fmt.Errorf("ref22: block %d has no current accumulator witness", b.Seq)
	}
	// With the published nonce, so verification is one primality test rather
	// than a ~177-candidate search. Searching per block made ledger
	// construction O(n) searches and took minutes for 200 blocks.
	nonce, ok2 := l.acc.Nonce(b.element())
	if !ok2 {
		return fmt.Errorf("ref22: block %d has no prime nonce", b.Seq)
	}
	ok, err := accumulator.VerifyMembershipWithNonce(
		l.acc.Modulus(), l.acc.State(), w, b.element(), nonce)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("ref22: block %d: accumulator membership does not verify", b.Seq)
	}
	return nil
}

// Modify is Algorithm 5.
//
// CH.Adapt produces a collision for the new content, then UA.Del invalidates the
// prior version and UA.Add accumulates the new one. Both accumulator operations
// are required: adapting alone would leave the superseded version accumulated,
// and a reverted block would still verify.
func (l *ledger) Modify(seq uint64, newPayload []byte) error {
	if seq >= uint64(len(l.blocks)) {
		return fmt.Errorf("ref22: block %d is not in the chain", seq)
	}
	b := l.blocks[seq]

	oldElement := b.element()

	// The content changes with the payload, so the adaptation is over the new
	// content string.
	prevPayload := b.Payload
	b.Payload = newPayload

	check, err := l.key.Adapt(b.handle, b.Content(), rand.Reader)
	if err != nil {
		b.Payload = prevPayload
		return fmt.Errorf("ref22: adapt block %d: %w", seq, err)
	}
	b.Check = check

	// UA.Del then UA.Add — the pair that makes the redaction detectable.
	if err := l.acc.Delete(oldElement); err != nil {
		return fmt.Errorf("ref22: UA.Del for block %d: %w", seq, err)
	}
	witness, err := l.acc.Add(b.element())
	if err != nil {
		return fmt.Errorf("ref22: UA.Add for block %d: %w", seq, err)
	}

	// The block's recorded A and w are covered by the chameleon hash, so they
	// stay as adapted. Current witnesses are refreshed below.
	_ = witness

	// Every other block's witness is now stale: an RSA accumulator invalidates
	// them on any update. Regenerating them is part of what Modify costs, and
	// skipping it would make ValChain fail for reasons unrelated to redaction.
	return l.regenerateWitnesses()
}

// ValMod is Algorithm 6: validate one modified block, including that the
// SUPERSEDED version is provably gone.
func (l *ledger) ValMod(b *Block, supersededElement []byte) error {
	if err := l.ValApp(b); err != nil {
		return err
	}
	if supersededElement == nil {
		return nil
	}

	aCoef, d, err := l.acc.NonMembershipWitness(supersededElement)
	if err != nil {
		return fmt.Errorf("ref22: block %d: superseded version is still accumulated: %w", b.Seq, err)
	}
	ok, err := accumulator.VerifyNonMembership(
		l.acc.Modulus(), l.acc.Generator(), l.acc.State(), aCoef, d, supersededElement)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("ref22: block %d: cannot prove the superseded version was removed", b.Seq)
	}
	return nil
}

// Delete is Algorithm 7 over a set L.
//
// H_prime is computed for EVERY deleted block, and one CH.Adapt runs BEHIND
// each consecutive subset — on the block that follows the run, whose linkage p
// is re-pointed past the whole run at once.
//
// That is why the delete set's STRUCTURE drives the cost: a consecutive run of
// 8 costs one adaptation, eight scattered blocks cost eight. Exp 2 sweeps the
// structure for exactly this reason, and an implementation that adapted once
// per block would erase the distinction the experiment exists to measure.
func (l *ledger) Delete(positions []uint64) (adaptations int, err error) {
	if len(positions) == 0 {
		return 0, nil
	}

	// H_prime per deleted block, multiplied over the set. Computing one hash
	// for the whole set instead would make a large delete set cost the same as
	// a small one.
	product := big.NewInt(1)
	for _, seq := range positions {
		if seq >= uint64(len(l.blocks)) {
			return 0, fmt.Errorf("ref22: block %d is not in the chain", seq)
		}
		product.Mul(product, hPrime(l.blocks[seq]))
	}
	_ = product

	removed := make(map[uint64]bool, len(positions))
	for _, seq := range positions {
		removed[seq] = true
	}

	// Accumulator first: every deleted version must stop verifying, or a
	// removed block could be presented with its old witness and re-accepted.
	for seq := range removed {
		if err := l.acc.Delete(l.blocks[seq].element()); err != nil {
			return adaptations, fmt.Errorf("ref22: UA.Del for block %d: %w", seq, err)
		}
	}

	// Excise the runs and re-link behind each.
	runs := consecutiveRuns(positions)
	kept := make([]*Block, 0, len(l.blocks))
	for _, b := range l.blocks {
		if !removed[b.Seq] {
			kept = append(kept, b)
		}
	}

	for _, run := range runs {
		successor := findSuccessor(kept, run[len(run)-1])
		if successor == nil {
			// The run is a suffix: nothing links past it, so no adaptation.
			continue
		}

		// The block before the run, or the genesis marker if the run starts the
		// chain.
		var newPrev []byte
		if pred := findPredecessor(kept, run[0]); pred != nil {
			newPrev = pred.hash()
		} else {
			newPrev = make([]byte, sha256.Size)
		}

		successor.Prev = newPrev
		check, err := l.key.Adapt(successor.handle, successor.Content(), rand.Reader)
		if err != nil {
			return adaptations, fmt.Errorf(
				"ref22: adapt block %d behind the run ending at %d: %w",
				successor.Seq, run[len(run)-1], err)
		}
		successor.Check = check
		adaptations++
	}

	l.blocks = kept
	if err := l.regenerateWitnesses(); err != nil {
		return adaptations, err
	}
	return adaptations, nil
}

// findSuccessor returns the first surviving block after seq.
func findSuccessor(blocks []*Block, seq uint64) *Block {
	for _, b := range blocks {
		if b.Seq > seq {
			return b
		}
	}
	return nil
}

// findPredecessor returns the last surviving block before seq.
func findPredecessor(blocks []*Block, seq uint64) *Block {
	var out *Block
	for _, b := range blocks {
		if b.Seq < seq {
			out = b
		}
	}
	return out
}

// ValDel is Algorithm 8.
// ValDel is Algorithm 8: confirm a block really was deleted.
//
// Positive evidence, not merely absence: the accumulator must be able to PROVE
// the removed version is gone. Checking only that the block is missing from the
// slice would pass for a block that was never accumulated at all.
func (l *ledger) ValDel(deletedElement []byte) error {
	aCoef, d, err := l.acc.NonMembershipWitness(deletedElement)
	if err != nil {
		return fmt.Errorf("ref22: deleted version is still accumulated: %w", err)
	}
	ok, err := accumulator.VerifyNonMembership(
		l.acc.Modulus(), l.acc.Generator(), l.acc.State(), aCoef, d, deletedElement)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("ref22: cannot prove the deleted version was removed")
	}
	return nil
}

// ValChain is Algorithm 9: validate the WHOLE chain.
//
// EXP 3 COMPARES AGAINST THIS COST, so it must genuinely traverse every block.
// No cache, no early exit, no memoised accumulator state. Its linear growth is
// the property being measured, and hiding it would understate ZK-Redact's
// advantage while making this baseline look better than the design is.
func (l *ledger) ValChain() (blocksVisited int, err error) {
	var prev []byte
	for i, b := range l.blocks {
		blocksVisited++

		// Linkage: every block's p must be its SURVIVING predecessor's hash.
		// After a deletion the successor was re-linked past the removed run, so
		// this walks the chain as it now stands.
		if i == 0 {
			prev = make([]byte, sha256.Size)
		}
		if string(b.Prev) != string(prev) {
			return blocksVisited, fmt.Errorf("ref22: block %d breaks the chain linkage", b.Seq)
		}

		if err := l.ValApp(b); err != nil {
			return blocksVisited, err
		}
		prev = b.hash()
	}
	return blocksVisited, nil
}

// regenerateWitnesses refreshes every block's membership witness.
//
// Required after any accumulator update: RSA accumulators invalidate all
// outstanding witnesses. This is real work Ref[22] pays on every redaction, and
// it is one reason its Modify cost is not flat.
func (l *ledger) regenerateWitnesses() error {
	// Computed as a batch. One witness at a time is O(n^2) exponentiations, and
	// Exp 3 builds ledgers of 10,000 blocks — at which point this baseline
	// could not be constructed, never mind measured.
	witnesses, err := l.acc.AllMembershipWitnesses()
	if err != nil {
		return fmt.Errorf("ref22: regenerate witnesses: %w", err)
	}
	for _, b := range l.blocks {
		w, ok := witnesses[string(b.element())]
		if !ok {
			return fmt.Errorf("ref22: block %d is not accumulated", b.Seq)
		}
		// Into the ledger's map, NOT into the block: the block's w is covered by
		// the chameleon hash and must not move.
		l.current[string(b.element())] = w
	}
	return nil
}

// hPrime is H'(B), the per-block value Algorithm 7 multiplies over the delete
// set.
func hPrime(b *Block) *big.Int {
	h := sha256.New()
	h.Write([]byte("ref22/hprime"))
	h.Write(b.Content())
	return new(big.Int).SetBytes(h.Sum(nil))
}

// consecutiveRuns splits a delete set into maximal consecutive runs.
//
// One CH.Adapt runs per run, so the split IS the cost model: a consecutive set
// of 8 costs one adaptation, an inconsecutive set of 8 costs eight. Exp 2 sweeps
// the structure for exactly this reason.
func consecutiveRuns(positions []uint64) [][]uint64 {
	if len(positions) == 0 {
		return nil
	}
	sorted := append([]uint64(nil), positions...)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j] < sorted[j-1]; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}

	var runs [][]uint64
	cur := []uint64{sorted[0]}
	for i := 1; i < len(sorted); i++ {
		if sorted[i] == sorted[i-1]+1 {
			cur = append(cur, sorted[i])
			continue
		}
		runs = append(runs, cur)
		cur = []uint64{sorted[i]}
	}
	return append(runs, cur)
}
