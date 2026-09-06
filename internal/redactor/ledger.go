// Package redactor implements ZK-Redact's Phase 4: batch-verified redaction
// and provenance generation, executed against the permissioned blockchain.
//
// Spec: Reference/ZK-Redact Scheme/ZK-Redact.md, Phase 4.
//
// THE COST SPLIT IS THE POINT. Phase 4 is explicit that CH adaptation is
// per-request and cannot be amortised, while chaincode, validation, commitment
// and ledger processing are amortised across the batch. Exp 2 measures exactly
// that decomposition, so this package times the two separately and never
// reports one number.
package redactor

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"sync"

	"zkredact/internal/pai"
	"zkredact/pkg/ch"
	"zkredact/pkg/merkle"
	"zkredact/pkg/scheme"
)

// Entry is one transaction's state on the ledger: T_i^(v_i) together with the
// chameleon-hash material that makes it redactable.
type Entry struct {
	TxID  string
	Block int

	// Core is immutable; Redactable is the redaction target. The split comes
	// from the shared corpus, so every scheme redacts the same bytes.
	Core       []byte
	Redactable []byte

	Version uint64

	// InitialDigest is d_{i,0} = H(T_i^(0)), fixed at genesis.
	//
	// A chameleon-hash redaction REPLACES content in place, so the original
	// bytes are gone from the chain once a redaction commits — which is the
	// whole point of the construction. Phase 1 Step 5 anticipates this by
	// committing d_{i,0} at initialisation, and Phase 6's boundary check reads
	// the digest rather than the vanished content.
	InitialDigest []byte

	// Value is CH.Hash(pk, m, r). It is INVARIANT across redactions: adapting
	// the randomness is what preserves it, and preserving it is what leaves the
	// block root, the block hash and every forward link untouched.
	Value      *ch.Value
	Randomness *big.Int
}

// StateDigest is d_{i,k} for this entry's current state.
func (e *Entry) StateDigest() []byte {
	return pai.StateDigest(e.TxID, e.Version, e.Core, e.Redactable)
}

// Block is one ledger block.
type Block struct {
	Height   int
	PrevHash []byte
	TxIDs    []string
	Root     []byte
	Hash     []byte

	// Anchor is AR^(e) when this block was appended to record one. Phase 5
	// Step 4 puts the anchor on the chain, and Phase 6 reads exactly one of
	// them — which is why an audit's block count does not grow with the ledger.
	Anchor *pai.Anchor
}

// Ledger is the permissioned blockchain's transaction state.
//
// Safe for concurrent use. Exp 1 does not touch it, but Exp 3's preparation
// interleaves reads with the redactions that build history.
type Ledger struct {
	mu sync.RWMutex

	curve   elliptic.Curve
	chKey   *ch.PrivateKey
	blockTx int

	blocks []*Block
	index  map[string]*Entry

	// anchorBlock maps a round to the block holding its AR^(e). Phase 6 reads
	// exactly one anchor, and this is what lets the audit report an honest
	// block count instead of assuming one.
	anchorBlock map[uint64]int
}

// NewLedger materialises the shared corpus into ZK-Redact's own representation.
//
// UNTIMED. Every scheme ingests the identical source data into its own
// structure before measurement begins; docs/experiments.md makes that part of
// the fairness contract.
func NewLedger(curve elliptic.Curve, chKey *ch.PrivateKey, blockTx int, txs []scheme.Transaction) (*Ledger, error) {
	if chKey == nil {
		return nil, fmt.Errorf("redactor: a chameleon-hash key is required")
	}
	if blockTx < 1 {
		return nil, fmt.Errorf("redactor: block_max_transactions must be >= 1, got %d", blockTx)
	}
	if len(txs) == 0 {
		return nil, fmt.Errorf("redactor: cannot build a ledger from an empty corpus")
	}

	l := &Ledger{
		curve:       curve,
		chKey:       chKey,
		blockTx:     blockTx,
		index:       make(map[string]*Entry, len(txs)),
		anchorBlock: make(map[uint64]int),
	}

	for start := 0; start < len(txs); start += blockTx {
		end := start + blockTx
		if end > len(txs) {
			end = len(txs)
		}
		height := len(l.blocks)

		leafHashes := make([][]byte, 0, end-start)
		ids := make([]string, 0, end-start)

		for _, tx := range txs[start:end] {
			if _, dup := l.index[tx.ID]; dup {
				return nil, fmt.Errorf("redactor: duplicate transaction %s in the corpus", tx.ID)
			}
			r, err := ch.NewRandomness(curve, randReader)
			if err != nil {
				return nil, fmt.Errorf("redactor: randomness for %s: %w", tx.ID, err)
			}
			v, err := chKey.PublicKey.Hash(tx.Redactable, r)
			if err != nil {
				return nil, fmt.Errorf("redactor: chameleon hash for %s: %w", tx.ID, err)
			}

			e := &Entry{
				TxID:       tx.ID,
				Block:      height,
				Core:       append([]byte(nil), tx.Core...),
				Redactable: append([]byte(nil), tx.Redactable...),
				Version:    0,
				Value:      v,
				Randomness: r,
			}
			e.InitialDigest = e.StateDigest()

			l.index[tx.ID] = e
			ids = append(ids, tx.ID)
			leafHashes = append(leafHashes, l.leafHash(e))
		}

		tree, err := merkle.NewFromHashes(leafHashes)
		if err != nil {
			return nil, fmt.Errorf("redactor: block %d: %w", height, err)
		}
		b := &Block{Height: height, TxIDs: ids, Root: tree.Root()}
		if height > 0 {
			b.PrevHash = l.blocks[height-1].Hash
		}
		b.Hash = blockHash(b.Height, b.PrevHash, b.Root)
		l.blocks = append(l.blocks, b)
	}
	return l, nil
}

// leafHash commits a transaction into its block.
//
// It covers the immutable core and the CHAMELEON DIGEST rather than the
// redactable content. That is the construction, not an optimisation: because
// CH.Adapt preserves the digest, this leaf survives a redaction unchanged, and
// with it the block root, the block hash and every subsequent block's
// back-link. Committing the raw content instead would break the chain on every
// redaction, which is precisely what a chameleon hash exists to avoid.
func (l *Ledger) leafHash(e *Entry) []byte {
	h := sha256.New()
	h.Write([]byte("zkredact/ledger/leaf/v1"))
	h.Write([]byte(e.TxID))
	h.Write(e.Core)
	h.Write(e.Value.Bytes(l.curve))
	return h.Sum(nil)
}

func blockHash(height int, prev, root []byte) []byte {
	h := sha256.New()
	h.Write([]byte("zkredact/ledger/block/v1"))
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(height))
	h.Write(n[:])
	h.Write(prev)
	h.Write(root)
	return h.Sum(nil)
}

// TxIDs returns every indexed transaction in ledger order, which is the leaf
// order the PAI is initialised with.
func (l *Ledger) TxIDs() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]string, 0, len(l.index))
	for _, b := range l.blocks {
		out = append(out, b.TxIDs...)
	}
	return out
}

// Blocks reports the current ledger height.
func (l *Ledger) Blocks() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.blocks)
}

// InitialDigest returns d_{i,0}, for initialising the PAI.
func (l *Ledger) InitialDigest(txID string) ([]byte, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	e, ok := l.index[txID]
	if !ok {
		return nil, fmt.Errorf("redactor: %s is not on the ledger", txID)
	}
	return append([]byte(nil), e.InitialDigest...), nil
}

// State returns a transaction's current version and state digest, plus the
// block holding it. This is the blockchain half of Phase 6 Step 2.
func (l *Ledger) State(txID string) (version uint64, digest []byte, block int, err error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	e, ok := l.index[txID]
	if !ok {
		return 0, nil, 0, fmt.Errorf("redactor: %s is not on the ledger", txID)
	}
	return e.Version, e.StateDigest(), e.Block, nil
}

// Version reports a transaction's current version, for Phase 4's freshness
// revalidation.
func (l *Ledger) Version(txID string) (uint64, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	e, ok := l.index[txID]
	if !ok {
		return 0, false
	}
	return e.Version, true
}

// Versions snapshots every transaction's current version, for rebuilding the
// gateway's view of ledger state between replays.
func (l *Ledger) Versions() map[string]uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make(map[string]uint64, len(l.index))
	for id, e := range l.index {
		out[id] = e.Version
	}
	return out
}

// Adapt is Phase 4 Step 3: CH.Adapt for one transaction, followed by the state
// transition T_i^(v) -> T_i^(v+1).
//
// Returns the pre- and post-state digests, which Phase 4 Step 4 binds into the
// provenance record.
//
// The chameleon digest is re-verified after adaptation. CH.Adapt returning a
// randomness that does NOT collide would silently fork the ledger: the block
// leaf would change, every later block's back-link would be wrong, and nothing
// in the redaction path would report it — the failure would surface much later
// as an audit that cannot verify. The check costs one CH.Hash and is inside
// CryptoTime, where it belongs.
func (l *Ledger) Adapt(txID string, newContent []byte) (oldDigest, newDigest []byte, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	e, ok := l.index[txID]
	if !ok {
		return nil, nil, fmt.Errorf("redactor: %s is not on the ledger", txID)
	}

	oldDigest = e.StateDigest()

	newR, err := l.chKey.Adapt(e.Redactable, e.Randomness, newContent)
	if err != nil {
		return nil, nil, fmt.Errorf("redactor: adapt %s: %w", txID, err)
	}
	if !l.chKey.PublicKey.Verify(newContent, newR, e.Value) {
		return nil, nil, fmt.Errorf(
			"redactor: adapting %s produced a randomness that does not collide with "+
				"the committed digest; the block hash would change and the chain would fork", txID)
	}

	e.Redactable = append([]byte(nil), newContent...)
	e.Randomness = newR
	e.Version++
	newDigest = e.StateDigest()
	return oldDigest, newDigest, nil
}

// AppendAnchor writes AR^(e) into a new block, as Phase 5 Step 4 requires.
//
// A block of its own rather than an amendment to the last one: the anchor is a
// transaction, and rewriting a committed block to hold it would change that
// block's hash — the one thing the chameleon-hash construction exists to
// prevent.
func (l *Ledger) AppendAnchor(a *pai.Anchor) (int, error) {
	if a == nil {
		return 0, fmt.Errorf("redactor: no anchor to append")
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	height := len(l.blocks)
	leaf := sha256.Sum256(append([]byte("zkredact/ledger/anchor/v1"), a.Commitment...))
	tree, err := merkle.NewFromHashes([][]byte{leaf[:]})
	if err != nil {
		return 0, fmt.Errorf("redactor: anchor block: %w", err)
	}
	b := &Block{Height: height, Root: tree.Root(), Anchor: a}
	if height > 0 {
		b.PrevHash = l.blocks[height-1].Hash
	}
	b.Hash = blockHash(b.Height, b.PrevHash, b.Root)
	l.blocks = append(l.blocks, b)
	l.anchorBlock[a.Round] = height
	return height, nil
}

// AnchorBlock reports which block holds AR^(e).
//
// Round 0's anchor is the trusted initial provenance state established in
// Phase 1; it is not written as its own block, so an audit against it reads
// only the transaction's block.
func (l *Ledger) AnchorBlock(round uint64) (int, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	h, ok := l.anchorBlock[round]
	return h, ok
}

// BlockHash exposes a block's hash so tests can assert the invariant that
// matters: a redaction must not change it.
func (l *Ledger) BlockHash(height int) ([]byte, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if height < 0 || height >= len(l.blocks) {
		return nil, fmt.Errorf("redactor: no block at height %d", height)
	}
	return append([]byte(nil), l.blocks[height].Hash...), nil
}

// VerifyBlock recomputes a block's Merkle root and hash from the entries it
// holds, so a test can prove the chameleon collision really did preserve them.
func (l *Ledger) VerifyBlock(height int) (bool, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if height < 0 || height >= len(l.blocks) {
		return false, fmt.Errorf("redactor: no block at height %d", height)
	}
	b := l.blocks[height]
	if b.Anchor != nil {
		return true, nil // anchor blocks hold no transactions
	}

	leaves := make([][]byte, 0, len(b.TxIDs))
	for _, id := range b.TxIDs {
		leaves = append(leaves, l.leafHash(l.index[id]))
	}
	tree, err := merkle.NewFromHashes(leaves)
	if err != nil {
		return false, err
	}
	if string(tree.Root()) != string(b.Root) {
		return false, nil
	}
	return string(blockHash(b.Height, b.PrevHash, tree.Root())) == string(b.Hash), nil
}
