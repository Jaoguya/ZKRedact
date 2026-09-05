package ref10

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"zkredact/pkg/merkle"
	"zkredact/pkg/scheme"
)

// The Extended Merkle Tree and the ledger it sits in (Ref[10] §IV-B, Eq. 4).
//
// EMT's whole idea is that each transaction contributes TWO leaves rather than
// one: a core branch H_c that can never change, and an inserted-data branch H_w
// that redaction rewrites. A block's tree is built over the interleaved
// sequence
//
//	EMT( <tx_1.H_c, tx_1.H_w, ..., tx_m.H_c, tx_m.H_w> )        (Eq. 4)
//
// and each transaction additionally records H_tx = H(H_c || H_w).
//
// WHY THE SPLIT MATTERS FOR THE COMPARISON. Because H_c is a separate leaf, a
// redaction recomputes only the H_w leaf and the path above it — no chameleon
// hash and no trapdoor anywhere in the scheme. That is precisely why Ref[10]
// belongs in Exp 2 as the no-CH reference point, and why substituting a cheaper
// or more expensive hash here would misrepresent it.
//
// A redaction that alters core data must be detectable. Keeping H_c as its own
// leaf is what makes Algorithm 1 able to say so, and the fidelity checklist in
// docs/baselines/ref10-emt.md requires that it does.

// txKind classifies a transaction for the redactability set T_rdbl.
//
// Eq. 6 defines T_rdbl = T_all \ (T_gen U T_rdt U T_con): genesis, redaction
// and contract transactions are permanently ineligible. Tracking the kind on
// the transaction itself means Algorithm 2 answers that question by lookup
// rather than by a heuristic on the ID.
type txKind uint8

const (
	txNormal    txKind = iota // T_all \ the excluded sets — redactable
	txGenesis                 // T_gen
	txRedaction               // T_rdt — the tx_rdt records themselves
	txContract                // T_con — redaction contract deployments
)

func (k txKind) String() string {
	switch k {
	case txGenesis:
		return "genesis"
	case txRedaction:
		return "redaction"
	case txContract:
		return "contract"
	default:
		return "normal"
	}
}

// emtTx is one transaction inside a block.
type emtTx struct {
	ID   string
	Kind txKind

	// Core is immutable for the transaction's whole life. Redaction never
	// touches it, and Algorithm 1 fails if it changed.
	Core []byte

	// Redactable is the inserted data d_w. Algorithm 5 replaces it with a
	// reference to the redaction transaction that authorised the change.
	Redactable []byte

	HC  []byte // H_c
	HW  []byte // H_w
	HTx []byte // H_tx = H(H_c || H_w)

	// Version counts redactions applied. Exposed to the harness as
	// Authorization.TxVersion so staleness is measurable, even though this
	// scheme does not itself revalidate (Capabilities.StateFreshnessCheck).
	Version uint64

	// RedactedBy lists, oldest first, the IDs of the redaction transactions
	// that rewrote this transaction. This is a per-transaction index and Ref[10]
	// has no such thing on-chain — it exists here only so the harness can BUILD
	// history of a known depth during Setup, which is untimed. Audit must not
	// read it; see Scheme.Audit.
	RedactedBy []string

	// rdt is the parsed redaction record, present only on transactions of kind
	// txRedaction. A real node parses block contents the same way; what it does
	// NOT get is an index from target transaction to the records naming it,
	// which is why Audit still has to walk every block.
	rdt *redactionTx
}

// redactionTx is tx_rdt = {req, Sigma}: the redaction request together with the
// committee signatures that approved it.
type redactionTx struct {
	ID         string
	TargetTxID string
	NewDigest  []byte
	OldDigest  []byte
	FromVer    uint64
	ToVer      uint64
	PolicyID   string
	// Evidence is the serialised vote set Sigma, re-verifiable by Algorithm 5
	// and by any auditor.
	Evidence []byte
}

// block is one ledger block with its own EMT.
type block struct {
	Height   int
	Txs      []*emtTx
	tree     *merkle.Tree
	PrevHash []byte
	Hash     []byte
}

// leaves returns the interleaved leaf hashes of Eq. 4.
func (b *block) leaves() [][]byte {
	out := make([][]byte, 0, len(b.Txs)*2)
	for _, tx := range b.Txs {
		out = append(out, tx.HC, tx.HW)
	}
	return out
}

// rebuild recomputes the block's EMT and hash from its current transactions.
//
// Called at construction and after every redaction. Recomputing the whole block
// tree rather than patching one path is what Ref[10] actually costs: the node
// holds the block, not a persistent authenticated structure with incremental
// update. Optimising this would be inventing an efficiency the paper does not
// claim.
func (b *block) rebuild() error {
	t, err := merkle.NewFromHashes(b.leaves())
	if err != nil {
		return fmt.Errorf("block %d: %w", b.Height, err)
	}
	b.tree = t

	h := sha256.New()
	h.Write(b.PrevHash)
	h.Write(t.Root())
	b.Hash = h.Sum(nil)
	return nil
}

// hashTx computes H_tx = H(H_c || H_w).
func hashTx(hc, hw []byte) []byte {
	h := sha256.New()
	h.Write(hc)
	h.Write(hw)
	return h.Sum(nil)
}

// ledger is the local chain a node holds.
//
// Every field here is state a real node would have. There is deliberately NO
// index from transaction to the redaction transactions affecting it: Ref[10]
// has no per-transaction provenance (Capabilities.PerTxProvenance is false),
// and adding one would give this baseline ZK-Redact's Exp 3 advantage for free.
type ledger struct {
	mu     sync.RWMutex
	blocks []*block

	// txLoc maps a transaction ID to its position. A real Fabric peer keeps
	// exactly this index in its state database, so using it for Algorithm 5's
	// "locate the block containing tx_id" is faithful. It says nothing about
	// redaction history.
	txLoc map[string]txLocation

	blockSize int
	nextRdt   int
}

type txLocation struct{ Block, Index int }

// newLedger materialises the shared source dataset into blocks.
//
// NOT TIMED (scheme.Scheme.Setup). Each system ingests the identical corpus
// into its own on-chain form before measurement starts.
func newLedger(txs []scheme.Transaction, blockSize int) (*ledger, error) {
	if blockSize <= 0 {
		return nil, fmt.Errorf("ref10: block size must be positive, got %d", blockSize)
	}
	if len(txs) == 0 {
		return nil, errors.New("ref10: dataset has no transactions")
	}

	l := &ledger{
		txLoc:     make(map[string]txLocation, len(txs)+1),
		blockSize: blockSize,
	}

	// Block 0 is the genesis block. Its transaction is in T_gen and therefore
	// permanently outside T_rdbl (Eq. 6).
	gen := &emtTx{
		ID:         "tx-genesis",
		Kind:       txGenesis,
		Core:       []byte("genesis"),
		Redactable: []byte{},
	}
	l.appendBlock([]*emtTx{gen})

	for i := 0; i < len(txs); i += blockSize {
		end := i + blockSize
		if end > len(txs) {
			end = len(txs)
		}
		batch := make([]*emtTx, 0, end-i)
		for _, src := range txs[i:end] {
			batch = append(batch, &emtTx{
				ID:         src.ID,
				Kind:       txNormal,
				Core:       src.Core,
				Redactable: src.Redactable,
			})
		}
		l.appendBlock(batch)
	}

	for _, b := range l.blocks {
		if err := b.rebuild(); err != nil {
			return nil, err
		}
	}
	return l, nil
}

// appendBlock adds a block, computing each transaction's hashes. The caller
// rebuilds trees afterwards.
func (l *ledger) appendBlock(txs []*emtTx) *block {
	b := &block{Height: len(l.blocks), Txs: txs}
	if b.Height > 0 {
		b.PrevHash = l.blocks[b.Height-1].Hash
	} else {
		b.PrevHash = make([]byte, merkle.Size)
	}
	for i, tx := range txs {
		tx.HC = merkle.HashLeaf(tx.Core)
		tx.HW = merkle.HashLeaf(tx.Redactable)
		tx.HTx = hashTx(tx.HC, tx.HW)
		l.txLoc[tx.ID] = txLocation{Block: b.Height, Index: i}
	}
	l.blocks = append(l.blocks, b)
	return b
}

// blockCount reports the chain length.
func (l *ledger) blockCount() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.blocks)
}

// lookup returns a transaction by ID.
func (l *ledger) lookup(id string) (*emtTx, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	loc, ok := l.txLoc[id]
	if !ok {
		return nil, false
	}
	return l.blocks[loc.Block].Txs[loc.Index], true
}

// applyRedaction runs Algorithm 5's ledger mutation: locate the block holding
// tx_id, replace tx_n.d_w with a reference to tx_rdt, and update the tree.
//
// Returns the new H_tx and the number of blocks touched.
func (l *ledger) applyRedaction(rdt *redactionTx, newContent []byte) (*emtTx, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	loc, ok := l.txLoc[rdt.TargetTxID]
	if !ok {
		return nil, fmt.Errorf("ref10: transaction %s is not in the ledger", rdt.TargetTxID)
	}
	b := l.blocks[loc.Block]
	tx := b.Txs[loc.Index]

	beforeHC := append([]byte(nil), tx.HC...)

	tx.Redactable = newContent
	tx.HW = merkle.HashLeaf(tx.Redactable)
	tx.HTx = hashTx(tx.HC, tx.HW)
	tx.Version++
	tx.RedactedBy = append(tx.RedactedBy, rdt.ID)

	// H_c is not recomputed above, so this can only fail if something else
	// mutated it. Checked anyway: the invariant is the scheme's entire
	// integrity claim, and an assertion here costs one comparison.
	if string(beforeHC) != string(tx.HC) {
		return nil, errors.New("ref10: redaction altered core transaction data")
	}

	if err := b.rebuild(); err != nil {
		return nil, err
	}
	// Blocks after the redacted one carry a stale PrevHash. Ref[10] prunes
	// locally and does not re-link the chain — §V-C is explicit that per-node
	// inconsistency is expected and resolved by record, not by rewriting. So
	// the chain is deliberately NOT re-hashed forward here; doing so would
	// charge Ref[10] a cost its design does not incur.
	return tx, nil
}

// appendRedactionTx records tx_rdt as a ledger transaction in T_rdt.
//
// It goes into a block of its own, which is what makes Exp 3's cost grow: the
// only way to find a transaction's redaction history later is to look through
// blocks for redaction transactions naming it.
func (l *ledger) appendRedactionTx(rdt *redactionTx) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.nextRdt++
	tx := &emtTx{
		ID:         rdt.ID,
		Kind:       txRedaction,
		Core:       encodeRedactionCore(rdt),
		Redactable: []byte{},
	}
	tx.rdt = rdt
	b := l.appendBlock([]*emtTx{tx})
	_ = b.rebuild()
}

// encodeRedactionCore serialises tx_rdt into the immutable core branch. A
// redaction transaction's own content must never itself be redactable, which
// is why it lives in the core branch and its kind is T_rdt.
func encodeRedactionCore(rdt *redactionTx) []byte {
	out := make([]byte, 0, 128+len(rdt.Evidence))
	out = append(out, rdt.ID...)
	out = append(out, 0x1f)
	out = append(out, rdt.TargetTxID...)
	out = append(out, 0x1f)
	out = append(out, rdt.OldDigest...)
	out = append(out, rdt.NewDigest...)
	out = append(out, rdt.Evidence...)
	return out
}

// scanForRedactions walks the whole chain looking for redaction transactions
// naming the target.
//
// This is Ref[10]'s Exp 3 cost and it is linear in ledger size by construction.
// Capabilities.LedgerIndependentAudit is false for exactly this reason, and the
// exp3 guard checks the two agree.
//
// EvidenceBytes counts what an auditor actually has to read: every block root,
// plus the content of every redaction transaction encountered — not only the
// matching ones, since you cannot know which match without reading them.
func (l *ledger) scanForRedactions(targetTxID string) ([]scheme.ProvenanceRecord, int, int) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var out []scheme.ProvenanceRecord
	bytesRead := 0

	for _, b := range l.blocks {
		bytesRead += merkle.Size
		for _, tx := range b.Txs {
			if tx.Kind != txRedaction || tx.rdt == nil {
				continue
			}
			bytesRead += len(tx.Core)
			if tx.rdt.TargetTxID != targetTxID {
				continue
			}
			out = append(out, scheme.ProvenanceRecord{
				TxID:         tx.rdt.TargetTxID,
				FromVersion:  tx.rdt.FromVer,
				ToVersion:    tx.rdt.ToVer,
				PolicyID:     tx.rdt.PolicyID,
				OldDigest:    tx.rdt.OldDigest,
				NewDigest:    tx.rdt.NewDigest,
				AuthEvidence: tx.rdt.Evidence,
			})
		}
	}
	return out, len(l.blocks), bytesRead
}
