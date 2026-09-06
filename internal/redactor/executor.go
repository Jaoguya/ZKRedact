package redactor

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	"zkredact/internal/pai"
	"zkredact/pkg/merkle"
	"zkredact/pkg/zk"
)

// randReader is the source of chameleon-hash randomness at genesis.
var randReader io.Reader = rand.Reader

// Item is one already-authorized redaction, carrying everything Phase 4 needs
// and nothing that identifies the requester.
//
// The absence is structural. Phase 2 Step 4 hands downstream components only
// Q_i^* = (DID_i, x_i, eta_i, pi_i); a requester field here would eventually be
// read by something, and the scheme's anonymity claim is that nothing after the
// gateway sees it.
type Item struct {
	TxID       string
	NewContent []byte

	PolicyID      string
	PolicyVersion uint64 // v_{P_qi} as authorized
	TxVersion     uint64 // v_i as authorized

	DID       []byte
	Statement *zk.Statement // x_i
	Proof     []byte        // pi_i, marshalled

	// AuthorizedAt is retained for staleness analysis: the gap between it and
	// execution is what makes larger batches strand more requests.
	AuthorizedAt time.Time
}

// Eta is eta_i = H(x_i), the statement-binding digest.
func (it *Item) Eta() []byte { return it.Statement.Digest() }

// Outcome is one round's result, with the cost split Exp 2 depends on.
type Outcome struct {
	Succeeded     int
	StaleExcluded int
	Failed        int

	CryptoTime time.Duration
	LedgerTime time.Duration

	// BatchCommitment is C_B^(e).
	BatchCommitment []byte

	// Round is e, and Anchor is the AR^(e) this round produced.
	Round  uint64
	Anchor *pai.Anchor
}

// Executor runs Phase 4 against the ledger and the PAI.
type Executor struct {
	mu sync.Mutex

	ledger *Ledger
	index  *pai.Index

	// policyVersion supplies v_{P_q}^cur for Phase 4 Step 2's revalidation.
	// Passed in rather than read from a policy table held here, because the
	// registered policies belong to Phase 1 and this package has no business
	// owning a second copy that could drift.
	policyVersion func(policyID string) (uint64, bool)

	// round is e. It advances once per Redact call, which is what makes a
	// "redaction round" and a "batch" the same thing in this implementation —
	// exactly as Phase 5's opening sentence states.
	round uint64
}

// NewExecutor wires Phase 4 to the ledger and the index.
func NewExecutor(l *Ledger, ix *pai.Index, policyVersion func(string) (uint64, bool)) (*Executor, error) {
	if l == nil || ix == nil {
		return nil, fmt.Errorf("redactor: an executor needs both a ledger and a provenance index")
	}
	if policyVersion == nil {
		return nil, fmt.Errorf("redactor: policy versions are required for Fresh_i revalidation")
	}
	return &Executor{ledger: l, index: ix, policyVersion: policyVersion, round: ix.Round()}, nil
}

// Round reports the last committed round e.
func (x *Executor) Round() uint64 {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.round
}

// Run executes one redaction batch: Phase 4 Steps 1 to 5, then Phase 5's
// commitment through the index.
//
// SERIALISED. One round at a time, because a round is defined by its own
// R_B^(e), C_B^(e) and anchor, and two overlapping rounds would interleave
// their record sets into each other's commitments.
//
// Within a round, requests are executed in order and Fresh_i is re-checked
// before each transition — which is Phase 4 Step 2's "for requests targeting
// the same transaction, this check is repeated before each transition". Two
// requests in one batch against the same transaction therefore cost one
// success and one stale exclusion, which is the honest arithmetic of batching
// under conflict and precisely what exp2's conflict_ratios sweep.
func (x *Executor) Run(ctx context.Context, batch []*Item) (*Outcome, error) {
	x.mu.Lock()
	defer x.mu.Unlock()

	if len(batch) == 0 {
		return &Outcome{}, nil
	}

	round := x.round + 1
	out := &Outcome{Round: round}
	ledgerStart := time.Now()

	// ---- Step 2: state revalidation, Q_F^(e), and R_B^(e) ----
	//
	// Computed over the batch as admitted, BEFORE execution. A same-target
	// duplicate passes here and fails at its transition, so it is bound into
	// R_B^(e) but absent from Q_succ^(e) — which is exactly the containment
	// Q_succ ⊆ Q_F the manuscript states.
	fresh := make([]*Item, 0, len(batch))
	freshLeaves := make([][]byte, 0, len(batch))
	for _, it := range batch {
		if it == nil || it.Statement == nil || len(it.Proof) == 0 {
			out.Failed++
			continue
		}
		if !x.isFresh(it) {
			out.StaleExcluded++
			continue
		}
		fresh = append(fresh, it)
		freshLeaves = append(freshLeaves, batchLeaf(it.DID, it.Eta()))
	}
	out.LedgerTime += time.Since(ledgerStart)

	if len(fresh) == 0 {
		out.LedgerTime = time.Since(ledgerStart)
		return out, nil
	}

	ledgerStart = time.Now()
	batchTree, err := merkle.NewFromHashes(freshLeaves)
	if err != nil {
		return nil, fmt.Errorf("redactor: round %d batch root: %w", round, err)
	}
	batchRoot := batchTree.Root() // R_B^(e)
	out.LedgerTime += time.Since(ledgerStart)

	// ---- Steps 3 and 4: adapt, then build the provenance record ----
	records := make([]*pai.Record, 0, len(fresh))
	for _, it := range fresh {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		// Re-checked immediately before the transition, not only in Step 2.
		// The first same-target request in this batch has already advanced the
		// version by the time the second reaches here.
		if !x.isFresh(it) {
			out.StaleExcluded++
			continue
		}

		cryptoStart := time.Now()
		oldDigest, newDigest, err := x.ledger.Adapt(it.TxID, it.NewContent)
		if err != nil {
			out.CryptoTime += time.Since(cryptoStart)
			out.Failed++
			continue
		}
		authCommit := pai.AuthCommitment(it.DID, it.Eta(), it.Proof)
		out.CryptoTime += time.Since(cryptoStart)

		records = append(records, &pai.Record{
			TxID:          it.TxID,
			FromVersion:   it.TxVersion,
			ToVersion:     it.TxVersion + 1,
			PolicyID:      it.PolicyID,
			PolicyVersion: it.PolicyVersion,
			DID:           append([]byte(nil), it.DID...),
			Round:         round,
			OldDigest:     oldDigest,
			NewDigest:     newDigest,
			AuthCommit:    authCommit,
			BatchRoot:     batchRoot,
			CompletedAt:   time.Now(),
		})

		// Phase 4 Step 4: (x_i, pi_i) retained off-chain under DID_i,
		// authenticated by C_i^auth. Phase 6 re-verifies it from here.
		if err := x.index.StoreEvidence(it.DID, it.Statement, it.Proof); err != nil {
			return nil, fmt.Errorf("redactor: retain audit evidence: %w", err)
		}
	}

	if len(records) == 0 {
		// Nothing committed, so no round is opened. Advancing e here would
		// leave a gap the anchor chain could never close.
		out.LedgerTime += time.Since(ledgerStart)
		return out, nil
	}

	// ---- Step 5: R_PR^(e), C_B^(e), and the Phase 5 commitment ----
	ledgerStart = time.Now()

	recordTree, err := pai.RecordTree(records)
	if err != nil {
		return nil, fmt.Errorf("redactor: round %d record root: %w", round, err)
	}
	batchCommit := BatchCommitment(batchRoot, round, recordTree.Root())

	anchor, err := x.index.Commit(round, records, recordTree, batchCommit)
	if err != nil {
		return nil, fmt.Errorf("redactor: round %d: %w", round, err)
	}
	if _, err := x.ledger.AppendAnchor(anchor); err != nil {
		return nil, fmt.Errorf("redactor: round %d anchor: %w", round, err)
	}

	out.LedgerTime += time.Since(ledgerStart)
	out.Succeeded = len(records)
	out.BatchCommitment = batchCommit
	out.Anchor = anchor
	x.round = round
	return out, nil
}

// isFresh is Eq. (redaction-revalidation):
//
//	Fresh_i = [v_i = v_i^cur] AND [v_P = v_P^cur]
//
// Both halves matter. Checking only the transaction version would let a
// redaction authorized under a since-amended policy execute against the new
// one, which is the case Phase 4 Step 2 exists to exclude.
func (x *Executor) isFresh(it *Item) bool {
	cur, known := x.ledger.Version(it.TxID)
	if !known || cur != it.TxVersion {
		return false
	}
	pv, known := x.policyVersion(it.PolicyID)
	return known && pv == it.PolicyVersion
}

// batchLeaf is H(DID_i || eta_i), the leaf of R_B^(e) in Eq.
// (redaction-batch-root).
func batchLeaf(did, eta []byte) []byte {
	h := sha256.New()
	h.Write([]byte("zkredact/redactor/batch-leaf/v1"))
	h.Write(did)
	h.Write(eta)
	return h.Sum(nil)
}

// BatchCommitment is Eq. (batch-redaction-commitment):
//
//	C_B^(e) = H(R_B^(e) || e || R_PR^(e))
//
// It binds the round's admitted set, its index, and the records it produced,
// and is what the anchor commits to on the blockchain.
func BatchCommitment(batchRoot []byte, round uint64, recordRoot []byte) []byte {
	h := sha256.New()
	h.Write([]byte("zkredact/redactor/batch-commit/v1"))
	h.Write(batchRoot)
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], round)
	h.Write(n[:])
	h.Write(recordRoot)
	return h.Sum(nil)
}
