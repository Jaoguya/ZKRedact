// Package pai implements ZK-Redact's Provenance Audit Index: Phase 5
// (authenticated provenance maintenance) and the retrieval and verification
// halves of Phase 6.
//
// Spec: Reference/ZK-Redact Scheme/ZK-Redact.md, Phases 5 and 6.
//
// WHAT THIS PACKAGE IS FOR. Exp 3's claim is that audit cost tracks a
// transaction's own redaction history rather than the size of the ledger. That
// claim lives entirely in the data structure: a per-transaction hash chain
// (c_i), one authenticated leaf per transaction (A_i), and one blockchain
// anchor per round (AR^(e)). An auditor reads one history, one Merkle path, and
// one anchor — never the chain. If any of that were replaced by a scan, Exp 3's
// headline plot would climb and the capability declaration in
// zkredact.Capabilities would be false.
package pai

import (
	"bytes"
	"fmt"
	"sync"

	"zkredact/pkg/merkle"
	"zkredact/pkg/zk"
)

// Index is the PAI. Safe for concurrent use.
type Index struct {
	mu sync.RWMutex

	// order fixes the leaf position of every indexed transaction, decided once
	// at Init. The Merkle tree's shape depends on the leaf COUNT, so the set
	// cannot grow: a transaction absent at Init has no leaf and cannot be
	// audited. Init is called with the whole corpus.
	order []string
	slot  map[string]int

	state map[string]*txState

	// tree's leaves are A_i^(v_i); its root is R_PAI^(e).
	tree *merkle.Tree

	round    uint64
	prevRoot []byte

	// anchors and recordTrees are retained per round. Phase 6 verifies
	// psi_{i,k} against R_PR^(e_k) for the round each record names, so a
	// history spanning several rounds needs several of them.
	anchors     map[uint64]*Anchor
	recordTrees map[uint64]*merkle.Tree
	recordSlot  map[uint64]map[string]int

	// evidence is the off-chain audit-evidence store, keyed by DID. Phase 4
	// Step 4: "(x_i, pi_i) is retained off-chain under DID_i and authenticated
	// by C_i^auth". It is deliberately NOT part of any on-chain commitment —
	// only its digest is, through C_i^auth — which is what Phase 6 Step 4
	// re-checks.
	evidence map[string]*storedEvidence
}

type txState struct {
	version       uint64
	cumulative    []byte // c_i^(v_i)
	initialDigest []byte // d_{i,0}
	history       []*Record
}

type storedEvidence struct {
	statement *zk.Statement
	proof     []byte
}

// Init is Phase 1 Step 5: initialise every indexed transaction at version 0 and
// publish R_PAI^(0).
//
// initialDigest supplies d_{i,0} = H(T_i^(0)) for each transaction, computed by
// the caller from the blockchain state it holds. The PAI does not compute it
// because the PAI does not hold transaction contents — a design point, not an
// inconvenience: the index stores commitments, and Phase 6's boundary check is
// meaningful only because the digest it compares against comes from the chain
// rather than from the index.
func NewIndex(txIDs []string, initialDigest func(txID string) ([]byte, error)) (*Index, error) {
	if len(txIDs) == 0 {
		return nil, fmt.Errorf("pai: cannot initialise an index over no transactions")
	}
	if initialDigest == nil {
		return nil, fmt.Errorf("pai: an initial state digest is required for every transaction")
	}

	ix := &Index{
		order:       make([]string, len(txIDs)),
		slot:        make(map[string]int, len(txIDs)),
		state:       make(map[string]*txState, len(txIDs)),
		anchors:     make(map[uint64]*Anchor),
		recordTrees: make(map[uint64]*merkle.Tree),
		recordSlot:  make(map[uint64]map[string]int),
		evidence:    make(map[string]*storedEvidence),
	}

	leaves := make([][]byte, len(txIDs))
	for i, id := range txIDs {
		if _, dup := ix.slot[id]; dup {
			return nil, fmt.Errorf("pai: duplicate transaction %s in the index", id)
		}
		d0, err := initialDigest(id)
		if err != nil {
			return nil, fmt.Errorf("pai: initial digest for %s: %w", id, err)
		}
		if len(d0) == 0 {
			return nil, fmt.Errorf("pai: empty initial digest for %s", id)
		}

		c0 := InitialCumulative(id, d0)
		ix.order[i] = id
		ix.slot[id] = i
		ix.state[id] = &txState{version: 0, cumulative: c0, initialDigest: d0}
		leaves[i] = Entry(id, 0, c0)
	}

	tree, err := merkle.New(leaves)
	if err != nil {
		return nil, fmt.Errorf("pai: build initial PAI tree: %w", err)
	}
	ix.tree = tree
	ix.prevRoot = tree.Root()

	// Round 0 is the trusted initial provenance state. It has no batch and no
	// records, so its anchor commits R_PAI^(0) against itself; Phase 6 never
	// verifies a record path against round 0 because no record names it.
	ac := AnchorCommitment(0, tree.Root(), tree.Root(), nil)
	ix.anchors[0] = &Anchor{
		Round:      0,
		Root:       tree.Root(),
		PrevRoot:   tree.Root(),
		Commitment: ac,
	}
	return ix, nil
}

// Round reports the most recently committed round e.
func (ix *Index) Round() uint64 {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	return ix.round
}

// Root reports the current R_PAI^(e).
func (ix *Index) Root() []byte {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	return ix.tree.Root()
}

// Version reports a transaction's current version, or false if it is not
// indexed.
func (ix *Index) Version(txID string) (uint64, bool) {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	st, ok := ix.state[txID]
	if !ok {
		return 0, false
	}
	return st.version, true
}

// StoreEvidence records (x_i, pi_i) in the off-chain audit-evidence store under
// DID_i. Called by Phase 4 Step 4 as each redaction completes.
func (ix *Index) StoreEvidence(did []byte, st *zk.Statement, proof []byte) error {
	if len(did) == 0 {
		return fmt.Errorf("pai: evidence needs a deduplication identifier")
	}
	if st == nil || len(proof) == 0 {
		return fmt.Errorf("pai: evidence for %x is incomplete", did)
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	ix.evidence[string(did)] = &storedEvidence{statement: st, proof: append([]byte(nil), proof...)}
	return nil
}

// Commit is Phase 5: append the round's records to their transactions'
// histories, update the authenticated index, and produce the blockchain anchor.
//
// The four steps of Phase 5 in order:
//
//	Step 1  H_i^(v+1) = H_i^(v) || PR, and c_i^(v+1) = H(c_i^(v) || H(PR)),
//	        with the continuity requirement d^new_k = d^old_{k+1}.
//	Step 2  A_i^(v+1) = H(TID || v+1 || c_i^(v+1)).
//	Step 3  R_PAI^(e) over every indexed transaction's current entry.
//	Step 4  AC^(e) and AR^(e).
//
// recordTree and batchCommitment come from Phase 4 Step 5 — the caller holds
// them because C_B^(e) is formed there, from R_B^(e) and R_PR^(e) together.
//
// ATOMIC. A record that fails continuity aborts the whole round with nothing
// applied. A partially applied round would leave some transactions committed
// against a root that was never anchored, and Phase 6 would report those as
// tampered histories — a real defect presenting as a false audit failure.
func (ix *Index) Commit(round uint64, records []*Record, recordTree *merkle.Tree, batchCommitment []byte) (*Anchor, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()

	if round != ix.round+1 {
		return nil, fmt.Errorf(
			"pai: round %d committed after round %d; anchors chain to their "+
				"predecessor, so a gap would make every later audit fail", round, ix.round)
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("pai: round %d has no records to commit", round)
	}
	if recordTree == nil {
		return nil, fmt.Errorf("pai: round %d has no record tree; psi_{i,k} could not be produced", round)
	}
	if len(batchCommitment) == 0 {
		return nil, fmt.Errorf("pai: round %d has no batch-result commitment C_B", round)
	}

	// --- validate the whole round before touching any state ---
	type pending struct {
		st     *txState
		rec    *Record
		newCum []byte
		newVer uint64
	}
	staged := make([]pending, 0, len(records))
	// Working copies, so several records for the same transaction in one round
	// chain through each other rather than each starting from the committed
	// value.
	working := make(map[string]*txState, len(records))

	for i, rec := range records {
		if rec == nil {
			return nil, fmt.Errorf("pai: nil record at position %d", i)
		}
		if rec.Round != round {
			return nil, fmt.Errorf(
				"pai: record for %s names round %d but is being committed in round %d; "+
					"psi_{i,k} would be verified against the wrong R_PR",
				rec.TxID, rec.Round, round)
		}
		cur, ok := working[rec.TxID]
		if !ok {
			committed, known := ix.state[rec.TxID]
			if !known {
				return nil, fmt.Errorf("pai: record for unindexed transaction %s", rec.TxID)
			}
			// Copy: nothing is written until every record has validated.
			cp := *committed
			cp.history = append([]*Record(nil), committed.history...)
			cur = &cp
			working[rec.TxID] = cur
		}

		if rec.FromVersion != cur.version || rec.ToVersion != cur.version+1 {
			return nil, fmt.Errorf(
				"pai: record for %s moves %d->%d but the index is at version %d",
				rec.TxID, rec.FromVersion, rec.ToVersion, cur.version)
		}
		// Phase 5 Step 1's continuity requirement, Eq. (history-continuity):
		// each redaction's output state must be the next one's input state.
		if err := checkContinuity(cur, rec); err != nil {
			return nil, err
		}

		newCum := NextCumulative(cur.cumulative, rec.Hash())
		cur.version = rec.ToVersion
		cur.cumulative = newCum
		cur.history = append(cur.history, rec)

		staged = append(staged, pending{st: cur, rec: rec, newCum: newCum, newVer: rec.ToVersion})
	}

	// --- apply ---
	for _, p := range staged {
		ix.state[p.rec.TxID] = p.st
	}
	// Step 2 and Step 3: one leaf update per touched transaction, then the
	// root. Updating incrementally rather than rebuilding is what keeps this
	// O(touched x log |I|) instead of O(|I|); merkle.UpdateLeaf produces the
	// identical root, which TestUpdateMatchesRebuild pins.
	touched := make(map[string]struct{}, len(staged))
	for _, p := range staged {
		touched[p.rec.TxID] = struct{}{}
	}
	for txID := range touched {
		st := ix.state[txID]
		if err := ix.tree.UpdateLeaf(ix.slot[txID], Entry(txID, st.version, st.cumulative)); err != nil {
			return nil, fmt.Errorf("pai: update PAI entry for %s: %w", txID, err)
		}
	}

	root := ix.tree.Root()

	// Step 4.
	anchor := &Anchor{
		Round:           round,
		Root:            root,
		PrevRoot:        ix.prevRoot,
		BatchCommitment: append([]byte(nil), batchCommitment...),
		RecordRoot:      recordTree.Root(),
	}
	anchor.Commitment = AnchorCommitment(round, root, ix.prevRoot, batchCommitment)

	ix.anchors[round] = anchor
	ix.recordTrees[round] = recordTree
	slots := make(map[string]int, len(records))
	for i, rec := range records {
		slots[string(rec.Hash())] = i
	}
	ix.recordSlot[round] = slots

	ix.prevRoot = root
	ix.round = round
	return anchor, nil
}

// checkContinuity enforces Eq. (history-continuity) for one appended record.
//
// The first record of a transaction must start from the authenticated initial
// state; every later one must start where its predecessor ended.
func checkContinuity(st *txState, rec *Record) error {
	var want []byte
	if len(st.history) == 0 {
		want = st.initialDigest
	} else {
		want = st.history[len(st.history)-1].NewDigest
	}
	if !bytes.Equal(rec.OldDigest, want) {
		return fmt.Errorf(
			"pai: record for %s at version %d does not continue from the previous "+
				"state (d^old %x, expected %x); the history would not replay",
			rec.TxID, rec.ToVersion, rec.OldDigest, want)
	}
	return nil
}

// Anchor returns AR^(e) for a round.
func (ix *Index) Anchor(round uint64) (*Anchor, bool) {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	a, ok := ix.anchors[round]
	return a, ok
}

// Retrieve is Phase 6 Step 2's PAI half: the target's history, its
// authenticated entry and path, the per-record paths psi_{i,k}, and the stored
// public evidence.
//
// epoch selects the anchored state to verify against; zero means the latest.
// Only the CURRENT root is materialised, so a query against an older epoch is
// refused rather than answered against the wrong root — silently substituting
// the latest root would make mu_i^(e) verify against a state the query did not
// ask about.
//
// The caller completes the evidence with the blockchain half: the anchor's own
// block, and the initial and current transaction states.
func (ix *Index) Retrieve(txID string, epoch uint64) (*AuditEvidence, error) {
	ix.mu.RLock()
	defer ix.mu.RUnlock()

	st, ok := ix.state[txID]
	if !ok {
		return nil, fmt.Errorf("pai: transaction %s is not indexed", txID)
	}
	if epoch == 0 {
		epoch = ix.round
	}
	if epoch != ix.round {
		return nil, fmt.Errorf(
			"pai: epoch %d requested but the index holds %d; historical PAI roots "+
				"are not retained, and answering against the current root would "+
				"authenticate a state the query did not ask for", epoch, ix.round)
	}

	anchor, ok := ix.anchors[epoch]
	if !ok {
		return nil, fmt.Errorf("pai: no anchor for round %d", epoch)
	}

	path, err := ix.tree.Proof(ix.slot[txID])
	if err != nil {
		return nil, fmt.Errorf("pai: authentication path for %s: %w", txID, err)
	}

	ev := &AuditEvidence{
		History:     append([]*Record(nil), st.history...),
		Version:     st.version,
		Cumulative:  append([]byte(nil), st.cumulative...),
		EntryValue:  Entry(txID, st.version, st.cumulative),
		EntryPath:   path,
		Anchor:      anchor,
		RootAtEpoch: ix.tree.Root(),
	}

	// Per record: psi_{i,k} against R_PR^(e_k), and (x_{i,k}, pi_{i,k}).
	ev.RecordPaths = make([]*merkle.Proof, len(ev.History))
	ev.RecordRoots = make([][]byte, len(ev.History))
	ev.Statements = make([]*zk.Statement, len(ev.History))
	ev.Proofs = make([][]byte, len(ev.History))

	for k, rec := range ev.History {
		tree, ok := ix.recordTrees[rec.Round]
		if !ok {
			return nil, fmt.Errorf(
				"pai: record %d of %s names round %d, which has no record tree",
				k, txID, rec.Round)
		}
		idx, ok := ix.recordSlot[rec.Round][string(rec.Hash())]
		if !ok {
			return nil, fmt.Errorf(
				"pai: record %d of %s is not in round %d's record tree", k, txID, rec.Round)
		}
		p, err := tree.Proof(idx)
		if err != nil {
			return nil, fmt.Errorf("pai: psi for record %d of %s: %w", k, txID, err)
		}
		ev.RecordPaths[k] = p

		roundAnchor, ok := ix.anchors[rec.Round]
		if !ok {
			return nil, fmt.Errorf("pai: no anchor for round %d", rec.Round)
		}
		ev.RecordRoots[k] = roundAnchor.RecordRoot

		stored, ok := ix.evidence[string(rec.DID)]
		if !ok {
			return nil, fmt.Errorf(
				"pai: no off-chain evidence stored under DID %x for record %d of %s",
				rec.DID, k, txID)
		}
		ev.Statements[k] = stored.statement
		ev.Proofs[k] = stored.proof
	}
	return ev, nil
}
