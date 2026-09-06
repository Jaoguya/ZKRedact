package pai

import (
	"fmt"
	"time"

	"zkredact/pkg/merkle"
	"zkredact/pkg/scheme"
	"zkredact/pkg/zk"
)

// Record is PR_i^(v_i+1), Eq. (provenance-record):
//
//	PR_i^(v_i+1) = ( TID_i, v_i, v_i+1, PID_i, v_{P_qi}, DID_i, e,
//	                 d^old_{i,v_i+1}, d^new_{i,v_i+1},
//	                 C_i^auth, R_B^(e), t_i' )
//
// Every field is committed by Hash and therefore by the cumulative chain, the
// PAI entry and the anchored root. Nothing about a completed redaction can be
// changed afterwards without breaking Phase 6's replay.
//
// Round (e) is carried because Phase 6 needs it: psi_{i,k} is verified against
// R_PR^(e_k), "the round index recorded in PR_i^(k)". A record without it could
// not be located in any round's record tree, and the path check would have
// nothing to verify against.
type Record struct {
	TxID          string
	FromVersion   uint64
	ToVersion     uint64
	PolicyID      string
	PolicyVersion uint64
	DID           []byte
	Round         uint64

	OldDigest []byte // d^old: the pre-state digest
	NewDigest []byte // d^new: the post-state digest

	AuthCommit []byte // C_i^auth
	BatchRoot  []byte // R_B^(e)

	CompletedAt time.Time
}

// Hash is H(PR_i^(v_i+1)): the value the cumulative chain and the round's
// record tree both commit to.
//
// The timestamp is included. It is a field of the record in Eq.
// (provenance-record), and omitting it would leave a completion time that could
// be rewritten after the fact while every check in Phase 6 still passed.
func (r *Record) Hash() []byte {
	return digest(tagRecord,
		[]byte(r.TxID),
		u64(r.FromVersion),
		u64(r.ToVersion),
		[]byte(r.PolicyID),
		u64(r.PolicyVersion),
		r.DID,
		u64(r.Round),
		r.OldDigest,
		r.NewDigest,
		r.AuthCommit,
		r.BatchRoot,
		u64(uint64(r.CompletedAt.UnixNano())),
	)
}

// Bytes reports the record's wire size, for Exp 3's evidence accounting.
func (r *Record) Bytes() int {
	return len(r.TxID) + len(r.PolicyID) + len(r.DID) +
		len(r.OldDigest) + len(r.NewDigest) +
		len(r.AuthCommit) + len(r.BatchRoot) +
		5*8 // FromVersion, ToVersion, PolicyVersion, Round, CompletedAt
}

// Export converts to the harness's cross-scheme record shape, so Exp 3 can
// report history uniformly without any scheme's internals leaking into results.
func (r *Record) Export() scheme.ProvenanceRecord {
	return scheme.ProvenanceRecord{
		TxID:          r.TxID,
		FromVersion:   r.FromVersion,
		ToVersion:     r.ToVersion,
		PolicyID:      r.PolicyID,
		PolicyVersion: r.PolicyVersion,
		OldDigest:     r.OldDigest,
		NewDigest:     r.NewDigest,
		AuthEvidence:  r.AuthCommit,
		BatchRoot:     r.BatchRoot,
		CompletedAt:   r.CompletedAt,
	}
}

// RecordTree builds the round's record tree, whose root is Eq.
// (round-record-root):
//
//	R_PR^(e) = MerkleRoot({ H(PR_i^(v_i+1)) }_{i in Q_succ^(e)})
//
// Phase 4 Step 5 needs the ROOT to form C_B^(e); Phase 6 needs the TREE, to
// produce psi_{i,k}. Both come from here so the leaf encoding is defined once —
// a producer and a verifier that hashed leaves differently would fail every
// path check with nothing indicating that the encodings, rather than the
// records, had diverged.
//
// Leaves are already domain-separated by Record.Hash's tag, which is why this
// uses NewFromHashes and callers verify with merkle.VerifyHash.
func RecordTree(records []*Record) (*merkle.Tree, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("pai: a round with no successful records has no record tree")
	}
	hashes := make([][]byte, len(records))
	for i, r := range records {
		if r == nil {
			return nil, fmt.Errorf("pai: nil record at position %d", i)
		}
		hashes[i] = r.Hash()
	}
	return merkle.NewFromHashes(hashes)
}

// Anchor is AR^(e), Eq. (pai-anchor-record):
//
//	AR^(e) = ( e, R_PAI^(e), R_PAI^(e-1), C_B^(e), AC^(e) )
//
// Recorded on the permissioned blockchain. It is the only thing Phase 6 has to
// read from the chain besides the transaction's own state, which is why the
// audit's block count does not grow with the ledger.
type Anchor struct {
	Round           uint64
	Root            []byte // R_PAI^(e)
	PrevRoot        []byte // R_PAI^(e-1)
	BatchCommitment []byte // C_B^(e)
	Commitment      []byte // AC^(e)

	// RecordRoot is R_PR^(e). It is bound into C_B^(e) rather than being a
	// separate field of AR^(e); it is carried here because Phase 6 verifies
	// psi_{i,k} against it and would otherwise have to trust the PAI's copy.
	RecordRoot []byte
}

// Bytes reports the anchor's wire size, for Exp 3's evidence accounting.
func (a *Anchor) Bytes() int {
	return 8 + len(a.Root) + len(a.PrevRoot) + len(a.BatchCommitment) +
		len(a.Commitment) + len(a.RecordRoot)
}

// AuditEvidence is E_i^(e) from Eq. (audit-retrieval) together with the extra
// material Phase 6 Step 2 says the PAI additionally returns:
//
//	E_i^(e) = ( H_i^(v_i), v_i, c_i^(v_i), A_i^(v_i), mu_i^(e) )
//
// plus, per record, the path psi_{i,k} and the public evidence (x_{i,k},
// pi_{i,k}) retrieved from the off-chain store.
//
// InitialDigest and CurrentDigest are NOT from the PAI. Phase 6 Step 2 has the
// auditor obtain the authenticated initial and round-e transaction states from
// the PERMISSIONED BLOCKCHAIN, so they are filled in by the caller that holds
// the ledger. Keeping them in the same struct is what lets Verify perform the
// boundary checks; sourcing them from the PAI would make the audit verify the
// PAI against itself.
type AuditEvidence struct {
	History    []*Record
	Version    uint64
	Cumulative []byte
	EntryValue []byte
	EntryPath  *merkle.Proof

	// RecordPaths[k] is psi_{i,k} for History[k]; RecordRoots[k] is the
	// R_PR^(e_k) it is verified against, taken from AR^(e_k).
	RecordPaths []*merkle.Proof
	RecordRoots [][]byte

	// Statements[k] and Proofs[k] are (x_{i,k}, pi_{i,k}) from the off-chain
	// audit-evidence store, keyed by the record's DID.
	Statements []*zk.Statement
	Proofs     [][]byte

	// Anchor is AR^(e), read from the blockchain.
	Anchor *Anchor

	// RootAtEpoch is R_PAI^(e), the root mu_i^(e) authenticates against. It
	// equals Anchor.Root; kept separate so Verify can check that identity
	// rather than assume it.
	RootAtEpoch []byte

	// InitialDigest is d_{i,0} = H(T_i^(0)) and CurrentDigest is H(T_i^(v_i)),
	// both from the blockchain.
	InitialDigest []byte
	CurrentDigest []byte

	// BlocksTraversed counts the blockchain blocks the retrieval touched.
	BlocksTraversed int
}

// Bytes is the total evidence size Exp 3 reports.
func (e *AuditEvidence) Bytes() int {
	n := len(e.Cumulative) + len(e.EntryValue) + len(e.InitialDigest) + len(e.CurrentDigest) + 8
	for _, r := range e.History {
		n += r.Bytes()
	}
	if e.EntryPath != nil {
		n += e.EntryPath.Bytes()
	}
	for _, p := range e.RecordPaths {
		if p != nil {
			n += p.Bytes()
		}
	}
	for _, r := range e.RecordRoots {
		n += len(r)
	}
	for _, p := range e.Proofs {
		n += len(p)
	}
	if e.Anchor != nil {
		n += e.Anchor.Bytes()
	}
	return n
}
