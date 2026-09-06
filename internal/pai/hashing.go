package pai

import (
	"crypto/sha256"
	"encoding/binary"
)

// The manuscript writes every provenance commitment as H(a || b || c) with a
// single collision-resistant H. Two things about that notation have to be
// decided before it can be code, and both decisions are recorded here rather
// than made silently at each call site.
//
// LENGTH PREFIXES. "||" over variable-length fields is ambiguous: H("ab"||"c")
// and H("a"||"bc") are the same input. Every component below is therefore
// written as an 8-byte big-endian length followed by its bytes, so distinct
// field tuples always produce distinct preimages.
//
// DOMAIN TAGS. Several equations share a shape. Phase 1 Step 5 defines
//
//	c_i^(0) = H(TID_i || 0 || d_{i,0})        (initial provenance)
//	A_i^(0) = H(TID_i || 0 || c_i^(0))        (initial PAI entry)
//
// — the same three-field layout with a different third element. Without a tag,
// a cumulative commitment is a syntactically valid PAI entry and vice versa,
// which would let one be presented in the other's place during Phase 6. Each
// construction therefore commits to its own tag first.
//
// DEVIATION, RECORDED. The manuscript specifies neither. Both are strict
// strengthenings: they add a fixed number of bytes to inputs that were already
// being hashed, so the number of hash invocations — which is what Exp 2 and
// Exp 3 measure — is unchanged. docs/paper-conformance.md carries this.

const (
	tagCumulative = "zkredact/pai/cumulative/v1"   // c_i^(v)
	tagEntry      = "zkredact/pai/entry/v1"        // A_i^(v)
	tagRecord     = "zkredact/pai/record/v1"       // H(PR_i^(v+1))
	tagAnchor     = "zkredact/pai/anchor/v1"       // AC^(e)
	tagAuthCommit = "zkredact/pai/auth/v1"         // C_i^auth
	tagAuditReq   = "zkredact/pai/audit-req/v1"    // H(R_a^audit)
	tagStateDigst = "zkredact/pai/state-digest/v1" // d_{i,k}
)

// digest hashes a tag and a sequence of length-prefixed components.
func digest(tag string, parts ...[]byte) []byte {
	h := sha256.New()
	writeField(h, []byte(tag))
	for _, p := range parts {
		writeField(h, p)
	}
	return h.Sum(nil)
}

type byteWriter interface{ Write([]byte) (int, error) }

func writeField(h byteWriter, b []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(b)))
	_, _ = h.Write(n[:])
	_, _ = h.Write(b)
}

// u64 encodes an integer field for hashing.
func u64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

// -----------------------------------------------------------------------------
// The manuscript's commitments
// -----------------------------------------------------------------------------

// StateDigest is d_{i,k} = H(T_i^(k)): the digest of one transaction state.
//
// T_i is the whole transaction, so the digest covers the immutable core as well
// as the redactable payload — a redaction that silently altered the core would
// otherwise leave the provenance chain intact.
func StateDigest(txID string, version uint64, core, redactable []byte) []byte {
	return digest(tagStateDigst, []byte(txID), u64(version), core, redactable)
}

// InitialCumulative is Eq. (initial-provenance): c_i^(0) = H(TID_i || 0 || d_{i,0}).
func InitialCumulative(txID string, initialDigest []byte) []byte {
	return digest(tagCumulative, []byte(txID), u64(0), initialDigest)
}

// NextCumulative is Eq. (provenance-chain):
//
//	c_i^(v+1) = H(c_i^(v) || H(PR_i^(v+1)))
//
// Phase 6 replays this from c_i^(0) forward; a record that is missing,
// reordered, inserted or altered breaks the replay at that point.
func NextCumulative(prev, recordHash []byte) []byte {
	return digest(tagCumulative, prev, recordHash)
}

// Entry is Eq. (pai-entry): A_i^(v) = H(TID_i || v || c_i^(v)).
//
// Binding the VERSION into the leaf is what makes truncation detectable: a
// prefix of the true history yields a valid cumulative commitment for a shorter
// chain, and only the version number distinguishes it from the real one.
func Entry(txID string, version uint64, cumulative []byte) []byte {
	return digest(tagEntry, []byte(txID), u64(version), cumulative)
}

// AuthCommitment is Eq. (authorization-evidence):
//
//	C_i^auth = H(DID_i || eta_i || H(pi_i))
//
// This is the link between a provenance record and the zero-knowledge proof
// that authorized it. The proof itself lives off-chain; this commitment is what
// makes substituting it detectable in Phase 6.
func AuthCommitment(did, eta, proofBytes []byte) []byte {
	inner := sha256.Sum256(proofBytes)
	return digest(tagAuthCommit, did, eta, inner[:])
}

// AnchorCommitment is Eq. (pai-anchor):
//
//	AC^(e) = H(e || R_PAI^(e) || R_PAI^(e-1) || C_B^(e))
//
// Chaining to the PREDECESSOR root is what stops a whole round being dropped:
// an anchor whose predecessor does not match the previous anchor's root is
// visible without replaying the ledger.
func AnchorCommitment(round uint64, root, prevRoot, batchCommitment []byte) []byte {
	return digest(tagAnchor, u64(round), root, prevRoot, batchCommitment)
}

// AuditRequestDigest is H(R_a^audit) from Eq. (auditor-request), the message
// the auditor signs in Phase 6 Step 1.
func AuditRequestDigest(auditorID, txID string, epoch uint64, timestamp int64, nonce []byte) []byte {
	return digest(tagAuditReq,
		[]byte(auditorID), []byte(txID), u64(epoch), u64(uint64(timestamp)), nonce)
}
