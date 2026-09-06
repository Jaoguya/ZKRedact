package pai

import (
	"bytes"
	"fmt"

	"zkredact/pkg/merkle"
	"zkredact/pkg/zk"
)

// Verify performs Phase 6 Steps 3 to 5: everything the auditor checks for
// itself, using only the retrieved evidence and the system's public parameters.
//
// Nothing here consults the Index. That is the point of the split — an audit
// that asked the PAI whether the PAI was correct would verify nothing. Every
// value compared below either arrives in the evidence or is recomputed from it.
//
//	Step 3  A_i^(v_i) recomputed and checked against R_PAI^(e) via mu_i^(e);
//	        the cumulative chain replayed from the authenticated initial state;
//	        length and terminal commitment checked.
//	Step 4  per record: the ZK authorization, the record's path psi_{i,k},
//	        state and version continuity, and the two boundary states.
//	Step 5  the anchor commitment AC^(e).
//
// Returns nil when the history is authentic. Every other return says which
// check failed and why, because "audit failed" on its own is not a usable
// result for either a run or a bug report.
func Verify(params *zk.Params, registryRoot []byte, txID string, ev *AuditEvidence) error {
	if ev == nil {
		return fmt.Errorf("pai: no evidence to verify")
	}
	if ev.Anchor == nil {
		return fmt.Errorf("pai: evidence carries no anchor; there is nothing to verify against")
	}
	if len(registryRoot) == 0 {
		return fmt.Errorf("pai: no credential registry root; ZK authorization could not be checked")
	}

	// The root mu_i^(e) is checked against must be the anchored one. Verifying
	// against a root the PAI supplied separately would let the index choose the
	// state its own evidence authenticates against.
	if !bytes.Equal(ev.RootAtEpoch, ev.Anchor.Root) {
		return fmt.Errorf(
			"pai: the retrieved root %x is not the anchored root %x for round %d",
			ev.RootAtEpoch, ev.Anchor.Root, ev.Anchor.Round)
	}

	if err := verifyEntry(txID, ev); err != nil {
		return err
	}
	if err := verifyHistoryChain(txID, ev); err != nil {
		return err
	}
	if err := verifyRecords(params, registryRoot, txID, ev); err != nil {
		return err
	}
	if err := verifyBoundaries(ev); err != nil {
		return err
	}
	return verifyAnchor(ev)
}

// verifyEntry is Eq. (audit-entry) and Eq. (audit-merkle).
func verifyEntry(txID string, ev *AuditEvidence) error {
	recomputed := Entry(txID, ev.Version, ev.Cumulative)
	if !bytes.Equal(recomputed, ev.EntryValue) {
		return fmt.Errorf(
			"pai: recomputed PAI entry %x does not match the retrieved one %x",
			recomputed, ev.EntryValue)
	}
	if ev.EntryPath == nil {
		return fmt.Errorf("pai: no authentication path mu_i^(e) for %s", txID)
	}
	if !merkle.Verify(ev.Anchor.Root, recomputed, ev.EntryPath) {
		return fmt.Errorf(
			"pai: entry for %s at version %d is not in the anchored PAI root",
			txID, ev.Version)
	}
	return nil
}

// verifyHistoryChain is Eq. (audit-initial), (audit-chain) and
// (audit-completeness): replay the cumulative commitment from the authenticated
// initial state and check both its length and its terminal value.
//
// This is the check that detects a missing, inserted, reordered or truncated
// record. The length test is not redundant with the chain test: a truncated
// history replays to a perfectly valid commitment for the shorter chain, and
// only the version pins which length was anchored.
func verifyHistoryChain(txID string, ev *AuditEvidence) error {
	if len(ev.InitialDigest) == 0 {
		return fmt.Errorf("pai: no authenticated initial state for %s", txID)
	}
	if uint64(len(ev.History)) != ev.Version {
		return fmt.Errorf(
			"pai: %s carries %d provenance records but is at version %d; the "+
				"history is incomplete or padded",
			txID, len(ev.History), ev.Version)
	}

	c := InitialCumulative(txID, ev.InitialDigest)
	for k, rec := range ev.History {
		if rec == nil {
			return fmt.Errorf("pai: nil record at position %d of %s's history", k, txID)
		}
		if rec.TxID != txID {
			return fmt.Errorf(
				"pai: record %d of %s's history belongs to %s", k, txID, rec.TxID)
		}
		c = NextCumulative(c, rec.Hash())
	}
	if !bytes.Equal(c, ev.Cumulative) {
		return fmt.Errorf(
			"pai: replayed cumulative commitment %x does not match the anchored %x "+
				"for %s; the history has been altered", c, ev.Cumulative, txID)
	}
	return nil
}

// verifyRecords is Phase 6 Step 4 per record: the authorization evidence, the
// record's own Merkle path, and the version and state continuity between
// successive records.
func verifyRecords(params *zk.Params, registryRoot []byte, txID string, ev *AuditEvidence) error {
	n := len(ev.History)
	if len(ev.RecordPaths) != n || len(ev.RecordRoots) != n ||
		len(ev.Statements) != n || len(ev.Proofs) != n {
		return fmt.Errorf(
			"pai: %s returned %d records but %d paths, %d roots, %d statements and %d proofs",
			txID, n, len(ev.RecordPaths), len(ev.RecordRoots), len(ev.Statements), len(ev.Proofs))
	}

	for k, rec := range ev.History {
		// --- psi_{i,k}: the record is in its own round's record tree ---
		if !merkle.VerifyHash(ev.RecordRoots[k], rec.Hash(), ev.RecordPaths[k]) {
			return fmt.Errorf(
				"pai: record %d of %s is not in the anchored record root for round %d",
				k, txID, rec.Round)
		}

		// --- the statement must describe THIS record ---
		//
		// Without this the proof would only have to be a valid proof of
		// something. A record could then cite an authorization issued for a
		// different transaction, version or policy, and every other check —
		// including ZK.Verify — would still pass.
		st := ev.Statements[k]
		if st == nil {
			return fmt.Errorf("pai: record %d of %s has no statement", k, txID)
		}
		if !bytes.Equal(st.TxID, zk.FieldBytes([]byte(rec.TxID))) {
			return fmt.Errorf(
				"pai: record %d of %s cites a proof for a different transaction", k, txID)
		}
		if st.TxVersion != rec.FromVersion {
			return fmt.Errorf(
				"pai: record %d of %s moves from version %d but cites a proof for version %d",
				k, txID, rec.FromVersion, st.TxVersion)
		}
		if !bytes.Equal(st.PolicyID, zk.FieldBytes([]byte(rec.PolicyID))) {
			return fmt.Errorf(
				"pai: record %d of %s cites a proof for a different policy", k, txID)
		}
		if st.PolicyVersion != rec.PolicyVersion {
			return fmt.Errorf(
				"pai: record %d of %s names policy version %d but cites a proof for %d",
				k, txID, rec.PolicyVersion, st.PolicyVersion)
		}

		// --- Eq. (audit-auth): C_i^auth recomputed from the retrieved evidence ---
		recomputed := AuthCommitment(rec.DID, st.Digest(), ev.Proofs[k])
		if !bytes.Equal(recomputed, rec.AuthCommit) {
			return fmt.Errorf(
				"pai: record %d of %s does not commit to the retrieved evidence", k, txID)
		}

		// --- Eq. (audit-authorization): the proof itself ---
		if err := zk.VerifyEvidence(params, st, registryRoot, ev.Proofs[k]); err != nil {
			return fmt.Errorf(
				"pai: record %d of %s carries an invalid authorization proof: %w", k, txID, err)
		}

		// --- Eq. (audit-state-continuity) and (audit-version-continuity) ---
		if k+1 < n {
			next := ev.History[k+1]
			if !bytes.Equal(rec.NewDigest, next.OldDigest) {
				return fmt.Errorf(
					"pai: %s is discontinuous between records %d and %d: the output "+
						"state is not the next input state", txID, k, k+1)
			}
			if next.ToVersion != rec.ToVersion+1 {
				return fmt.Errorf(
					"pai: %s jumps from version %d to %d between records %d and %d",
					txID, rec.ToVersion, next.ToVersion, k, k+1)
			}
		}
	}
	return nil
}

// verifyBoundaries is Eq. (audit-boundary-states): the history must begin at the
// authenticated initial state and end at the authenticated current one.
//
// The interior continuity checks alone would accept a history that is
// self-consistent but describes a different transaction's evolution. Pinning
// both ends to states obtained from the blockchain is what ties the chain to
// reality.
func verifyBoundaries(ev *AuditEvidence) error {
	if len(ev.History) == 0 {
		// An unredacted transaction: the initial state is the current state.
		if len(ev.CurrentDigest) != 0 && !bytes.Equal(ev.InitialDigest, ev.CurrentDigest) {
			return fmt.Errorf(
				"pai: no redactions are recorded, but the current state differs from the initial one")
		}
		return nil
	}

	first := ev.History[0]
	if !bytes.Equal(first.OldDigest, ev.InitialDigest) {
		return fmt.Errorf(
			"pai: the first record does not start from the authenticated initial state")
	}
	if first.FromVersion != 0 {
		return fmt.Errorf(
			"pai: the first record starts at version %d rather than 0", first.FromVersion)
	}

	last := ev.History[len(ev.History)-1]
	if len(ev.CurrentDigest) == 0 {
		return fmt.Errorf("pai: no authenticated current state to check the history against")
	}
	if !bytes.Equal(last.NewDigest, ev.CurrentDigest) {
		return fmt.Errorf(
			"pai: the last record's output state is not the transaction's current state")
	}
	if last.ToVersion != ev.Version {
		return fmt.Errorf(
			"pai: the last record ends at version %d but the entry is at %d",
			last.ToVersion, ev.Version)
	}
	return nil
}

// verifyAnchor is Eq. (audit-anchor): recompute AC^(e) and compare.
//
// This binds the PAI state the audit just verified to its predecessor and to
// the batch that produced it, so a round cannot be dropped or replaced without
// the substitution being visible in the anchor the blockchain holds.
func verifyAnchor(ev *AuditEvidence) error {
	a := ev.Anchor
	if a.Round == 0 {
		// The genesis anchor commits the initial root against itself; there is
		// no batch, so there is no C_B to bind.
		want := AnchorCommitment(0, a.Root, a.PrevRoot, nil)
		if !bytes.Equal(want, a.Commitment) {
			return fmt.Errorf("pai: the initial anchor's commitment does not recompute")
		}
		return nil
	}
	want := AnchorCommitment(a.Round, a.Root, a.PrevRoot, a.BatchCommitment)
	if !bytes.Equal(want, a.Commitment) {
		return fmt.Errorf(
			"pai: anchor commitment for round %d does not recompute; the anchored "+
				"state, its predecessor or the batch commitment has been altered", a.Round)
	}
	return nil
}
