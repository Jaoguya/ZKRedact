package pai

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"zkredact/pkg/zk"
)

// These tests reach the failure modes the scheme-level tests cannot construct.
// Going through zkredact.Redact means the executor has already enforced
// ordering and continuity, so a bug in the index's OWN guards would be masked
// by a correct caller — and would only surface the day something else called it.

func testIndex(t *testing.T, n int) *Index {
	t.Helper()
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("tx-%03d", i)
	}
	ix, err := NewIndex(ids, func(id string) ([]byte, error) {
		return StateDigest(id, 0, []byte("core-"+id), []byte("payload-"+id)), nil
	})
	if err != nil {
		t.Fatalf("NewIndex: %v", err)
	}
	return ix
}

// record builds a record that legitimately continues from a transaction's
// current state, so a test only has to break the one thing it is about.
func record(t *testing.T, ix *Index, txID string, round uint64) *Record {
	t.Helper()
	ix.mu.RLock()
	st := ix.state[txID]
	var prev []byte
	if len(st.history) == 0 {
		prev = st.initialDigest
	} else {
		prev = st.history[len(st.history)-1].NewDigest
	}
	version := st.version
	ix.mu.RUnlock()

	return &Record{
		TxID:        txID,
		FromVersion: version,
		ToVersion:   version + 1,
		PolicyID:    "pol-0",
		DID:         []byte(fmt.Sprintf("did-%s-%d", txID, round)),
		Round:       round,
		OldDigest:   prev,
		NewDigest:   StateDigest(txID, version+1, []byte("core-"+txID), []byte(fmt.Sprintf("v%d", round))),
		AuthCommit:  []byte("auth"),
		BatchRoot:   []byte("batch"),
		CompletedAt: time.Now(),
	}
}

func commit(t *testing.T, ix *Index, round uint64, recs ...*Record) (*Anchor, error) {
	t.Helper()
	tree, err := RecordTree(recs)
	if err != nil {
		return nil, err
	}
	// Phase 4 Step 4 stores (x_i, pi_i) under DID_i as each redaction
	// completes, so a round committed without it is not a state the executor
	// can produce. Retrieve refuses such a record, which is correct — these
	// tests are about the index's other guards, so the evidence is supplied.
	for _, r := range recs {
		if err := ix.StoreEvidence(r.DID, &zk.Statement{
			TxID: []byte(r.TxID), TxVersion: r.FromVersion, PolicyID: []byte(r.PolicyID),
		}, []byte("proof-"+string(r.DID))); err != nil {
			return nil, err
		}
	}
	return ix.Commit(round, recs, tree, []byte(fmt.Sprintf("C_B-%d", round)))
}

func TestCommitAdvancesTheAnchorChain(t *testing.T) {
	ix := testIndex(t, 8)
	prevRoot := ix.Root()

	for round := uint64(1); round <= 3; round++ {
		a, err := commit(t, ix, round, record(t, ix, "tx-000", round))
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if !bytes.Equal(a.PrevRoot, prevRoot) {
			t.Errorf("round %d anchors to %x, but the previous root was %x",
				round, a.PrevRoot, prevRoot)
		}
		if bytes.Equal(a.Root, prevRoot) {
			t.Errorf("round %d did not move R_PAI", round)
		}
		want := AnchorCommitment(round, a.Root, a.PrevRoot, a.BatchCommitment)
		if !bytes.Equal(want, a.Commitment) {
			t.Errorf("round %d anchor commitment does not recompute", round)
		}
		prevRoot = a.Root
	}

	if v, _ := ix.Version("tx-000"); v != 3 {
		t.Errorf("version %d after three rounds, want 3", v)
	}
}

// TestCommitRefusesARoundGap guards the anchor chain. AC^(e) binds R_PAI^(e-1),
// so a skipped round leaves a predecessor no anchor ever published, and every
// later audit fails against it.
func TestCommitRefusesARoundGap(t *testing.T) {
	ix := testIndex(t, 4)
	if _, err := commit(t, ix, 2, record(t, ix, "tx-000", 2)); err == nil {
		t.Error("round 2 was committed with no round 1; the anchor chain now has a gap")
	}
	if _, err := commit(t, ix, 1, record(t, ix, "tx-000", 1)); err != nil {
		t.Fatalf("round 1: %v", err)
	}
	if _, err := commit(t, ix, 1, record(t, ix, "tx-001", 1)); err == nil {
		t.Error("round 1 was committed twice")
	}
}

// TestCommitRefusesADiscontinuousRecord pins Eq. (history-continuity) at the
// index rather than only at the executor.
func TestCommitRefusesADiscontinuousRecord(t *testing.T) {
	ix := testIndex(t, 4)

	rec := record(t, ix, "tx-000", 1)
	rec.OldDigest = []byte("not the initial state")
	if _, err := commit(t, ix, 1, rec); err == nil {
		t.Error("a record that does not continue from the initial state was committed")
	}

	rec = record(t, ix, "tx-000", 1)
	rec.ToVersion = 5
	if _, err := commit(t, ix, 1, rec); err == nil {
		t.Error("a record skipping versions was committed")
	}
}

// TestCommitIsAtomic is the property that keeps a failed round from becoming a
// false audit failure.
//
// A partially applied round advances some transactions against a root that was
// never anchored. Phase 6 would then report those histories as tampered — a
// real defect wearing the costume of an attack.
func TestCommitIsAtomic(t *testing.T) {
	ix := testIndex(t, 4)

	good := record(t, ix, "tx-000", 1)
	bad := record(t, ix, "tx-001", 1)
	bad.OldDigest = []byte("broken")

	rootBefore := ix.Root()
	if _, err := commit(t, ix, 1, good, bad); err == nil {
		t.Fatal("a round containing an invalid record was committed")
	}

	if !bytes.Equal(rootBefore, ix.Root()) {
		t.Error("R_PAI moved despite the round being rejected")
	}
	if v, _ := ix.Version("tx-000"); v != 0 {
		t.Errorf("tx-000 advanced to version %d in a rejected round", v)
	}
	if ix.Round() != 0 {
		t.Errorf("the round counter advanced to %d despite the failure", ix.Round())
	}
}

// TestCommitChainsSameTargetRecordsWithinARound covers the case the working-copy
// state exists for: two records for one transaction in a single round must
// chain through each other, not both start from the committed version.
func TestCommitChainsSameTargetRecordsWithinARound(t *testing.T) {
	ix := testIndex(t, 4)

	first := record(t, ix, "tx-000", 1)
	second := &Record{
		TxID:        "tx-000",
		FromVersion: 1,
		ToVersion:   2,
		PolicyID:    "pol-0",
		DID:         []byte("did-second"),
		Round:       1,
		OldDigest:   first.NewDigest,
		NewDigest:   StateDigest("tx-000", 2, []byte("core-tx-000"), []byte("v2")),
		AuthCommit:  []byte("auth"),
		BatchRoot:   []byte("batch"),
		CompletedAt: time.Now(),
	}
	if _, err := commit(t, ix, 1, first, second); err != nil {
		t.Fatalf("two chained records in one round: %v", err)
	}
	if v, _ := ix.Version("tx-000"); v != 2 {
		t.Errorf("version %d, want 2", v)
	}
}

// TestCommitRefusesAMisroundedRecord: psi_{i,k} is verified against R_PR^(e_k)
// for the round the record NAMES, so a record whose Round field disagrees with
// the round committing it could never be located again.
func TestCommitRefusesAMisroundedRecord(t *testing.T) {
	ix := testIndex(t, 4)
	rec := record(t, ix, "tx-000", 1)
	rec.Round = 7
	if _, err := commit(t, ix, 1, rec); err == nil {
		t.Error("a record naming a different round was committed")
	}
}

// TestRetrieveRefusesAHistoricalEpoch. Only the current PAI root is
// materialised; answering an older epoch against it would authenticate a state
// the query did not ask about, which is worse than refusing.
func TestRetrieveRefusesAHistoricalEpoch(t *testing.T) {
	ix := testIndex(t, 4)
	for round := uint64(1); round <= 3; round++ {
		if _, err := commit(t, ix, round, record(t, ix, "tx-000", round)); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
	}
	if _, err := ix.Retrieve("tx-000", 1); err == nil {
		t.Error("an audit against a superseded epoch was answered")
	}
	if _, err := ix.Retrieve("tx-000", 0); err != nil {
		t.Errorf("the latest epoch was refused: %v", err)
	}
	if _, err := ix.Retrieve("no-such-tx", 0); err == nil {
		t.Error("an unindexed transaction was retrieved")
	}
}

func TestNewIndexRejectsBadInput(t *testing.T) {
	digestOK := func(string) ([]byte, error) { return []byte("d"), nil }

	if _, err := NewIndex(nil, digestOK); err == nil {
		t.Error("an empty index was accepted")
	}
	if _, err := NewIndex([]string{"a", "a"}, digestOK); err == nil {
		t.Error("duplicate transactions were accepted; two leaves would share a slot")
	}
	if _, err := NewIndex([]string{"a"}, nil); err == nil {
		t.Error("an index was built with no initial state digests")
	}
	if _, err := NewIndex([]string{"a"}, func(string) ([]byte, error) {
		return nil, nil
	}); err == nil {
		t.Error("an empty initial digest was accepted; the boundary check would compare nothing")
	}
}
