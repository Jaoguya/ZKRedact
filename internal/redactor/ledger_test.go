package redactor

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"

	"zkredact/internal/pai"
	"zkredact/pkg/ch"
	"zkredact/pkg/scheme"
)

func testLedger(t *testing.T, txCount, blockTx int) (*Ledger, *ch.PrivateKey) {
	t.Helper()
	curve := elliptic.P256()
	key, err := ch.KeyGen(curve, rand.Reader)
	if err != nil {
		t.Fatalf("ch.KeyGen: %v", err)
	}

	txs := make([]scheme.Transaction, txCount)
	for i := range txs {
		txs[i] = scheme.Transaction{
			ID:         fmt.Sprintf("tx-%03d", i),
			Core:       []byte(fmt.Sprintf("core-%03d", i)),
			Redactable: []byte(fmt.Sprintf("payload-%03d", i)),
		}
	}
	l, err := NewLedger(curve, key, blockTx, txs)
	if err != nil {
		t.Fatalf("NewLedger: %v", err)
	}
	return l, key
}

// TestAdaptPreservesEveryBlockHash is the chameleon-hash construction's whole
// reason for existing, checked across the entire chain rather than one block.
//
// If the collision were not being used, the redacted transaction's block hash
// would change and every LATER block's back-link would be stale. Checking only
// the redacted block would miss exactly that.
func TestAdaptPreservesEveryBlockHash(t *testing.T) {
	l, _ := testLedger(t, 30, 10)

	before := make([][]byte, l.Blocks())
	for i := range before {
		h, err := l.BlockHash(i)
		if err != nil {
			t.Fatalf("BlockHash(%d): %v", i, err)
		}
		before[i] = h
	}

	// Redact something in the middle block, where a broken link would be most
	// visible.
	if _, _, err := l.Adapt("tx-015", []byte("redacted payload")); err != nil {
		t.Fatalf("Adapt: %v", err)
	}

	for i := range before {
		after, err := l.BlockHash(i)
		if err != nil {
			t.Fatalf("BlockHash(%d): %v", i, err)
		}
		if !bytes.Equal(before[i], after) {
			t.Errorf("block %d's hash changed across a redaction; the chain has forked", i)
		}
		ok, err := l.VerifyBlock(i)
		if err != nil {
			t.Fatalf("VerifyBlock(%d): %v", i, err)
		}
		if !ok {
			t.Errorf("block %d no longer recomputes to its committed root and hash", i)
		}
	}
}

// TestAdaptChangesTheStateAndItsDigest is the other half. Without it the test
// above would pass for an implementation that redacted nothing at all.
func TestAdaptChangesTheStateAndItsDigest(t *testing.T) {
	l, _ := testLedger(t, 10, 10)

	oldDigest, newDigest, err := l.Adapt("tx-003", []byte("something else entirely"))
	if err != nil {
		t.Fatalf("Adapt: %v", err)
	}
	if bytes.Equal(oldDigest, newDigest) {
		t.Error("the state digest did not change across a redaction")
	}

	version, digest, _, err := l.State("tx-003")
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if version != 1 {
		t.Errorf("version %d after one redaction, want 1", version)
	}
	if !bytes.Equal(digest, newDigest) {
		t.Error("the ledger's current digest is not the one Adapt reported")
	}

	// The initial digest must survive: Phase 6's boundary check reads it after
	// the original content is gone.
	d0, err := l.InitialDigest("tx-003")
	if err != nil {
		t.Fatalf("InitialDigest: %v", err)
	}
	if !bytes.Equal(d0, oldDigest) {
		t.Error("the recorded initial digest is not the pre-redaction state")
	}
	if bytes.Equal(d0, digest) {
		t.Error("the initial digest was overwritten by the redaction")
	}
}

// TestSuccessiveAdaptationsChain: each redaction's output digest must be the
// next one's input, which is what Phase 5's continuity requirement asserts.
func TestSuccessiveAdaptationsChain(t *testing.T) {
	l, _ := testLedger(t, 10, 10)

	prev, err := l.InitialDigest("tx-000")
	if err != nil {
		t.Fatalf("InitialDigest: %v", err)
	}
	for i := 0; i < 4; i++ {
		oldD, newD, err := l.Adapt("tx-000", []byte(fmt.Sprintf("revision %d", i)))
		if err != nil {
			t.Fatalf("Adapt %d: %v", i, err)
		}
		if !bytes.Equal(oldD, prev) {
			t.Fatalf("redaction %d starts from %x, but the previous one ended at %x",
				i, oldD, prev)
		}
		prev = newD
	}
	if v, _ := l.Version("tx-000"); v != 4 {
		t.Errorf("version %d after four redactions, want 4", v)
	}
}

func TestAnchorBlocksAreAppendedNotRewritten(t *testing.T) {
	l, _ := testLedger(t, 20, 10)
	heightBefore := l.Blocks()
	hashBefore, err := l.BlockHash(heightBefore - 1)
	if err != nil {
		t.Fatalf("BlockHash: %v", err)
	}

	h, err := l.AppendAnchor(&pai.Anchor{
		Round: 1, Root: []byte("root"), PrevRoot: []byte("prev"),
		BatchCommitment: []byte("cb"), Commitment: []byte("ac"),
	})
	if err != nil {
		t.Fatalf("AppendAnchor: %v", err)
	}
	if h != heightBefore {
		t.Errorf("anchor landed at height %d, want %d", h, heightBefore)
	}
	if l.Blocks() != heightBefore+1 {
		t.Errorf("ledger height %d, want %d", l.Blocks(), heightBefore+1)
	}

	after, err := l.BlockHash(heightBefore - 1)
	if err != nil {
		t.Fatalf("BlockHash: %v", err)
	}
	if !bytes.Equal(hashBefore, after) {
		t.Error("appending an anchor rewrote the previous block")
	}
	if _, ok := l.AnchorBlock(1); !ok {
		t.Error("the anchor's block was not recorded")
	}
}

func TestNewLedgerRejectsBadInput(t *testing.T) {
	curve := elliptic.P256()
	key, err := ch.KeyGen(curve, rand.Reader)
	if err != nil {
		t.Fatalf("ch.KeyGen: %v", err)
	}
	tx := []scheme.Transaction{{ID: "a", Core: []byte("c"), Redactable: []byte("r")}}

	if _, err := NewLedger(curve, nil, 10, tx); err == nil {
		t.Error("a ledger was built with no chameleon-hash key")
	}
	if _, err := NewLedger(curve, key, 0, tx); err == nil {
		t.Error("a block size of zero was accepted")
	}
	if _, err := NewLedger(curve, key, 10, nil); err == nil {
		t.Error("an empty corpus was accepted")
	}
	dup := []scheme.Transaction{tx[0], tx[0]}
	if _, err := NewLedger(curve, key, 10, dup); err == nil {
		t.Error("a duplicate transaction id was accepted; the index would lose one")
	}
}

func TestAdaptRejectsAnUnknownTransaction(t *testing.T) {
	l, _ := testLedger(t, 5, 10)
	if _, _, err := l.Adapt("no-such-tx", []byte("x")); err == nil {
		t.Error("a redaction against an unknown transaction was accepted")
	}
}
