package ref13

import (
	"context"
	"fmt"
	"testing"

	"zkredact/pkg/metrics"
	"zkredact/pkg/scheme"
)

// setupParams builds the parameter map the runner supplies, so the test
// exercises the same keys config.SchemeParams produces.
func setupParams(q, challenged int) map[string]any {
	return map[string]any{
		"arity_q":              q,
		"challenged_blocks":    challenged,
		"corrupted_block_rate": 0.01,
		"optimized_auditing":   true,
		"chameleon_hash_curve": "P-256",
	}
}

func testDataset(n int) *scheme.Dataset {
	txs := make([]scheme.Transaction, n)
	for i := range txs {
		txs[i] = scheme.Transaction{
			ID:         fmt.Sprintf("tx-%d", i),
			Core:       []byte(fmt.Sprintf("core-%d", i)),
			Redactable: []byte(fmt.Sprintf("redactable-payload-%d", i)),
		}
	}
	return &scheme.Dataset{ID: "test", Transactions: txs}
}

func setupScheme(t *testing.T, q, blocks, challenged int) *Scheme {
	t.Helper()
	s := New()
	err := s.Setup(context.Background(), scheme.SetupParams{
		Dataset:      testDataset(blocks),
		Seed:         42,
		SecurityBits: 128,
		Params:       setupParams(q, challenged),
	})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	return s
}

// TestSchemeRunsEndToEnd is the gate task 7 was blocked on: ref13 no longer
// returns ErrNotImplemented anywhere on the measured paths.
func TestSchemeRunsEndToEnd(t *testing.T) {
	s := setupScheme(t, 5, 60, 8)
	ctx := context.Background()

	auth, err := s.Authorize(ctx, &scheme.Request{
		ID: "r1", TargetTxID: "tx-10", NewContent: []byte("replacement"),
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !auth.Granted {
		t.Fatalf("authorization denied: %s", auth.Reason)
	}

	res, err := s.Redact(ctx, []*scheme.Authorization{auth})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if res.Succeeded != 1 {
		t.Errorf("Succeeded = %d, want 1 (failed %d, stale %d)",
			res.Succeeded, res.Failed, res.StaleExcluded)
	}
	// Exp 2's whole comparison is CryptoTime against LedgerTime, so both must be
	// populated — but only a host with a usable clock can see it. On a coarse
	// clock every sub-tick duration reads as exactly zero, which is the failure
	// pkg/metrics/resolution.go exists to catch, and asserting non-zero here
	// would just reproduce it as a flaky test.
	if metrics.ClockIsUsable() {
		if res.CryptoTime == 0 || res.LedgerTime == 0 {
			t.Errorf("CryptoTime=%v LedgerTime=%v; Exp 2 separates them and a "+
				"zero makes the ratio undefined", res.CryptoTime, res.LedgerTime)
		}
	} else {
		t.Logf("clock resolution %v is too coarse to check the cost split; "+
			"skipped, as a real run would be refused on this host",
			metrics.ClockResolution())
	}

	audit, err := s.Audit(ctx, &scheme.AuditQuery{AuditorID: "a"})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if !audit.Verified {
		t.Error("audit of an untampered ledger did not verify")
	}
	if audit.Semantics != scheme.SemanticsLedgerIntegrity {
		t.Errorf("Semantics = %q, want ledger_integrity", audit.Semantics)
	}
}

// TestAuthorizeDeniesAnUnknownTarget is the negative for Exp 1's guards: a
// scheme that granted everything would trip the all-granted check, and one that
// could never deny is not authorizing.
func TestAuthorizeDeniesAnUnknownTarget(t *testing.T) {
	s := setupScheme(t, 5, 20, 4)

	auth, err := s.Authorize(context.Background(), &scheme.Request{
		ID: "r1", TargetTxID: "tx-does-not-exist",
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if auth.Granted {
		t.Error("a request against a transaction not in the chain was granted")
	}
	if auth.Reason == "" {
		t.Error("a denial must say why")
	}
}

// TestRedactExcludesStaleAuthorizations pins the freshness bookkeeping Exp 2
// reports: a request authorized against an older version must be excluded, not
// silently applied.
func TestRedactExcludesStaleAuthorizations(t *testing.T) {
	s := setupScheme(t, 5, 20, 4)
	ctx := context.Background()

	first, err := s.Authorize(ctx, &scheme.Request{
		ID: "r1", TargetTxID: "tx-5", NewContent: []byte("one"),
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	second, err := s.Authorize(ctx, &scheme.Request{
		ID: "r2", TargetTxID: "tx-5", NewContent: []byte("two"),
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	if _, err := s.Redact(ctx, []*scheme.Authorization{first}); err != nil {
		t.Fatalf("Redact: %v", err)
	}
	// second was authorized against the pre-redaction version.
	res, err := s.Redact(ctx, []*scheme.Authorization{second})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if res.StaleExcluded != 1 {
		t.Errorf("StaleExcluded = %d, want 1 — a stale authorization was applied",
			res.StaleExcluded)
	}
}

// TestRedactionIsVisibleInTheAudit ties the two halves together: after a
// redaction the ledger must still audit clean, and the root must have moved.
func TestRedactionIsVisibleInTheAudit(t *testing.T) {
	s := setupScheme(t, 5, 40, 6)
	ctx := context.Background()

	before := s.bat.Root()

	auth, err := s.Authorize(ctx, &scheme.Request{
		ID: "r1", TargetTxID: "tx-20", NewContent: []byte("new"),
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if _, err := s.Redact(ctx, []*scheme.Authorization{auth}); err != nil {
		t.Fatalf("Redact: %v", err)
	}

	after := s.bat.Root()
	if before.Equal(&after) {
		t.Error("a redaction left the BAT root unchanged")
	}

	audit, err := s.Audit(ctx, &scheme.AuditQuery{AuditorID: "a"})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if !audit.Verified {
		t.Error("the ledger did not audit clean after a legitimate redaction")
	}
}

// TestAuditReportsUnionNotLedgerSize pins that BlocksTraversed is the path
// union. A scheme declaring LedgerIndependentAudit whose value grows with the
// ledger is contradicting itself, and the harness is meant to catch that.
func TestAuditReportsUnionNotLedgerSize(t *testing.T) {
	ctx := context.Background()

	small := setupScheme(t, 5, 50, 8)
	large := setupScheme(t, 5, 500, 8)

	a, err := small.Audit(ctx, &scheme.AuditQuery{})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	b, err := large.Audit(ctx, &scheme.AuditQuery{})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}

	t.Logf("50 blocks: %d traversed | 500 blocks: %d traversed",
		a.BlocksTraversed, b.BlocksTraversed)

	if a.BlocksTraversed >= 50 || b.BlocksTraversed >= 500 {
		t.Error("BlocksTraversed is tracking the ledger, not the path union")
	}
	if b.BlocksTraversed > a.BlocksTraversed*3 {
		t.Errorf("traversal grew %d to %d for a 10x ledger; the audit is not "+
			"ledger-independent", a.BlocksTraversed, b.BlocksTraversed)
	}
}

// TestSetupRefusesAnUnderSizedLedger keeps a run from quietly measuring a
// smaller audit sample than the config asked for.
func TestSetupRefusesAnUnderSizedLedger(t *testing.T) {
	s := New()
	err := s.Setup(context.Background(), scheme.SetupParams{
		Dataset:      testDataset(10),
		Seed:         1,
		SecurityBits: 128,
		Params:       setupParams(5, 300),
	})
	if err == nil {
		t.Error("challenged_blocks=300 against a 10-block ledger was accepted")
	}
}

// TestSetupRefusesAChangedCorruptionRate pins that challenged_blocks and the
// rate it was derived from cannot drift apart.
func TestSetupRefusesAChangedCorruptionRate(t *testing.T) {
	params := setupParams(5, 8)
	params["corrupted_block_rate"] = 0.05

	s := New()
	err := s.Setup(context.Background(), scheme.SetupParams{
		Dataset:      testDataset(60),
		Seed:         1,
		SecurityBits: 128,
		Params:       params,
	})
	if err == nil {
		t.Error("a corruption rate other than 1% was accepted while keeping " +
			"a sample size derived at 1%")
	}
}

// TestSetupRefusesAMissingArity is the regression guard for the defect that
// blocked this scheme: arity_q was declared swept and never injected.
func TestSetupRefusesAMissingArity(t *testing.T) {
	params := setupParams(5, 8)
	delete(params, "arity_q")

	s := New()
	err := s.Setup(context.Background(), scheme.SetupParams{
		Dataset:      testDataset(60),
		Seed:         1,
		SecurityBits: 128,
		Params:       params,
	})
	if err == nil {
		t.Error("Setup succeeded without arity_q; it must fail loudly rather " +
			"than pick a default the config did not choose")
	}
}

// TestArityIsHonoured pins that the swept value reaches the tree. A scheme that
// accepted arity_q and then built a fixed-arity tree would report a sweep it
// never performed.
func TestArityIsHonoured(t *testing.T) {
	for _, q := range []int{2, 5, 10} {
		t.Run(fmt.Sprintf("q=%d", q), func(t *testing.T) {
			s := setupScheme(t, q, 60, 4)
			if s.bat.q != q {
				t.Errorf("BAT arity %d, configured %d", s.bat.q, q)
			}
			if s.vcParams.N != q+1 {
				t.Errorf("vector dimension %d, want q+1 = %d", s.vcParams.N, q+1)
			}
		})
	}
}

// TestRedactionKeepsTheChameleonHashAndMovesTheRoot pins the division of labour
// that this file originally got backwards.
//
// A redaction must do BOTH of these, and doing only one breaks the scheme in a
// different direction each way:
//
//   - ch_i UNCHANGED. That is what the collision buys: h_i = H(ch_i, ctr_i) is
//     preserved, so every later block stays valid and nothing is re-mined. If
//     ch_i moved, the chain would break after every redaction.
//   - BAT root CHANGED. m_i is the content, and Algorithm 1 propagates the new
//     value to the root. If the root did not move, a light node could not tell
//     redacted data from stale data — which is precisely the attack VRBC
//     exists to stop, so the scheme would be pointless.
//
// The original implementation committed ch_i to the BAT, so the root never
// moved. It passed every unit test in bat_test.go and was caught only here.
func TestRedactionKeepsTheChameleonHashAndMovesTheRoot(t *testing.T) {
	s := setupScheme(t, 5, 40, 6)
	ctx := context.Background()

	const target = "tx-17"
	seq := s.blockOf[target]
	before := s.blocks[seq-1]
	chBefore := *before.value
	rootBefore := s.bat.Root()

	auth, err := s.Authorize(ctx, &scheme.Request{
		ID: "r1", TargetTxID: target, NewContent: []byte("redacted content"),
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	res, err := s.Redact(ctx, []*scheme.Authorization{auth})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if res.Succeeded != 1 {
		t.Fatalf("redaction did not apply: %+v", res)
	}

	after := s.blocks[seq-1]
	if !chBefore.Equal(after.value) {
		t.Error("the chameleon hash changed; a collision must leave ch_i fixed, " +
			"or h_i moves and the chain breaks after every redaction")
	}

	rootAfter := s.bat.Root()
	if rootBefore.Equal(&rootAfter) {
		t.Error("the BAT root did not move; the tree is committing to something " +
			"a redaction does not change, so redacted and stale data are " +
			"indistinguishable to a light node")
	}

	// And the new content really is what the block now holds.
	if string(after.redactable) != "redacted content" {
		t.Errorf("block content = %q, want the replacement", after.redactable)
	}
}

// TestEq12CatchesWhatEq11Cannot is the reason both checks exist.
//
// The attack: change a block's content WITHOUT computing a chameleon-hash
// collision, then rebind the BAT to the new digest. Eq. 11 is now perfectly
// valid — the root really does commit to the new m_s — but no legitimate
// (r_s, Y_s) hashes that content to ch_s, so the chain is lying about what was
// ever agreed. Only Eq. 12 sees it.
//
// If this test starts passing with Eq. 12 removed, the audit has stopped
// checking that on-chain data was ever validly produced, and Exp 3 would be
// reporting a verifier cheaper than the scheme specifies.
func TestEq12CatchesWhatEq11Cannot(t *testing.T) {
	s := setupScheme(t, 5, 60, 6)
	ctx := context.Background()

	const target = "tx-11"
	seq := s.blockOf[target]

	// Sanity: the ledger audits clean first, so a later failure means the
	// tampering and not a broken fixture.
	before, err := s.Audit(ctx, &scheme.AuditQuery{TargetTxID: target})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if !before.Verified {
		t.Fatal("an untampered block did not verify; this test proves nothing")
	}

	// Tamper: new content, new commitment, NO collision.
	b := s.blocks[seq-1]
	b.redactable = []byte("content that was never chameleon-hashed")
	if err := s.bat.Bind(seq, scalarOf(blockDigest(b.core, b.redactable))); err != nil {
		t.Fatalf("rebind: %v", err)
	}

	// Eq. 11 alone still holds: the root commits to the new digest.
	proof, err := s.bat.ProveAudit(
		Challenge{Z: 1, Phi1: []byte("a"), Phi2: []byte("b")}, []int{seq})
	if err != nil {
		t.Fatalf("ProveAudit: %v", err)
	}
	pairingOK, err := s.bat.VerifyAudit(s.bat.Root(),
		Challenge{Z: 1, Phi1: []byte("a"), Phi2: []byte("b")}, proof)
	if err != nil {
		t.Fatalf("VerifyAudit: %v", err)
	}
	if !pairingOK {
		t.Fatal("the pairing check rejected the tampered block, so this test is " +
			"not demonstrating what Eq. 12 adds")
	}

	// But the full audit must fail, and only Eq. 12 can be what fails it.
	after, err := s.Audit(ctx, &scheme.AuditQuery{TargetTxID: target})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if after.Verified {
		t.Error("a block whose content was never chameleon-hashed passed the " +
			"audit; Eq. 12 is not being checked")
	}
}

// TestEq12AcceptsALegitimateRedaction is the other half: a redaction done
// properly, through a collision, must still verify. A check that rejected
// everything would pass the test above and be useless.
func TestEq12AcceptsALegitimateRedaction(t *testing.T) {
	s := setupScheme(t, 5, 60, 6)
	ctx := context.Background()

	const target = "tx-11"
	auth, err := s.Authorize(ctx, &scheme.Request{
		ID: "r1", TargetTxID: target, NewContent: []byte("lawfully redacted"),
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if _, err := s.Redact(ctx, []*scheme.Authorization{auth}); err != nil {
		t.Fatalf("Redact: %v", err)
	}

	res, err := s.Audit(ctx, &scheme.AuditQuery{TargetTxID: target})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if !res.Verified {
		t.Error("a properly redacted block failed the audit; the collision path " +
			"and Eq. 12 disagree about what a valid block looks like")
	}
}

// TestBlockQueryAndBlockchainAuditAreBothReachable pins the protocol split: the
// spec measures two protocols and the Scheme interface has one method, so the
// selection has to work or one of the two is never measured.
func TestBlockQueryAndBlockchainAuditAreBothReachable(t *testing.T) {
	s := setupScheme(t, 5, 200, 8)
	ctx := context.Background()

	query, err := s.Audit(ctx, &scheme.AuditQuery{TargetTxID: "tx-42"})
	if err != nil {
		t.Fatalf("block query: %v", err)
	}
	audit, err := s.Audit(ctx, &scheme.AuditQuery{})
	if err != nil {
		t.Fatalf("blockchain audit: %v", err)
	}

	if !query.Verified || !audit.Verified {
		t.Fatalf("query verified=%v, audit verified=%v; both must",
			query.Verified, audit.Verified)
	}
	t.Logf("block query: %d nodes, %d bytes | blockchain audit: %d nodes, %d bytes",
		query.BlocksTraversed, query.EvidenceBytes,
		audit.BlocksTraversed, audit.EvidenceBytes)

	// One block's path must be cheaper than z blocks' union, or the two
	// protocols are not actually distinct.
	if query.BlocksTraversed >= audit.BlocksTraversed {
		t.Errorf("a single-block query traversed %d nodes against the audit's %d; "+
			"the protocol selection is not taking effect",
			query.BlocksTraversed, audit.BlocksTraversed)
	}
}

// TestAuditOfAnUnknownTargetDoesNotVerify keeps a query for a transaction the
// ledger lacks from being reported as success.
func TestAuditOfAnUnknownTargetDoesNotVerify(t *testing.T) {
	s := setupScheme(t, 5, 40, 4)
	res, err := s.Audit(context.Background(), &scheme.AuditQuery{TargetTxID: "nope"})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if res.Verified {
		t.Error("a query for a transaction not in the ledger verified")
	}
}
