package zkredact

import (
	"context"
	"testing"
	"time"

	"zkredact/pkg/metrics"
	"zkredact/pkg/scheme"
	"zkredact/pkg/workload"
)

// These tests drive Phases 4, 5 and 6 end to end.
//
// The lesson recorded in TASK.md is that code breaks where it has never run,
// and every defect so far has presented as something other than its cause. So
// nothing here asserts against a mock: each test performs real redactions
// through the real ledger, the real PAI and the real auditor, and then checks
// the property that would be silently wrong if the phase were miswired.

const (
	testTransactions = 40
	testIdentities   = 12
	testSecurityBits = 128
)

// fixture builds a set-up scheme over a small real corpus.
//
// The dataset comes from pkg/workload rather than being hand-rolled, for the
// reason internal/schemes/contract_test.go gives: each scheme validates the
// corpus in its own terms, and a fixture that satisfies the compiler is not the
// same thing as one that satisfies the scheme.
func fixture(t *testing.T) (*Scheme, *scheme.Dataset) {
	t.Helper()

	ds, err := workload.GenerateDataset(workload.Config{
		Seed:                   7,
		BaseTransactions:       testTransactions,
		CorePayloadBytes:       64,
		RedactablePayloadBytes: 128,
		IdentityCount:          testIdentities,
		IdentityAttributes:     []string{"sender", "receiver", "validator", "org", "role"},
		PolicyCount:            2,
		PredicateDepth:         3,
		TotalRequests:          testTransactions,
		TargetDistribution:     "uniform",
		ConflictRatio:          0,
	})
	if err != nil {
		t.Fatalf("generate dataset: %v", err)
	}

	s := New()
	err = s.Setup(context.Background(), scheme.SetupParams{
		Dataset:      ds,
		Seed:         7,
		SecurityBits: testSecurityBits,
		Params: map[string]any{
			"shard_count":              1,
			"proof_batch_size":         1,
			"proof_batch_wait_ms":      10,
			"native_batch_verify":      false,
			"freshness_window_ms":      3600000,
			"signature_curve":          "P-256",
			"hash":                     "SHA-256",
			"redactable_payload_bytes": 128,
			"block_max_transactions":   10,
			"auditor_count":            3,
			"max_concurrency":          8,
		},
	})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	t.Cleanup(func() { _ = s.Teardown(context.Background()) })
	return s, ds
}

// grantedRequester finds an identity the scheme actually authorizes, by asking
// rather than assuming which attributes satisfy the generated policy.
func grantedRequester(t *testing.T, s *Scheme, ds *scheme.Dataset) string {
	t.Helper()
	ctx := context.Background()
	probeTx := ds.Transactions[len(ds.Transactions)-1].ID

	for i, id := range ds.Identities {
		req := &scheme.Request{
			ID:          "probe-" + id.ID,
			RequesterID: id.ID,
			TargetTxID:  probeTx,
			NewContent:  []byte("probe"),
			PolicyID:    ds.Policies[0].ID,
			Timestamp:   time.Now(),
			Nonce:       []byte{byte(i)},
		}
		if err := s.PrepareTrace(ctx, []*scheme.Request{req}); err != nil {
			t.Fatalf("PrepareTrace: %v", err)
		}
		auth, err := s.Authorize(ctx, req)
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		if auth.Granted {
			return id.ID
		}
	}
	t.Fatal("no identity in the corpus satisfies the policy; the fixture cannot redact anything")
	return ""
}

// redactOnce authorizes and executes one redaction against a target, returning
// the result. It re-prepares first, because the statement must be built against
// the transaction's CURRENT version.
func redactOnce(t *testing.T, s *Scheme, requester, txID, reqID string, content []byte) *scheme.RedactionResult {
	t.Helper()
	ctx := context.Background()

	req := &scheme.Request{
		ID:          reqID,
		RequesterID: requester,
		TargetTxID:  txID,
		NewContent:  content,
		PolicyID:    s.params.Dataset.Policies[0].ID,
		Timestamp:   time.Now(),
		Nonce:       []byte(reqID),
	}
	if err := s.PrepareTrace(ctx, []*scheme.Request{req}); err != nil {
		t.Fatalf("PrepareTrace: %v", err)
	}
	auth, err := s.Authorize(ctx, req)
	if err != nil {
		t.Fatalf("Authorize %s: %v", reqID, err)
	}
	if !auth.Granted {
		t.Fatalf("Authorize %s denied: %s", reqID, auth.Reason)
	}
	res, err := s.Redact(ctx, []*scheme.Authorization{auth})
	if err != nil {
		t.Fatalf("Redact %s: %v", reqID, err)
	}
	return res
}

// TestRedactionPreservesTheBlockHash is the property the whole chameleon-hash
// construction exists for, and the one thing no other check would catch.
//
// If CH.Adapt's collision were not actually being used — if the ledger
// committed the content rather than the chameleon digest, or the adaptation
// were wrong — every redaction would silently fork the chain. Nothing in Exp 2
// looks at block hashes, so the run would report perfectly good throughput for
// a ledger that no longer verifies.
func TestRedactionPreservesTheBlockHash(t *testing.T) {
	s, ds := fixture(t)
	requester := grantedRequester(t, s, ds)
	target := ds.Transactions[0].ID

	_, _, block, err := s.ledger.State(target)
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	before, err := s.ledger.BlockHash(block)
	if err != nil {
		t.Fatalf("BlockHash: %v", err)
	}

	res := redactOnce(t, s, requester, target, "r1", []byte("redacted content one"))
	if res.Succeeded != 1 {
		t.Fatalf("redaction did not commit: %+v", res)
	}

	after, err := s.ledger.BlockHash(block)
	if err != nil {
		t.Fatalf("BlockHash: %v", err)
	}
	if string(before) != string(after) {
		t.Errorf("the block hash changed across a redaction (%x -> %x); the "+
			"chameleon collision is not being used and every forward link is now broken",
			before, after)
	}

	ok, err := s.ledger.VerifyBlock(block)
	if err != nil {
		t.Fatalf("VerifyBlock: %v", err)
	}
	if !ok {
		t.Error("the block no longer recomputes to its committed root and hash")
	}

	// The content really did change — otherwise the test above would pass for
	// a redaction that did nothing at all.
	version, _, _, err := s.ledger.State(target)
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if version != 1 {
		t.Errorf("version is %d after one redaction, want 1", version)
	}
}

// TestRedactionSplitsCostAndReportsBoth guards exp2's headline metric.
//
// TWO ASSERTIONS, DELIBERATELY SEPARATED. That the ledger side RAN is checked
// unconditionally, through the artefacts it must leave behind: C_B, an
// advanced round, and a moved PAI root. That it was TIMED is checked only on a
// host whose clock can resolve it.
//
// Without the split this test is unreliable in both directions. On a Windows
// developer host the clock granularity is a few hundred microseconds — measured
// at ~300us here — and the ledger work for a one-request batch finishes well
// inside a single tick, so a correct implementation reports zero. Asserting on
// the duration would fail honest code; dropping the assertion entirely would
// let genuinely untimed work through on the EC2 host, where LedgerTime is the
// denominator of the amortisation result. pkg/metrics is the same guard the
// runner uses to refuse recording results on such a host.
func TestRedactionSplitsCostAndReportsBoth(t *testing.T) {
	s, ds := fixture(t)
	requester := grantedRequester(t, s, ds)

	before := append([]byte(nil), s.index.Root()...)
	roundBefore := s.exec.Round()

	res := redactOnce(t, s, requester, ds.Transactions[1].ID, "r-cost", []byte("cost split"))
	if res.Succeeded != 1 {
		t.Fatalf("redaction did not commit: %+v", res)
	}

	// --- the ledger side ran ---
	if len(res.BatchCommitment) == 0 {
		t.Error("no batch commitment C_B was produced; Phase 4 Step 5 did not run")
	}
	if got := s.exec.Round(); got != roundBefore+1 {
		t.Errorf("round is %d after one batch, want %d; no redaction round was opened",
			got, roundBefore+1)
	}
	if string(before) == string(s.index.Root()) {
		t.Error("R_PAI did not move across a committed redaction; Phase 5 Step 3 " +
			"is not updating the authenticated index")
	}
	if _, ok := s.index.Anchor(s.exec.Round()); !ok {
		t.Error("no anchor AR^(e) was produced for the round")
	}

	// --- and it was timed, where the host can tell ---
	//
	// BOTH components are behind the clock guard, including CryptoTime. A single
	// CH.Adapt is two P-256 scalar multiplications, on the order of a hundred
	// microseconds — comfortably INSIDE one tick of this host's ~500us clock, so
	// a correct implementation reports zero here perhaps half the time. An
	// earlier version of this test asserted CryptoTime unconditionally on the
	// grounds that an elliptic-curve operation "cannot finish inside a tick";
	// that was simply false, and it passed only by luck.
	//
	// That the adaptation ran is established elsewhere and unconditionally:
	// TestRedactionPreservesTheBlockHash shows the content changed while the
	// chameleon digest did not, which no path but CH.Adapt produces.
	if err := metrics.RequireUsableClock(); err != nil {
		t.Skipf("clock too coarse for the timing assertions (%v); the artefact checks above still ran", err)
	}
	if res.CryptoTime <= 0 {
		t.Error("CryptoTime is zero on a host that can resolve it; the per-request " +
			"floor Exp 2 plots is not being measured")
	}
	if res.LedgerTime <= 0 {
		t.Error("LedgerTime is zero on a host that can resolve it; the batch root, " +
			"PAI update and anchor are not being timed, so batching would appear " +
			"to amortise nothing")
	}
	t.Logf("crypto %v, ledger %v, total %v", res.CryptoTime, res.LedgerTime, res.Total)
}

// TestSameTargetInOneBatchIsExcludedAsStale pins Phase 4 Step 2's "for requests
// targeting the same transaction, this check is repeated before each
// transition".
//
// Both requests are authorized against version 0. The first advances the
// transaction; the second must then fail revalidation. Applying both would
// produce two records claiming the same FromVersion, and Phase 6's continuity
// check would report the transaction's own history as tampered.
func TestSameTargetInOneBatchIsExcludedAsStale(t *testing.T) {
	ctx := context.Background()
	s, ds := fixture(t)
	requester := grantedRequester(t, s, ds)
	target := ds.Transactions[2].ID

	reqs := []*scheme.Request{
		{ID: "conflict-a", RequesterID: requester, TargetTxID: target,
			NewContent: []byte("first"), PolicyID: ds.Policies[0].ID,
			Timestamp: time.Now(), Nonce: []byte("a")},
		{ID: "conflict-b", RequesterID: requester, TargetTxID: target,
			NewContent: []byte("second"), PolicyID: ds.Policies[0].ID,
			Timestamp: time.Now(), Nonce: []byte("b")},
	}
	if err := s.PrepareTrace(ctx, reqs); err != nil {
		t.Fatalf("PrepareTrace: %v", err)
	}

	batch := make([]*scheme.Authorization, 0, 2)
	for _, r := range reqs {
		a, err := s.Authorize(ctx, r)
		if err != nil {
			t.Fatalf("Authorize %s: %v", r.ID, err)
		}
		if !a.Granted {
			t.Fatalf("Authorize %s denied: %s", r.ID, a.Reason)
		}
		batch = append(batch, a)
	}

	res, err := s.Redact(ctx, batch)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if res.Succeeded != 1 || res.StaleExcluded != 1 {
		t.Errorf("two same-target requests in one batch gave %d succeeded and %d "+
			"stale; want 1 and 1 — same-target requests must serialise",
			res.Succeeded, res.StaleExcluded)
	}
}

// TestAuditVerifiesAHistoryItBuilt is the Phase 6 end-to-end check: build a
// multi-record history, then audit it.
//
// Run TWICE against the same scheme, deliberately. A second audit that fails
// would mean retained state — a consumed nonce, an exhausted iterator, a
// mutated evidence buffer — and the live tests have already been bitten once by
// exactly that class of defect.
func TestAuditVerifiesAHistoryItBuilt(t *testing.T) {
	ctx := context.Background()
	s, ds := fixture(t)
	requester := grantedRequester(t, s, ds)
	target := ds.Transactions[3].ID

	clockUsable := metrics.RequireUsableClock() == nil

	const depth = 4
	for i := 0; i < depth; i++ {
		res := redactOnce(t, s, requester, target,
			"hist-"+string(rune('a'+i)), []byte("revision "+string(rune('0'+i))))
		if res.Succeeded != 1 {
			t.Fatalf("revision %d did not commit: %+v", i, res)
		}
	}

	for attempt := 1; attempt <= 2; attempt++ {
		r, err := s.Audit(ctx, &scheme.AuditQuery{
			AuditorID: "auditor-0", TargetTxID: target,
		})
		if err != nil {
			t.Fatalf("attempt %d: Audit: %v", attempt, err)
		}
		if !r.Verified {
			t.Fatalf("attempt %d: an honest history did not verify", attempt)
		}
		if r.Semantics != scheme.SemanticsPerTxProvenance {
			t.Errorf("attempt %d: semantics %q, want per_tx_provenance", attempt, r.Semantics)
		}
		if len(r.History) != depth {
			t.Errorf("attempt %d: %d records returned, want %d", attempt, len(r.History), depth)
		}
		// Timed assertions only where the clock can resolve them. Phase 6
		// Step 1 is one Schnorr sign and one verify — a few hundred
		// microseconds, inside a single tick on a coarse host. That it RAN is
		// established structurally: an unauthorized query returns before
		// retrieval with no records, so a verified result carrying history
		// cannot have skipped it.
		if clockUsable && r.AuthorizationTime <= 0 {
			t.Errorf("attempt %d: auditor authorization was not timed", attempt)
		}
		if r.VerificationTime <= 0 {
			// Groth16 verification of four proofs is milliseconds, well above
			// any plausible tick, so this one stands unconditionally.
			t.Errorf("attempt %d: verification was not timed", attempt)
		}
		if r.EvidenceBytes <= 0 {
			t.Errorf("attempt %d: no evidence size reported", attempt)
		}
		t.Logf("attempt %d: %d records, %d blocks, %d bytes, auth %v, retrieve %v, verify %v",
			attempt, len(r.History), r.BlocksTraversed, r.EvidenceBytes,
			r.AuthorizationTime, r.RetrievalTime, r.VerificationTime)
	}
}

// TestAuditIsLedgerIndependent is Exp 3's claim, checked directly rather than
// inferred from a timing curve.
//
// Two ledgers an order of magnitude apart, the same history depth: the number
// of blocks the audit reads must not move. exp3's runner enforces the weaker
// "fewer than the whole ledger"; this pins the actual constant.
func TestAuditIsLedgerIndependent(t *testing.T) {
	ctx := context.Background()

	blocksAt := func(txCount int) int {
		ds, err := workload.GenerateDataset(workload.Config{
			Seed: 11, BaseTransactions: txCount,
			CorePayloadBytes: 64, RedactablePayloadBytes: 128,
			IdentityCount:      testIdentities,
			IdentityAttributes: []string{"sender", "receiver", "validator", "org", "role"},
			PolicyCount:        2, PredicateDepth: 3,
			TotalRequests: txCount, TargetDistribution: "uniform",
		})
		if err != nil {
			t.Fatalf("generate dataset: %v", err)
		}
		s := New()
		if err := s.Setup(ctx, scheme.SetupParams{
			Dataset: ds, Seed: 11, SecurityBits: testSecurityBits,
			Params: map[string]any{
				"shard_count": 1, "proof_batch_size": 1, "proof_batch_wait_ms": 10,
				"native_batch_verify": false, "freshness_window_ms": 3600000,
				"signature_curve": "P-256", "hash": "SHA-256",
				"redactable_payload_bytes": 128, "block_max_transactions": 10,
				"auditor_count": 3, "max_concurrency": 8,
			},
		}); err != nil {
			t.Fatalf("Setup at %d transactions: %v", txCount, err)
		}
		defer func() { _ = s.Teardown(ctx) }()

		requester := grantedRequester(t, s, ds)
		target := ds.Transactions[0].ID
		for i := 0; i < 2; i++ {
			if res := redactOnce(t, s, requester, target,
				"li-"+string(rune('a'+i)), []byte{byte('0' + i)}); res.Succeeded != 1 {
				t.Fatalf("history revision %d did not commit at %d transactions", i, txCount)
			}
		}

		r, err := s.Audit(ctx, &scheme.AuditQuery{AuditorID: "auditor-0", TargetTxID: target})
		if err != nil {
			t.Fatalf("Audit at %d transactions: %v", txCount, err)
		}
		if !r.Verified {
			t.Fatalf("audit at %d transactions did not verify", txCount)
		}
		t.Logf("%d transactions (%d blocks): audit read %d blocks",
			txCount, s.ledger.Blocks(), r.BlocksTraversed)
		return r.BlocksTraversed
	}

	small := blocksAt(40)
	large := blocksAt(400)
	if small != large {
		t.Errorf("audit read %d blocks on a small ledger and %d on one ten times "+
			"larger; the ledger-independence claim this scheme declares is false",
			small, large)
	}
}

// TestAuditRejectsOutOfScopeAuditor proves AuditAuth can refuse.
//
// A registry where every auditor may audit everything would make Phase 6 Step 1
// a rubber stamp: it would return 1 for every input it could receive, and there
// would be no way to tell an enforced policy from an ignored one.
func TestAuditRejectsOutOfScopeAuditor(t *testing.T) {
	ctx := context.Background()
	s, ds := fixture(t)
	requester := grantedRequester(t, s, ds)
	target := ds.Transactions[4].ID

	if res := redactOnce(t, s, requester, target, "scope-1", []byte("scoped")); res.Succeeded != 1 {
		t.Fatalf("setup redaction did not commit: %+v", res)
	}

	// Find a registered auditor whose scope excludes this transaction's policy.
	policyIDs, err := s.index.PolicyIDs(target)
	if err != nil {
		t.Fatalf("PolicyIDs: %v", err)
	}
	var restricted string
	for id := 1; id < s.auditorCount; id++ {
		name := auditorID(id)
		req := &scheme.AuditQuery{AuditorID: name, TargetTxID: target}
		r, err := s.Audit(ctx, req)
		if err != nil {
			t.Fatalf("Audit as %s: %v", name, err)
		}
		if !r.Verified && len(r.History) == 0 {
			restricted = name
			break
		}
	}
	if restricted == "" {
		t.Fatalf("no registered auditor was refused for policies %v; AuditAuth "+
			"accepts every input and is therefore not enforcing Pi_a^audit", policyIDs)
	}
	t.Logf("%s was refused, as its registered audit policy requires", restricted)
}

// TestAuditDetectsATamperedHistory is the other half of the fidelity
// requirement: the verifier must reject as well as accept.
//
// The record is altered AFTER it was committed and anchored, which is exactly
// the attack Phase 6 exists to detect — the ledger still verifies, the PAI
// entry still exists, and only the replayed cumulative commitment disagrees.
func TestAuditDetectsATamperedHistory(t *testing.T) {
	ctx := context.Background()
	s, ds := fixture(t)
	requester := grantedRequester(t, s, ds)
	target := ds.Transactions[5].ID

	for i := 0; i < 2; i++ {
		if res := redactOnce(t, s, requester, target,
			"tamper-"+string(rune('a'+i)), []byte{byte('0' + i)}); res.Succeeded != 1 {
			t.Fatalf("revision %d did not commit", i)
		}
	}
	if r, err := s.Audit(ctx, &scheme.AuditQuery{AuditorID: "auditor-0", TargetTxID: target}); err != nil || !r.Verified {
		t.Fatalf("the honest history must verify first: verified=%v err=%v", r != nil && r.Verified, err)
	}

	// Reach into the committed history and rewrite one record's post-state
	// digest. Nothing else is touched.
	ev, err := s.index.Retrieve(target, 0)
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	ev.History[0].NewDigest = append([]byte(nil), []byte("not the committed digest")...)

	r, err := s.Audit(ctx, &scheme.AuditQuery{AuditorID: "auditor-0", TargetTxID: target})
	if err == nil && r.Verified {
		t.Error("a history with an altered record still verified; Phase 6 is not " +
			"checking what it claims to")
	} else {
		t.Logf("rejected as expected: %v", err)
	}
}
