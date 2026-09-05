package ref10

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"zkredact/pkg/merkle"
	"zkredact/pkg/metrics"
	"zkredact/pkg/scheme"
)

// -----------------------------------------------------------------------------
// Fixtures
// -----------------------------------------------------------------------------

const (
	testCommittee = 7
	testThreshold = 5
	testBlockSize = 5
	testPolicy    = "S OR R OR V"
)

// testIdentities builds n identities. Every third is ineligible under
// "S OR R OR V" — all three attributes false — so denial is exercised by the
// data rather than by a special case in the test.
func testIdentities(n int) []scheme.Identity {
	out := make([]scheme.Identity, n)
	for i := range out {
		eligible := i%3 != 0
		out[i] = scheme.Identity{
			ID: fmt.Sprintf("id-%03d", i),
			Attributes: map[string]string{
				"sender":    fmt.Sprint(eligible),
				"receiver":  "false",
				"validator": fmt.Sprint(eligible && i%2 == 0),
				"org":       fmt.Sprintf("org%d", i%4+1),
				"role":      []string{"operator", "auditor", "admin"}[i%3],
			},
		}
	}
	return out
}

func testDataset(txCount, idCount int) *scheme.Dataset {
	txs := make([]scheme.Transaction, txCount)
	for i := range txs {
		txs[i] = scheme.Transaction{
			ID:         fmt.Sprintf("tx-%08d", i),
			Core:       []byte(fmt.Sprintf("core-payload-%d", i)),
			Redactable: []byte(fmt.Sprintf("redactable-payload-%d", i)),
		}
	}
	return &scheme.Dataset{
		ID:           "test-dataset",
		Transactions: txs,
		Identities:   testIdentities(idCount),
		Policies:     []scheme.Policy{{ID: "pol-0000", Version: 1, Predicate: "sender"}},
	}
}

func testParams() map[string]any {
	return map[string]any{
		"committee_size":         testCommittee,
		"vote_threshold":         testThreshold,
		"vote_window_ms":         5000,
		"attribute_policy":       testPolicy,
		"vote_transport":         transportInProcess,
		"signature_curve":        "P-256",
		"hash":                   "SHA-256",
		"block_max_transactions": testBlockSize,
	}
}

func mustSetup(t *testing.T) *Scheme {
	t.Helper()
	s := New()
	if err := s.Setup(context.Background(), scheme.SetupParams{
		Dataset:      testDataset(20, 30),
		Seed:         42,
		SecurityBits: 128,
		Params:       testParams(),
	}); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	return s
}

// eligibleRequester returns an identity ID that satisfies A_r.
func eligibleRequester(t *testing.T, s *Scheme) string {
	t.Helper()
	pool, err := s.registry.eligible(testPolicy)
	if err != nil {
		t.Fatalf("eligible: %v", err)
	}
	if len(pool) == 0 {
		t.Fatal("no eligible identities in fixture")
	}
	return pool[0].Identity.ID
}

func ineligibleRequester(t *testing.T, s *Scheme) string {
	t.Helper()
	for _, n := range s.registry.nodes {
		ok, err := evalPolicy(testPolicy, n.Identity.Attributes)
		if err != nil {
			t.Fatalf("evalPolicy: %v", err)
		}
		if !ok {
			return n.Identity.ID
		}
	}
	t.Fatal("no ineligible identities in fixture")
	return ""
}

func request(id, requester, target string) *scheme.Request {
	return &scheme.Request{
		ID:          id,
		RequesterID: requester,
		TargetTxID:  target,
		NewContent:  []byte("redacted"),
		PolicyID:    "pol-0000",
	}
}

// -----------------------------------------------------------------------------
// A_r evaluation (Algorithm 2 / Eq. 5)
// -----------------------------------------------------------------------------

func TestEvalPolicy(t *testing.T) {
	attrs := map[string]string{
		"sender": "true", "receiver": "false", "validator": "false",
		"role": "operator",
	}
	for _, tc := range []struct {
		expr string
		want bool
	}{
		{"S", true},
		{"R", false},
		{"V", false},
		{"S OR R OR V", true},
		{"R OR V", false},
		{"S AND R", false},
		{"S AND role=operator", true},
		{"S AND role=admin", false},
		{"(R OR V) AND S", false},
		{"(S OR V) AND role=operator", true},
		{"R OR (S AND role=operator)", true},
		{"s or r", true}, // operators and symbols are case-insensitive
	} {
		got, err := evalPolicy(tc.expr, attrs)
		if err != nil {
			t.Errorf("%q: %v", tc.expr, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%q = %v, want %v", tc.expr, got, tc.want)
		}
	}
}

// An unparseable policy must error, never silently evaluate to true or false.
// Silent true removes the check; silent false empties every committee.
func TestEvalPolicyRejectsMalformed(t *testing.T) {
	attrs := map[string]string{"sender": "true"}
	for _, expr := range []string{
		"", "   ", "X", "S OR", "S AND", "(S OR R", "S R", "OR S",
	} {
		if _, err := evalPolicy(expr, attrs); err == nil {
			t.Errorf("accepted malformed policy %q", expr)
		}
	}
}

// -----------------------------------------------------------------------------
// Committee selection (Algorithm 3 init, Eq. 7)
// -----------------------------------------------------------------------------

func TestCommitteeIsHashBasedOverFullNodeSet(t *testing.T) {
	s := mustSetup(t)

	a, err := s.registry.selectCommittee(contractAddress("req-1"), testPolicy, testCommittee)
	if err != nil {
		t.Fatalf("selectCommittee: %v", err)
	}
	b, err := s.registry.selectCommittee(contractAddress("req-2"), testPolicy, testCommittee)
	if err != nil {
		t.Fatalf("selectCommittee: %v", err)
	}

	if len(a) != testCommittee {
		t.Fatalf("committee has %d members, want %d", len(a), testCommittee)
	}

	// A fixed list would produce the same committee for every contract, and the
	// per-request selection cost inside Exp 1's boundary would be fictional.
	same := true
	for i := range a {
		if a[i].Identity.ID != b[i].Identity.ID {
			same = false
			break
		}
	}
	if same {
		t.Errorf("two different contracts selected an identical committee; selection is not address-dependent")
	}
}

func TestCommitteeIsDeterministic(t *testing.T) {
	s := mustSetup(t)
	addr := contractAddress("req-1")

	first, _ := s.registry.selectCommittee(addr, testPolicy, testCommittee)
	second, _ := s.registry.selectCommittee(addr, testPolicy, testCommittee)

	for i := range first {
		if first[i].Identity.ID != second[i].Identity.ID {
			t.Fatalf("selection is not reproducible at position %d", i)
		}
	}
}

func TestCommitteeMembersAllSatisfyPolicy(t *testing.T) {
	s := mustSetup(t)
	committee, _ := s.registry.selectCommittee(contractAddress("req-1"), testPolicy, testCommittee)

	for _, m := range committee {
		ok, err := evalPolicy(testPolicy, m.Identity.Attributes)
		if err != nil {
			t.Fatalf("evalPolicy: %v", err)
		}
		if !ok {
			t.Errorf("member %s does not satisfy A_r but was selected", m.Identity.ID)
		}
	}
}

// Silently shrinking the committee would weaken the threshold the baseline is
// measured under, so too small a pool is refused.
func TestCommitteeRefusesUndersizedPool(t *testing.T) {
	s := mustSetup(t)
	_, err := s.registry.selectCommittee(contractAddress("req-1"), testPolicy, 10000)
	if err == nil {
		t.Errorf("selected a committee larger than the eligible pool")
	}
}

// -----------------------------------------------------------------------------
// EMT structure (§IV-B, Eq. 4)
// -----------------------------------------------------------------------------

func TestEMTLeavesAreInterleavedAndProvable(t *testing.T) {
	l, err := newLedger(testDataset(20, 1).Transactions, testBlockSize)
	if err != nil {
		t.Fatalf("newLedger: %v", err)
	}

	for _, b := range l.blocks {
		if got, want := len(b.leaves()), len(b.Txs)*2; got != want {
			t.Fatalf("block %d has %d leaves, want %d (two per transaction)", b.Height, got, want)
		}
		root := b.tree.Root()
		for i, tx := range b.Txs {
			if !bytesEqual(hashTx(tx.HC, tx.HW), tx.HTx) {
				t.Errorf("H_tx != H(H_c || H_w) for %s", tx.ID)
			}
			for off, leaf := range [][]byte{tx.HC, tx.HW} {
				proof, err := b.tree.Proof(i*2 + off)
				if err != nil {
					t.Fatalf("Proof: %v", err)
				}
				if !merkle.VerifyHash(root, leaf, proof) {
					t.Errorf("leaf %d of %s does not prove against the block root", off, tx.ID)
				}
			}
		}
	}
}

func TestRedactionChangesOnlyTheInsertedBranch(t *testing.T) {
	l, _ := newLedger(testDataset(20, 1).Transactions, testBlockSize)
	target := "tx-00000007"

	before, ok := l.lookup(target)
	if !ok {
		t.Fatal("target not found")
	}
	hcBefore := append([]byte(nil), before.HC...)
	hwBefore := append([]byte(nil), before.HW...)

	rdt := &redactionTx{ID: "tx-rdt-1", TargetTxID: target, NewContent: []byte("new content")}
	after, err := l.applyRedaction(rdt)
	if err != nil {
		t.Fatalf("applyRedaction: %v", err)
	}

	if !bytesEqual(hcBefore, after.HC) {
		t.Errorf("H_c changed across a redaction; core data must be immutable")
	}
	if bytesEqual(hwBefore, after.HW) {
		t.Errorf("H_w did not change across a redaction")
	}
	if after.Version != 1 {
		t.Errorf("version = %d, want 1", after.Version)
	}
}

// -----------------------------------------------------------------------------
// Setup guards
// -----------------------------------------------------------------------------

func TestSetupGuards(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
		bits   int
		want   string
	}{
		{"threshold below majority", func(p map[string]any) { p["vote_threshold"] = 3 }, 128, "not a majority"},
		{"threshold above committee", func(p map[string]any) { p["vote_threshold"] = 9 }, 128, "exceeds committee size"},
		{"fabric transport refused", func(p map[string]any) { p["vote_transport"] = transportFabric }, 128, "not implemented"},
		{"unknown transport", func(p map[string]any) { p["vote_transport"] = "grpc" }, 128, "unknown vote_transport"},
		{"weak curve for target", func(p map[string]any) { p["signature_curve"] = "P-256" }, 192, "below the 192-bit target"},
		{"unimplemented curve", func(p map[string]any) { p["signature_curve"] = "BLS12-381" }, 128, "no standard-library"},
		{"wrong hash", func(p map[string]any) { p["hash"] = "SHA-3" }, 128, "SHA-256"},
		{"missing transport", func(p map[string]any) { delete(p, "vote_transport") }, 128, "missing parameter vote_transport"},
		{"missing block size", func(p map[string]any) { delete(p, "block_max_transactions") }, 128, "block_max_transactions"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := testParams()
			tc.mutate(p)
			err := New().Setup(context.Background(), scheme.SetupParams{
				Dataset:      testDataset(20, 30),
				Seed:         42,
				SecurityBits: tc.bits,
				Params:       p,
			})
			if err == nil {
				t.Fatalf("Setup accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestOperationsRefuseBeforeSetup(t *testing.T) {
	s := New()
	ctx := context.Background()
	if _, err := s.Authorize(ctx, request("r", "id-001", "tx-00000001")); err == nil {
		t.Errorf("Authorize succeeded before Setup")
	}
	if _, err := s.Redact(ctx, nil); err == nil {
		t.Errorf("Redact succeeded before Setup")
	}
	if _, err := s.Audit(ctx, &scheme.AuditQuery{}); err == nil {
		t.Errorf("Audit succeeded before Setup")
	}
}

// -----------------------------------------------------------------------------
// Authorization (Algorithms 2-4)
// -----------------------------------------------------------------------------

func TestAuthorizeGrantsEligibleRequester(t *testing.T) {
	s := mustSetup(t)
	auth, err := s.Authorize(context.Background(),
		request("req-1", eligibleRequester(t, s), "tx-00000003"))
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !auth.Granted {
		t.Fatalf("denied an eligible request: %s", auth.Reason)
	}
	if len(auth.Evidence) == 0 {
		t.Errorf("granted without recording Sigma")
	}
}

// The scheme must deny as well as grant. A baseline that approves everything
// benchmarks beautifully and measures nothing; exp1 fails such a scheme, and
// these are the paths that make the denial real.
func TestAuthorizeDenials(t *testing.T) {
	s := mustSetup(t)
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		req  *scheme.Request
		want string
	}{
		{"requester fails A_r", request("d1", ineligibleRequester(t, s), "tx-00000003"), "does not satisfy A_r"},
		{"unregistered requester", request("d2", "id-999999", "tx-00000003"), "not registered with the CA"},
		{"target not in ledger", request("d3", eligibleRequester(t, s), "tx-99999999"), "not in the ledger"},
		{"genesis target", request("d4", eligibleRequester(t, s), "tx-genesis"), "outside T_rdbl"},
		{"unknown policy", &scheme.Request{ID: "d5", RequesterID: eligibleRequester(t, s),
			TargetTxID: "tx-00000003", PolicyID: "pol-nope"}, "not registered"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth, err := s.Authorize(ctx, tc.req)
			if err != nil {
				t.Fatalf("Authorize: %v", err)
			}
			if auth.Granted {
				t.Fatalf("granted %s", tc.name)
			}
			if !strings.Contains(auth.Reason, tc.want) {
				t.Errorf("reason %q does not mention %q", auth.Reason, tc.want)
			}
		})
	}
}

// A redaction transaction is in T_rdt and must never itself be redactable.
func TestRedactionTransactionsAreNotRedactable(t *testing.T) {
	s := mustSetup(t)
	ctx := context.Background()

	auth, _ := s.Authorize(ctx, request("req-1", eligibleRequester(t, s), "tx-00000003"))
	if _, err := s.Redact(ctx, []*scheme.Authorization{auth}); err != nil {
		t.Fatalf("Redact: %v", err)
	}

	second, err := s.Authorize(ctx, request("req-2", eligibleRequester(t, s), "tx-rdt-req-1"))
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if second.Granted {
		t.Errorf("authorized a redaction of a redaction transaction")
	}
	if !strings.Contains(second.Reason, "outside T_rdbl") {
		t.Errorf("reason %q does not cite T_rdbl", second.Reason)
	}
}

// -----------------------------------------------------------------------------
// Vote fidelity (Theorem 2)
// -----------------------------------------------------------------------------

func TestVerifySigmaRejectsForgedSets(t *testing.T) {
	s := mustSetup(t)
	ctx := context.Background()
	req := request("req-1", eligibleRequester(t, s), "tx-00000003")

	if _, err := s.Authorize(ctx, req); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	rec := s.rounds[req.ID]
	if rec == nil {
		t.Fatal("no round recorded for a granted request")
	}

	if !verifySigma(rec.ContractAddr, req.ID, rec.Approved, testThreshold) {
		t.Fatal("a genuine Sigma failed verification")
	}

	t.Run("below threshold", func(t *testing.T) {
		if verifySigma(rec.ContractAddr, req.ID, rec.Approved[:testThreshold-1], testThreshold) {
			t.Errorf("accepted a Sigma below threshold")
		}
	})

	t.Run("padded with duplicates", func(t *testing.T) {
		// One member's real signature repeated to reach the count. Without the
		// one-node-one-vote check this passes every signature verification.
		padded := make([]ballot, 0, testThreshold)
		for i := 0; i < testThreshold; i++ {
			padded = append(padded, rec.Approved[0])
		}
		if verifySigma(rec.ContractAddr, req.ID, padded, testThreshold) {
			t.Errorf("accepted a Sigma made of one member's repeated vote")
		}
	})

	t.Run("replayed onto another request", func(t *testing.T) {
		if verifySigma(rec.ContractAddr, "req-other", rec.Approved, testThreshold) {
			t.Errorf("accepted a Sigma replayed onto a different request")
		}
	})

	t.Run("replayed onto another contract", func(t *testing.T) {
		if verifySigma(contractAddress("other"), req.ID, rec.Approved, testThreshold) {
			t.Errorf("accepted a Sigma replayed onto a different contract")
		}
	})
}

func TestCertificateTamperingIsDetected(t *testing.T) {
	s := mustSetup(t)
	req := request("req-1", eligibleRequester(t, s), "tx-00000003")
	target, _ := s.ledger.lookup(req.TargetTxID)

	cert, err := s.ca.validate(req, target, s.policies["pol-0000"], testPolicy)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !s.ca.verifyCert(cert) {
		t.Fatal("a genuine policy certificate failed verification")
	}

	// Flipping the decision bit is the attack that matters: it turns a denial
	// into an approval without the CA.
	cert.Satisfies = !cert.Satisfies
	if s.ca.verifyCert(cert) {
		t.Errorf("accepted a policy certificate whose decision was altered")
	}
}

// -----------------------------------------------------------------------------
// Redaction (Algorithm 5)
// -----------------------------------------------------------------------------

func TestRedactAppliesAndReportsCostSplit(t *testing.T) {
	s := mustSetup(t)
	ctx := context.Background()

	auth, err := s.Authorize(ctx, request("req-1", eligibleRequester(t, s), "tx-00000003"))
	if err != nil || !auth.Granted {
		t.Fatalf("Authorize: %v (%s)", err, auth.Reason)
	}

	res, err := s.Redact(ctx, []*scheme.Authorization{auth})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if res.Succeeded != 1 {
		t.Fatalf("succeeded = %d, want 1", res.Succeeded)
	}

	// exp2 fails any scheme reporting zero CryptoTime alongside successful
	// redactions, because that means the decomposition was never instrumented.
	//
	// Only checkable on a host whose clock can resolve a single redaction. On a
	// coarse-clock host every duration rounds to zero regardless of the code, so
	// asserting here would test the machine rather than the scheme. The harness
	// refuses to record results on such a host (metrics.RequireUsableClock), so
	// skipping is safe: no measured run can reach this state undetected.
	if !metrics.ClockIsUsable() {
		t.Skipf("clock resolution is %v, too coarse to time a single redaction; "+
			"the cost split cannot be asserted on this host",
			metrics.ClockResolution())
	}
	if res.CryptoTime <= 0 {
		t.Errorf("CryptoTime is zero after a successful redaction")
	}
	if res.LedgerTime <= 0 {
		t.Errorf("LedgerTime is zero after a successful redaction")
	}

	// Algorithm 5 line 9: d_w is PRUNED to a reference, not overwritten with
	// the new content. The replacement data lives in tx_rdt.
	tx, _ := s.ledger.lookup("tx-00000003")
	rdtID, pruned := parseRedactionReference(tx.Redactable)
	if !pruned {
		t.Fatalf("d_w was not replaced with a reference to tx_rdt, got %q", tx.Redactable)
	}
	if string(tx.Redactable) == "redacted" {
		t.Errorf("d_w holds the new content; Ref[10] prunes rather than overwriting")
	}
	rtx, ok := s.ledger.lookup(rdtID)
	if !ok || rtx.rdt == nil {
		t.Fatalf("reference %q does not resolve to a redaction transaction", rdtID)
	}
	if string(rtx.rdt.NewContent) != "redacted" {
		t.Errorf("d_new = %q, want %q; the new data must be reachable through tx_rdt",
			rtx.rdt.NewContent, "redacted")
	}
	if rtx.rdt.TargetTxID != "tx-00000003" {
		t.Errorf("redaction transaction targets %s", rtx.rdt.TargetTxID)
	}
}

func TestRedactRefusesUnauthorized(t *testing.T) {
	s := mustSetup(t)
	ctx := context.Background()

	denied := &scheme.Authorization{
		Request: request("req-x", ineligibleRequester(t, s), "tx-00000003"),
		Granted: false,
	}
	// A granted-looking authorization the contract never actually issued: no
	// round record exists for it, so Sigma cannot be re-verified.
	fabricated := &scheme.Authorization{
		Request: request("req-y", eligibleRequester(t, s), "tx-00000004"),
		Granted: true,
	}

	res, err := s.Redact(ctx, []*scheme.Authorization{denied, fabricated})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if res.Succeeded != 0 {
		t.Errorf("succeeded = %d, want 0", res.Succeeded)
	}
	if res.Failed != 2 {
		t.Errorf("failed = %d, want 2", res.Failed)
	}
}

// -----------------------------------------------------------------------------
// Audit (Algorithm 1, Exp 3)
// -----------------------------------------------------------------------------

func TestAuditIsLinearAndDeclaresFullScan(t *testing.T) {
	s := mustSetup(t)
	ctx := context.Background()

	auth, _ := s.Authorize(ctx, request("req-1", eligibleRequester(t, s), "tx-00000003"))
	if _, err := s.Redact(ctx, []*scheme.Authorization{auth}); err != nil {
		t.Fatalf("Redact: %v", err)
	}

	res, err := s.Audit(ctx, &scheme.AuditQuery{TargetTxID: "tx-00000003"})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}

	if res.Semantics != scheme.SemanticsFullScan {
		t.Errorf("semantics = %q, want %q", res.Semantics, scheme.SemanticsFullScan)
	}
	if !res.Verified {
		t.Errorf("a well-formed transaction failed Algorithm 1")
	}
	if len(res.History) != 1 {
		t.Fatalf("history has %d entries, want 1", len(res.History))
	}
	// Capabilities declares LedgerIndependentAudit false; the scan must actually
	// touch every block or the declaration and the behaviour disagree.
	if res.BlocksTraversed != s.ledger.blockCount() {
		t.Errorf("traversed %d blocks, want all %d", res.BlocksTraversed, s.ledger.blockCount())
	}
	if res.EvidenceBytes <= 0 {
		t.Errorf("reported no evidence bytes for a full scan")
	}
}

func TestAuditCostGrowsWithLedgerSize(t *testing.T) {
	small := New()
	large := New()
	for _, tc := range []struct {
		s  *Scheme
		tx int
	}{{small, 20}, {large, 200}} {
		if err := tc.s.Setup(context.Background(), scheme.SetupParams{
			Dataset:      testDataset(tc.tx, 30),
			Seed:         42,
			SecurityBits: 128,
			Params:       testParams(),
		}); err != nil {
			t.Fatalf("Setup: %v", err)
		}
	}

	a, _ := small.Audit(context.Background(), &scheme.AuditQuery{TargetTxID: "tx-00000003"})
	b, _ := large.Audit(context.Background(), &scheme.AuditQuery{TargetTxID: "tx-00000003"})

	if b.BlocksTraversed <= a.BlocksTraversed {
		t.Errorf("audit traversed %d blocks on a 10x larger ledger vs %d on the small one; "+
			"Exp 3 depends on this growing", b.BlocksTraversed, a.BlocksTraversed)
	}
}

// The fidelity checklist requires that a redaction altering core data fails.
func TestAuditDetectsCoreDataTampering(t *testing.T) {
	s := mustSetup(t)

	if !s.verifyEMT("tx-00000003") {
		t.Fatal("a well-formed transaction failed Algorithm 1")
	}

	tx, _ := s.ledger.lookup("tx-00000003")
	tx.Core = []byte("tampered core data")

	if s.verifyEMT("tx-00000003") {
		t.Errorf("Algorithm 1 accepted a transaction whose core data was altered")
	}
}

func TestAuditDetectsInsertedDataTampering(t *testing.T) {
	s := mustSetup(t)
	tx, _ := s.ledger.lookup("tx-00000005")
	tx.Redactable = []byte("silently changed, no redaction transaction")

	if s.verifyEMT("tx-00000005") {
		t.Errorf("Algorithm 1 accepted inserted data changed outside a redaction")
	}
}

func TestAuditOfUnknownTransaction(t *testing.T) {
	s := mustSetup(t)
	res, err := s.Audit(context.Background(), &scheme.AuditQuery{TargetTxID: "tx-99999999"})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if res.Verified {
		t.Errorf("verified a transaction that is not in the ledger")
	}
}

// -----------------------------------------------------------------------------
// Capability declarations must match behaviour
// -----------------------------------------------------------------------------

func TestCapabilitiesMatchBehaviour(t *testing.T) {
	c := New().Capabilities()
	if c.BatchRedaction {
		t.Errorf("Ref[10] declares batching; it has none, and exp2 would sweep it over batch sizes")
	}
	if c.LedgerIndependentAudit {
		t.Errorf("Ref[10] declares ledger-independent audit; Audit walks every block")
	}
	if c.PerTxProvenance {
		t.Errorf("Ref[10] declares per-transaction provenance; there is no such index")
	}
	if !c.DecentralizedAuth {
		t.Errorf("Ref[10] should declare decentralized authorization; it runs a committee vote")
	}
}

// -----------------------------------------------------------------------------
// The vote round must verify before counting
//
// The in-process transport only ever produces genuine ballots, so nothing above
// exercises the verification step inside vote(). A transport that submits
// forged ballots is the only way to prove the tally is not simply counting
// submissions — which is precisely Theorem 2's claim.
// -----------------------------------------------------------------------------

// forgingTransport returns some genuine approvals and some ballots whose
// signatures do not verify: one signed over the wrong message, one signed by a
// key that is not the claimed member's.
type forgingTransport struct {
	genuine  int
	outsider *member
}

func (forgingTransport) Name() string { return "forging_test" }

func (f forgingTransport) Collect(ctx context.Context, r *voteRound) ([]ballot, error) {
	out := make([]ballot, 0, len(r.Members))
	msg := voteMessage(r.ContractAddr, r.RequestID, true)

	for i, m := range r.Members {
		if i < f.genuine {
			xi, err := m.Key.Sign(msg, nil)
			if err != nil {
				return nil, err
			}
			out = append(out, ballot{NodeID: m.Identity.ID, Approve: true,
				Key: &m.Key.SchnorrPublicKey, Xi: xi})
			continue
		}

		// Forged: a real signature over a DIFFERENT message, presented as an
		// approval for this round.
		wrong, err := m.Key.Sign([]byte("some other message"), nil)
		if err != nil {
			return nil, err
		}
		if i%2 == 1 && f.outsider != nil {
			// Forged differently: a valid approval signed by a node that is not
			// this committee member, submitted under the member's identity.
			wrong, err = f.outsider.Key.Sign(msg, nil)
			if err != nil {
				return nil, err
			}
		}
		out = append(out, ballot{NodeID: m.Identity.ID, Approve: true,
			Key: &m.Key.SchnorrPublicKey, Xi: wrong})
	}
	return out, nil
}

func TestVoteRoundVerifiesBeforeCounting(t *testing.T) {
	s := mustSetup(t)
	req := request("req-vote", eligibleRequester(t, s), "tx-00000003")
	addr := contractAddress(req.ID)

	committee, err := s.registry.selectCommittee(addr, testPolicy, testCommittee)
	if err != nil {
		t.Fatalf("selectCommittee: %v", err)
	}
	target, _ := s.ledger.lookup(req.TargetTxID)
	cert, err := s.ca.validate(req, target, s.policies["pol-0000"], testPolicy)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}

	const genuine = testThreshold - 1
	approved, err := runVoteRound(context.Background(),
		forgingTransport{genuine: genuine, outsider: s.registry.nodes[0]},
		&voteRound{
			ContractAddr: addr,
			RequestID:    req.ID,
			Cert:         cert,
			CA:           s.ca,
			Members:      committee,
			Threshold:    testThreshold,
			Window:       5 * time.Second,
		})
	if err != nil {
		t.Fatalf("runVoteRound: %v", err)
	}

	// Only the genuine ballots may be counted. Counting submissions rather than
	// verified signatures would reach the threshold here.
	if len(approved) != genuine {
		t.Errorf("counted %d approvals, want %d; forged ballots reached the tally",
			len(approved), genuine)
	}
	if len(approved) >= testThreshold {
		t.Errorf("threshold reached using ballots that do not verify")
	}
}

// Each committee member must re-derive its decision from P_C (Algorithm 4
// line 1), not take the round's existence as approval.
//
// Authorize never opens a round for a denying certificate, so this is only
// reachable by driving the transport directly — which is exactly why it is
// worth pinning. A member that rubber-stamps whatever it is sent makes the
// threshold decorative.
func TestCommitteeMemberRederivesTheDecision(t *testing.T) {
	s := mustSetup(t)
	req := request("req-deny", eligibleRequester(t, s), "tx-genesis")
	addr := contractAddress(req.ID)

	committee, err := s.registry.selectCommittee(addr, testPolicy, testCommittee)
	if err != nil {
		t.Fatalf("selectCommittee: %v", err)
	}
	target, _ := s.ledger.lookup(req.TargetTxID)

	// A genuine CA certificate that DENIES: the target is the genesis
	// transaction, outside T_rdbl.
	cert, err := s.ca.validate(req, target, s.policies["pol-0000"], testPolicy)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if cert.Granted() {
		t.Fatal("fixture error: expected a denying certificate")
	}

	round := &voteRound{
		ContractAddr: addr, RequestID: req.ID, Cert: cert, CA: s.ca,
		Members: committee, Threshold: testThreshold, Window: 5 * time.Second,
	}

	ballots, err := localTransport{}.Collect(context.Background(), round)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, b := range ballots {
		if b.Approve {
			t.Errorf("member %s approved a request its own policy check denies", b.NodeID)
		}
	}

	approved, err := runVoteRound(context.Background(), localTransport{}, round)
	if err != nil {
		t.Fatalf("runVoteRound: %v", err)
	}
	if len(approved) != 0 {
		t.Errorf("%d approvals for a denied policy, want 0", len(approved))
	}
}

// A certificate the CA did not sign must draw no ballots at all: a member that
// cannot verify P_C does not vote.
func TestCommitteeIgnoresUnsignedCertificate(t *testing.T) {
	s := mustSetup(t)
	req := request("req-forged", eligibleRequester(t, s), "tx-00000003")
	addr := contractAddress(req.ID)
	committee, _ := s.registry.selectCommittee(addr, testPolicy, testCommittee)

	target, _ := s.ledger.lookup(req.TargetTxID)
	cert, _ := s.ca.validate(req, target, s.policies["pol-0000"], testPolicy)

	// Flip the decision after signing: the signature no longer matches.
	cert.Redactable = true
	cert.Satisfies = true
	cert.RequesterKnown = true
	cert.TargetTxID = "tx-genesis"

	ballots, err := localTransport{}.Collect(context.Background(), &voteRound{
		ContractAddr: addr, RequestID: req.ID, Cert: cert, CA: s.ca,
		Members: committee, Threshold: testThreshold, Window: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(ballots) != 0 {
		t.Errorf("%d members voted on a certificate the CA did not sign, want 0", len(ballots))
	}
}

// Regression: T_rdbl must not depend on who is asking.
//
// An earlier version folded "requester unknown" into Redactable, so a
// certificate for an unregistered requester asserted that a perfectly ordinary
// transaction was outside T_rdbl (Eq. 6). Committee members re-derive their
// decision from P_C, so they would have been reasoning from a false claim about
// the ledger — and the denial reason named the wrong cause, which is how it was
// noticed. The three conditions are recorded separately for this reason.
func TestCertificateSeparatesRequesterValidityFromRedactability(t *testing.T) {
	s := mustSetup(t)
	target, found := s.ledger.lookup("tx-00000003")
	if !found {
		t.Fatal("fixture error: target missing")
	}
	policy := s.policies["pol-0000"]

	known, err := s.ca.validate(request("c1", eligibleRequester(t, s), "tx-00000003"),
		target, policy, testPolicy)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	unknown, err := s.ca.validate(request("c2", "id-999999", "tx-00000003"),
		target, policy, testPolicy)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}

	if !known.Redactable {
		t.Fatal("fixture error: expected a redactable target")
	}
	if unknown.Redactable != known.Redactable {
		t.Errorf("Redactable is %v for an unknown requester and %v for a known one; "+
			"T_rdbl is a property of the ledger, not of the requester",
			unknown.Redactable, known.Redactable)
	}
	if unknown.RequesterKnown {
		t.Errorf("an unregistered requester passed V(n_i, C)")
	}
	if unknown.Granted() {
		t.Errorf("granted a request from an unregistered requester")
	}

	// The genesis transaction is genuinely outside T_rdbl, so Redactable must
	// be able to be false — otherwise the field above proves nothing.
	gen, _ := s.ledger.lookup("tx-genesis")
	genCert, err := s.ca.validate(request("c3", eligibleRequester(t, s), "tx-genesis"),
		gen, policy, testPolicy)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if genCert.Redactable {
		t.Errorf("genesis transaction reported as redactable")
	}
}

// V(n_i, C) must be covered by the CA signature, like the other two conditions.
// A field outside the signed bytes can be flipped in transit, and a committee
// member verifying P_C would accept the altered value.
func TestCertificateSignatureCoversAllThreeConditions(t *testing.T) {
	s := mustSetup(t)
	target, _ := s.ledger.lookup("tx-00000003")

	for _, tc := range []struct {
		name string
		flip func(*policyCert)
	}{
		{"RequesterKnown", func(c *policyCert) { c.RequesterKnown = !c.RequesterKnown }},
		{"Redactable", func(c *policyCert) { c.Redactable = !c.Redactable }},
		{"Satisfies", func(c *policyCert) { c.Satisfies = !c.Satisfies }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert, err := s.ca.validate(request("s1", eligibleRequester(t, s), "tx-00000003"),
				target, s.policies["pol-0000"], testPolicy)
			if err != nil {
				t.Fatalf("validate: %v", err)
			}
			tc.flip(cert)
			if s.ca.verifyCert(cert) {
				t.Errorf("CA signature still verifies after %s was altered; "+
					"the field is outside the signed bytes", tc.name)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Audit must verify every located redaction transaction
//
// The Exp 3 measurement boundary is "all located redaction transactions
// verified via Algorithm 1" (spec §2). Verifying only the target would make
// Ref[10]'s verification cost independent of history depth — a property it has
// no mechanism to provide, and one that would show it flat against ZK-Redact on
// Exp 3's second plot.
// -----------------------------------------------------------------------------

// redactNTimes drives a target to the requested history depth through the
// scheme's own Authorize and Redact.
func redactNTimes(t *testing.T, s *Scheme, target string, n int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		req := request(fmt.Sprintf("h-%s-%d", target, i), eligibleRequester(t, s), target)
		req.NewContent = []byte(fmt.Sprintf("revision %d", i+1))
		auth, err := s.Authorize(ctx, req)
		if err != nil || !auth.Granted {
			t.Fatalf("Authorize revision %d: %v (%s)", i+1, err, auth.Reason)
		}
		r, err := s.Redact(ctx, []*scheme.Authorization{auth})
		if err != nil || r.Succeeded != 1 {
			t.Fatalf("Redact revision %d: %v (succeeded=%d)", i+1, err, r.Succeeded)
		}
	}
}

func TestAuditVerifiesEveryLocatedRedaction(t *testing.T) {
	s := mustSetup(t)
	redactNTimes(t, s, "tx-00000003", 4)

	res, err := s.Audit(context.Background(), &scheme.AuditQuery{TargetTxID: "tx-00000003"})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if len(res.History) != 4 {
		t.Fatalf("history has %d entries, want 4", len(res.History))
	}
	if !res.Verified {
		t.Errorf("a genuine history failed verification")
	}
}

// If a stored Sigma is tampered with, the audit must fail. Without per-record
// verification this passes regardless, which is exactly how the gap survived.
func TestAuditRejectsTamperedRedactionRecord(t *testing.T) {
	s := mustSetup(t)
	redactNTimes(t, s, "tx-00000003", 3)

	found, _, _ := s.ledger.scanForRedactions("tx-00000003")
	if len(found) != 3 {
		t.Fatalf("expected 3 redaction records, got %d", len(found))
	}

	// Corrupt one signature scalar in the middle record's stored Sigma.
	tx, ok := s.ledger.lookup(found[1].RdtTxID)
	if !ok {
		t.Fatal("redaction transaction not found")
	}
	ev := tx.rdt.Evidence
	for i := range ev {
		if ev[i] >= '0' && ev[i] <= '8' {
			ev[i]++
			break
		}
	}

	res, err := s.Audit(context.Background(), &scheme.AuditQuery{TargetTxID: "tx-00000003"})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if res.Verified {
		t.Errorf("audit accepted a redaction record whose Sigma was altered")
	}
}

// A Sigma padded to threshold with one member's repeated vote must fail.
func TestAuditRejectsDuplicatePaddedRecord(t *testing.T) {
	s := mustSetup(t)
	redactNTimes(t, s, "tx-00000004", 1)

	found, _, _ := s.ledger.scanForRedactions("tx-00000004")
	tx, _ := s.ledger.lookup(found[0].RdtTxID)

	entries, err := parseSigma(tx.rdt.Evidence)
	if err != nil {
		t.Fatalf("parseSigma: %v", err)
	}
	// Rebuild Sigma from the first entry repeated.
	var padded []byte
	for i := 0; i < len(entries); i++ {
		padded = append(padded, entries[0].NodeID...)
		padded = append(padded, 0x1f)
		padded = append(padded, []byte(entries[0].Sig.E.Text(16))...)
		padded = append(padded, 0x1f)
		padded = append(padded, []byte(entries[0].Sig.S.Text(16))...)
		padded = append(padded, 0x1e)
	}
	tx.rdt.Evidence = padded

	res, _ := s.Audit(context.Background(), &scheme.AuditQuery{TargetTxID: "tx-00000004"})
	if res.Verified {
		t.Errorf("audit accepted a Sigma padded with one member's repeated vote")
	}
}

// Sigma must survive the ledger round trip: an auditor has only the stored
// bytes, so an encoding that cannot be parsed back makes verification
// impossible regardless of what the signatures say.
func TestSigmaRoundTrip(t *testing.T) {
	s := mustSetup(t)
	req := request("rt-1", eligibleRequester(t, s), "tx-00000003")
	auth, err := s.Authorize(context.Background(), req)
	if err != nil || !auth.Granted {
		t.Fatalf("Authorize: %v", err)
	}

	entries, err := parseSigma(auth.Evidence)
	if err != nil {
		t.Fatalf("parseSigma: %v", err)
	}
	rec := s.rounds[req.ID]
	if len(entries) != len(rec.Approved) {
		t.Fatalf("recovered %d votes, want %d", len(entries), len(rec.Approved))
	}
	for i, e := range entries {
		if e.NodeID != rec.Approved[i].NodeID {
			t.Errorf("vote %d: node %s, want %s", i, e.NodeID, rec.Approved[i].NodeID)
		}
		if e.Sig.E.Cmp(rec.Approved[i].Xi.E) != 0 || e.Sig.S.Cmp(rec.Approved[i].Xi.S) != 0 {
			t.Errorf("vote %d: signature scalars did not survive encoding", i)
		}
	}

	for _, bad := range [][]byte{nil, {}, []byte("garbage"), []byte("a\x1fzz\x1f01\x1e")} {
		if _, err := parseSigma(bad); err == nil {
			t.Errorf("parseSigma accepted malformed input %q", bad)
		}
	}
}

// -----------------------------------------------------------------------------
// Algorithm 1 must validate a redacted transaction AGAINST its redaction
// transaction (spec §1.2), not merely recompute its hashes.
//
// The recomputed hashes always agree with whatever a node wrote, so hash checks
// alone cannot tell an authorised redaction from an arbitrary edit. These are
// the tests that make the difference detectable.
// -----------------------------------------------------------------------------

func TestAuditRejectsPrunedContentReplacedByArbitraryData(t *testing.T) {
	s := mustSetup(t)
	redactNTimes(t, s, "tx-00000003", 1)

	tx, _ := s.ledger.lookup("tx-00000003")
	loc := s.ledger.txLoc["tx-00000003"]
	b := s.ledger.blocks[loc.Block]

	// A node substitutes its own content for the authorised reference and
	// rebuilds the block so every hash is internally consistent.
	tx.Redactable = []byte("content this node preferred")
	tx.HW = merkle.HashLeaf(tx.Redactable)
	tx.HTx = hashTx(tx.HC, tx.HW)
	if err := b.rebuild(); err != nil {
		t.Fatalf("rebuild: %v", err)
	}

	if s.verifyEMT("tx-00000003") {
		t.Errorf("Algorithm 1 accepted a redaction that replaced d_w with unauthorised content")
	}
}

func TestAuditRejectsReferenceToWrongTarget(t *testing.T) {
	s := mustSetup(t)
	redactNTimes(t, s, "tx-00000003", 1)
	redactNTimes(t, s, "tx-00000004", 1)

	// Point tx-00000003's d_w at the redaction transaction that authorised a
	// DIFFERENT transaction's redaction. It is a real, fully signed tx_rdt.
	other, _, _ := s.ledger.scanForRedactions("tx-00000004")
	if len(other) != 1 {
		t.Fatalf("expected one redaction record, got %d", len(other))
	}

	tx, _ := s.ledger.lookup("tx-00000003")
	loc := s.ledger.txLoc["tx-00000003"]
	tx.Redactable = redactionReference(other[0].RdtTxID)
	tx.HW = merkle.HashLeaf(tx.Redactable)
	tx.HTx = hashTx(tx.HC, tx.HW)
	if err := s.ledger.blocks[loc.Block].rebuild(); err != nil {
		t.Fatalf("rebuild: %v", err)
	}

	if s.verifyEMT("tx-00000003") {
		t.Errorf("Algorithm 1 accepted a reference to a redaction transaction for another target")
	}
}

func TestAuditRejectsDanglingReference(t *testing.T) {
	s := mustSetup(t)
	redactNTimes(t, s, "tx-00000003", 1)

	tx, _ := s.ledger.lookup("tx-00000003")
	loc := s.ledger.txLoc["tx-00000003"]
	tx.Redactable = redactionReference("tx-rdt-never-committed")
	tx.HW = merkle.HashLeaf(tx.Redactable)
	tx.HTx = hashTx(tx.HC, tx.HW)
	if err := s.ledger.blocks[loc.Block].rebuild(); err != nil {
		t.Fatalf("rebuild: %v", err)
	}

	if s.verifyEMT("tx-00000003") {
		t.Errorf("Algorithm 1 accepted a reference to a redaction transaction that is not on the ledger")
	}
}

func TestAuditRejectsUnredactedTransactionCarryingAReference(t *testing.T) {
	s := mustSetup(t)
	redactNTimes(t, s, "tx-00000003", 1)
	found, _, _ := s.ledger.scanForRedactions("tx-00000003")

	// tx-00000005 was never redacted, so Version is 0. Planting a valid-looking
	// reference must not make it verify.
	tx, _ := s.ledger.lookup("tx-00000005")
	loc := s.ledger.txLoc["tx-00000005"]
	tx.Redactable = redactionReference(found[0].RdtTxID)
	tx.HW = merkle.HashLeaf(tx.Redactable)
	tx.HTx = hashTx(tx.HC, tx.HW)
	if err := s.ledger.blocks[loc.Block].rebuild(); err != nil {
		t.Fatalf("rebuild: %v", err)
	}

	if s.verifyEMT("tx-00000005") {
		t.Errorf("Algorithm 1 accepted a reference on a transaction that was never redacted")
	}
}
