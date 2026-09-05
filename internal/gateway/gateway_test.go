package gateway

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"zkredact/pkg/crypto"
	"zkredact/pkg/scheme"
	"zkredact/pkg/zk"
)

const testWindow = 30 * time.Second

var fixedNow = time.Unix(1750000000, 0)

// -----------------------------------------------------------------------------
// Fixtures
// -----------------------------------------------------------------------------

type fixture struct {
	gw     *Gateway
	key    *crypto.SchnorrPrivateKey
	policy *zk.Policy
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	curve, err := crypto.SignatureCurve("P-256", 128)
	if err != nil {
		t.Fatalf("SignatureCurve: %v", err)
	}
	sk, err := crypto.SchnorrKeyGen(curve, rand.Reader)
	if err != nil {
		t.Fatalf("SchnorrKeyGen: %v", err)
	}

	pol, err := zk.CompilePolicy(scheme.Policy{
		ID: "pol-0000", Version: 1, Predicate: "((sender OR receiver) AND validator)",
	}, 3, 512)
	if err != nil {
		t.Fatalf("CompilePolicy: %v", err)
	}

	gw, err := New(
		Config{FreshnessWindow: testWindow, Now: func() time.Time { return fixedNow }},
		[]Registration{{ID: "id-000000", Key: &sk.SchnorrPublicKey}},
		map[string]PolicyRecord{"pol-0000": {Version: 1, Commitment: pol.Commitment()}},
		map[string]uint64{"tx-00000003": 0},
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &fixture{gw: gw, key: sk, policy: pol}
}

func (f *fixture) request() *scheme.Request {
	return &scheme.Request{
		ID:          "req-0001",
		RequesterID: "id-000000",
		TargetTxID:  "tx-00000003",
		NewContent:  []byte("redacted"),
		PolicyID:    "pol-0000",
		Timestamp:   fixedNow.Add(-time.Second),
		Nonce:       []byte("nonce-1"),
	}
}

// query builds a correctly signed query, which each test then perturbs.
func (f *fixture) query(t *testing.T, req *scheme.Request) *Query {
	t.Helper()

	st, err := zk.BuildStatement(req, f.policy, 0, 128)
	if err != nil {
		t.Fatalf("BuildStatement: %v", err)
	}
	sig, err := f.key.Sign(st.Digest(), rand.Reader)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return &Query{
		Request:          req,
		Statement:        st,
		PolicyVersion:    f.policy.Version,
		PolicyCommitment: f.policy.Commitment(),
		Signature:        sig,
	}
}

// -----------------------------------------------------------------------------
// Admission
// -----------------------------------------------------------------------------

func TestAdmitsAWellFormedRequest(t *testing.T) {
	f := newFixture(t)
	m, err := f.gw.Admit(f.query(t, f.request()))
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if len(m.DID) == 0 {
		t.Error("no deduplication id was assigned")
	}
	if string(m.Digest) != string(f.query(t, f.request()).Statement.Digest()) {
		t.Error("the forwarded digest is not eta_i")
	}
}

// TestRejections covers every reason a request is turned away before its proof
// is verified. Each is a DENIAL: Phase 3 costs a pairing check per request, so
// anything admitted here that should not be is a proof verified for nothing.
func TestRejections(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(t *testing.T, f *fixture, q *Query)
		want    error
		because string
	}{
		{
			name:    "forged signature",
			mutate:  func(t *testing.T, f *fixture, q *Query) { q.Signature.S.Add(q.Signature.S, bigOne()) },
			want:    ErrBadSignature,
			because: "an unauthenticated request must not reach the verifier",
		},
		{
			name: "unregistered requester",
			mutate: func(t *testing.T, f *fixture, q *Query) {
				q.Request.RequesterID = "id-999999"
			},
			want:    ErrUnknownSender,
			because: "accountability requires the gateway to know who asked",
		},
		{
			name: "stale transaction version",
			mutate: func(t *testing.T, f *fixture, q *Query) {
				f.gw.AdvanceTx("tx-00000003", 1)
			},
			want:    ErrStaleVersion,
			because: "a request against a superseded state cannot be executed",
		},
		{
			name: "stale policy version",
			mutate: func(t *testing.T, f *fixture, q *Query) {
				q.PolicyVersion = 99
			},
			want:    ErrStalePolicy,
			because: "the proof is bound to a policy version; a mismatch is unprovable downstream",
		},
		{
			name: "unregistered policy",
			mutate: func(t *testing.T, f *fixture, q *Query) {
				q.Request.PolicyID = "pol-9999"
			},
			want:    ErrUnknownPolicy,
			because: "an unregistered policy has no commitment to prove against",
		},
		{
			name: "policy commitment mismatch",
			mutate: func(t *testing.T, f *fixture, q *Query) {
				q.PolicyCommitment = zk.Hash(zk.Uint64Bytes(7))
			},
			want:    ErrPolicyMismatch,
			because: "C_P is what binds the proof to the registered policy",
		},
		{
			name: "expired request",
			mutate: func(t *testing.T, f *fixture, q *Query) {
				q.Request.Timestamp = fixedNow.Add(-2 * testWindow)
				*q = *f.query(t, q.Request)
			},
			want:    ErrExpired,
			because: "the freshness window is what stops a replay from an earlier epoch",
		},
		{
			name: "request from the future",
			mutate: func(t *testing.T, f *fixture, q *Query) {
				q.Request.Timestamp = fixedNow.Add(time.Hour)
				*q = *f.query(t, q.Request)
			},
			because: "a future timestamp would extend the replay window arbitrarily",
			want:    ErrExpired,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			q := f.query(t, f.request())
			tc.mutate(t, f, q)

			_, err := f.gw.Admit(q)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v — %s", err, tc.want, tc.because)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Deduplication
// -----------------------------------------------------------------------------

func TestDuplicateIsRejected(t *testing.T) {
	f := newFixture(t)
	if _, err := f.gw.Admit(f.query(t, f.request())); err != nil {
		t.Fatalf("first Admit: %v", err)
	}
	if _, err := f.gw.Admit(f.query(t, f.request())); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("got %v, want ErrDuplicate", err)
	}
}

// TestDedupIDIncludesTheVersion pins the reason the version is in DID: without
// it, a transaction could be redacted exactly once and never again, because the
// second legitimate request would collide with the first.
func TestDedupIDIncludesTheVersion(t *testing.T) {
	a := DedupID("tx-1", 0, 10, []byte("m"), "pol-0")
	b := DedupID("tx-1", 1, 10, []byte("m"), "pol-0")
	if string(a) == string(b) {
		t.Fatal("DID ignores the transaction version, so a transaction could only " +
			"ever be redacted once")
	}
}

func TestDedupIDBindsEveryComponent(t *testing.T) {
	base := DedupID("tx-1", 0, 10, []byte("m"), "pol-0")
	cases := map[string][]byte{
		"tx":     DedupID("tx-2", 0, 10, []byte("m"), "pol-0"),
		"loc":    DedupID("tx-1", 0, 11, []byte("m"), "pol-0"),
		"mod":    DedupID("tx-1", 0, 10, []byte("n"), "pol-0"),
		"policy": DedupID("tx-1", 0, 10, []byte("m"), "pol-1"),
	}
	for field, got := range cases {
		if string(got) == string(base) {
			t.Errorf("changing %s does not change the DID; two different requests "+
				"would deduplicate against each other", field)
		}
	}
}

// TestReleaseAllowsARetry pins Phase 3 Step 4's identifier release. Without it,
// one failed proof would block that redaction permanently.
func TestReleaseAllowsARetry(t *testing.T) {
	f := newFixture(t)

	m, err := f.gw.Admit(f.query(t, f.request()))
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	f.gw.Release(m.DID)

	if _, err := f.gw.Admit(f.query(t, f.request())); err != nil {
		t.Fatalf("a released request could not be retried: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Identity minimisation — the anonymity claim
// -----------------------------------------------------------------------------

// TestDownstreamCarriesNoRequesterIdentity is the structural check behind the
// scheme's anonymity claim: nothing after the gateway sees who asked.
func TestDownstreamCarriesNoRequesterIdentity(t *testing.T) {
	f := newFixture(t)
	req := f.request()

	m, err := f.gw.Admit(f.query(t, req))
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}

	// The DID must not be invertible to the requester by inspection: it is a
	// hash of request content, and the identity appears nowhere in it.
	if containsBytes(m.DID, []byte(req.RequesterID)) {
		t.Error("the requester id appears in the DID")
	}
	if m.Statement == nil {
		t.Fatal("no statement was forwarded")
	}
	// x_i binds the transaction, operation, policy and freshness — never the
	// requester. If this ever changes, the anonymity claim changes with it.
	if containsBytes(m.Statement.TxID, []byte(req.RequesterID)) {
		t.Error("the requester id appears in the forwarded statement")
	}
}

// TestGatewayRetainsAttribution pins the other half: anonymity is against
// downstream components, not against the gateway. A redaction with no
// accountable origin is not what the scheme claims.
func TestGatewayRetainsAttribution(t *testing.T) {
	f := newFixture(t)
	req := f.request()

	m, err := f.gw.Admit(f.query(t, req))
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	who, ok := f.gw.Attribute(m.DID)
	if !ok {
		t.Fatal("the gateway cannot attribute an admitted request")
	}
	if who != req.RequesterID {
		t.Errorf("attributed to %q, want %q", who, req.RequesterID)
	}
}

// -----------------------------------------------------------------------------
// Concurrency — Exp 1 drives this from every worker at once
// -----------------------------------------------------------------------------

func TestConcurrentAdmitAdmitsEachRequestExactlyOnce(t *testing.T) {
	f := newFixture(t)

	const workers = 64
	done := make(chan error, workers)
	for i := 0; i < workers; i++ {
		go func() {
			_, err := f.gw.Admit(f.query(t, f.request()))
			done <- err
		}()
	}

	admitted, duplicates := 0, 0
	for i := 0; i < workers; i++ {
		switch err := <-done; {
		case err == nil:
			admitted++
		case errors.Is(err, ErrDuplicate):
			duplicates++
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}

	if admitted != 1 {
		t.Errorf("%d of %d identical concurrent requests were admitted, want exactly 1: "+
			"the rest would each cost a pairing check downstream", admitted, workers)
	}
	if duplicates != workers-1 {
		t.Errorf("got %d duplicate rejections, want %d", duplicates, workers-1)
	}
}
