package pai

import (
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"zkredact/pkg/crypto"
)

// Phase 6 Step 1 has four ways to refuse a query, and a registry that could
// only ever accept would be indistinguishable from one that enforced nothing.
// Each is exercised here against a real Schnorr key.

func testRegistry(t *testing.T, now time.Time) (*AuditorRegistry, map[string]*crypto.SchnorrPrivateKey) {
	t.Helper()
	curve := elliptic.P256()

	keys := map[string]*crypto.SchnorrPrivateKey{}
	var auditors []Auditor
	for _, spec := range []struct {
		id     string
		policy *AuditPolicy
	}{
		{"auditor-0", &AuditPolicy{AllPolicies: true}},
		{"auditor-1", &AuditPolicy{PolicyIDs: map[string]struct{}{"pol-a": {}}}},
	} {
		sk, err := crypto.SchnorrKeyGen(curve, rand.Reader)
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		keys[spec.id] = sk
		auditors = append(auditors, Auditor{ID: spec.id, Key: &sk.SchnorrPublicKey, Policy: spec.policy})
	}

	reg, err := NewAuditorRegistry(auditors, time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewAuditorRegistry: %v", err)
	}
	return reg, keys
}

func signedRequest(t *testing.T, keys map[string]*crypto.SchnorrPrivateKey, id, txID string, ts time.Time, nonce string) *AuditRequest {
	t.Helper()
	req := &AuditRequest{
		AuditorID: id, TxID: txID, Epoch: 0,
		Timestamp: ts, Nonce: []byte(nonce),
	}
	sig, err := keys[id].Sign(req.Digest(), rand.Reader)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	req.Signature = sig
	return req
}

func TestAuthorizeAcceptsAWellFormedQuery(t *testing.T) {
	now := time.Now()
	reg, keys := testRegistry(t, now)

	req := signedRequest(t, keys, "auditor-0", "tx-1", now, "n1")
	if err := reg.Authorize(req, []string{"pol-a", "pol-b"}); err != nil {
		t.Fatalf("a valid query was refused: %v", err)
	}
}

func TestAuthorizeRejectsUnregisteredAuditor(t *testing.T) {
	now := time.Now()
	reg, keys := testRegistry(t, now)

	req := signedRequest(t, keys, "auditor-0", "tx-1", now, "n1")
	req.AuditorID = "auditor-99"
	if err := reg.Authorize(req, nil); err == nil {
		t.Error("an unregistered auditor was authorized")
	}
}

// TestAuthorizeRejectsAForgedSignature is the check that makes the registered
// key matter. Without it, AID_a alone would be the credential.
func TestAuthorizeRejectsAForgedSignature(t *testing.T) {
	now := time.Now()
	reg, keys := testRegistry(t, now)

	// A signature over a DIFFERENT request, presented with this one.
	other := signedRequest(t, keys, "auditor-0", "tx-other", now, "n0")
	req := signedRequest(t, keys, "auditor-0", "tx-1", now, "n1")
	req.Signature = other.Signature

	if err := reg.Authorize(req, nil); err == nil {
		t.Error("a request carrying another request's signature was authorized")
	}

	// Signed by the wrong auditor.
	req2 := &AuditRequest{AuditorID: "auditor-0", TxID: "tx-1", Timestamp: now, Nonce: []byte("n2")}
	sig, err := keys["auditor-1"].Sign(req2.Digest(), rand.Reader)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	req2.Signature = sig
	if err := reg.Authorize(req2, nil); err == nil {
		t.Error("a request signed by a different auditor's key was authorized")
	}

	if req.Signature == nil {
		t.Fatal("fixture problem")
	}
	unsigned := &AuditRequest{AuditorID: "auditor-0", TxID: "tx-1", Timestamp: now, Nonce: []byte("n3")}
	if err := reg.Authorize(unsigned, nil); err == nil {
		t.Error("an unsigned request was authorized")
	}
}

// TestAuthorizeRejectsStaleAndFutureRequests. Both directions: a stale request
// is a replay, and one stamped in the future would stay valid indefinitely.
func TestAuthorizeRejectsStaleAndFutureRequests(t *testing.T) {
	now := time.Now()
	reg, keys := testRegistry(t, now)

	old := signedRequest(t, keys, "auditor-0", "tx-1", now.Add(-2*time.Minute), "old")
	if err := reg.Authorize(old, nil); err == nil {
		t.Error("a request older than the freshness window was authorized")
	}
	future := signedRequest(t, keys, "auditor-0", "tx-1", now.Add(2*time.Minute), "future")
	if err := reg.Authorize(future, nil); err == nil {
		t.Error("a request stamped in the future was authorized")
	}
}

// TestAuthorizeRejectsAReplayedNonce covers the case a freshness window alone
// cannot: the same captured request, resubmitted inside the window.
func TestAuthorizeRejectsAReplayedNonce(t *testing.T) {
	now := time.Now()
	reg, keys := testRegistry(t, now)

	req := signedRequest(t, keys, "auditor-0", "tx-1", now, "same")
	if err := reg.Authorize(req, nil); err != nil {
		t.Fatalf("first submission refused: %v", err)
	}
	if err := reg.Authorize(req, nil); err == nil {
		t.Error("the identical request was accepted a second time")
	}

	reg.Reset()
	if err := reg.Authorize(req, nil); err != nil {
		t.Errorf("after Reset the request should be accepted again: %v", err)
	}
}

// TestAuthorizeEnforcesTheAuditScope is the check that makes Pi_a^audit more
// than a stored field.
func TestAuthorizeRejectsOutOfScope(t *testing.T) {
	now := time.Now()
	reg, keys := testRegistry(t, now)

	// auditor-1's scope is {pol-a} only.
	inScope := signedRequest(t, keys, "auditor-1", "tx-1", now, "s1")
	if err := reg.Authorize(inScope, []string{"pol-a"}); err != nil {
		t.Errorf("an in-scope query was refused: %v", err)
	}

	outOfScope := signedRequest(t, keys, "auditor-1", "tx-2", now, "s2")
	if err := reg.Authorize(outOfScope, []string{"pol-b"}); err == nil {
		t.Error("auditor-1 audited a policy outside its registered scope")
	}

	// Partial coverage must also be refused: the records come back together, so
	// permission for some of them is not permission for the query.
	partial := signedRequest(t, keys, "auditor-1", "tx-3", now, "s3")
	if err := reg.Authorize(partial, []string{"pol-a", "pol-b"}); err == nil {
		t.Error("auditor-1 read a history whose records span a policy it may not audit")
	}
}

func TestNewAuditorRegistryRejectsBadInput(t *testing.T) {
	curve := elliptic.P256()
	sk, err := crypto.SchnorrKeyGen(curve, rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	ok := Auditor{ID: "a", Key: &sk.SchnorrPublicKey, Policy: &AuditPolicy{AllPolicies: true}}

	if _, err := NewAuditorRegistry(nil, time.Minute, nil); err == nil {
		t.Error("a registry with no auditors was accepted; no query could ever be authorized")
	}
	if _, err := NewAuditorRegistry([]Auditor{ok}, 0, nil); err == nil {
		t.Error("a non-positive freshness window was accepted")
	}
	if _, err := NewAuditorRegistry([]Auditor{ok, ok}, time.Minute, nil); err == nil {
		t.Error("a duplicate auditor id was accepted")
	}
	if _, err := NewAuditorRegistry([]Auditor{{ID: "b"}}, time.Minute, nil); err == nil {
		t.Error("an auditor with no key or policy was accepted")
	}
}
