package pai

import (
	"fmt"
	"sync"
	"time"

	"zkredact/pkg/crypto"
)

// Phase 6 Step 1: auditor authentication and query authorization.
//
// WHY THIS IS TIMED SEPARATELY. No baseline authenticates the auditor at all —
// Ref[10], Ref[13] and Ref[22] answer an audit query from anyone. Folding this
// cost into Exp 3's total would charge ZK-Redact for a capability the others
// simply lack, so AuditResult.AuthorizationTime reports it as its own adder and
// docs/experiments.md says so.

// AuditPolicy is Pi_a^audit: the scope an auditor is permitted to query.
//
// Scoped by POLICY rather than left as a blanket permission. A registry where
// every auditor may audit everything would make AuditAuth a rubber stamp — it
// would return 1 for every input, and a check that cannot fail is not a check.
// docs/baselines and the fidelity rule in TASK.md both require each verification
// path to be able to reject; TestAuditAuthRejectsOutOfScope is where this one
// is shown to.
type AuditPolicy struct {
	// AllPolicies grants an unrestricted scope. The harness's own auditor holds
	// one, because Exp 3 measures a PERMITTED query; a denied one would measure
	// the rejection path instead.
	AllPolicies bool

	// PolicyIDs is the permitted set when AllPolicies is false.
	PolicyIDs map[string]struct{}
}

// Permits reports whether this auditor may audit a transaction whose history
// was produced under the given policies.
//
// ALL of the transaction's policies must be in scope. Requiring only one would
// let an auditor with narrow permission read a history whose other records it
// was never authorized to see — the records come back together, so partial
// permission is not a meaningful outcome.
func (p *AuditPolicy) Permits(policyIDs []string) bool {
	if p == nil {
		return false
	}
	if p.AllPolicies {
		return true
	}
	for _, id := range policyIDs {
		if _, ok := p.PolicyIDs[id]; !ok {
			return false
		}
	}
	return true
}

// Auditor is E_a^AU from Eq. (auditor-registration): (AID_a, pk_a, Pi_a^audit).
type Auditor struct {
	ID     string
	Key    *crypto.SchnorrPublicKey
	Policy *AuditPolicy
}

// AuditRequest is R_a^audit from Eq. (auditor-request), with its signature.
type AuditRequest struct {
	AuditorID string
	TxID      string
	Epoch     uint64
	Timestamp time.Time
	Nonce     []byte
	Signature *crypto.SchnorrSignature
}

// Digest is H(R_a^audit), the signed message.
func (r *AuditRequest) Digest() []byte {
	return AuditRequestDigest(r.AuditorID, r.TxID, r.Epoch, r.Timestamp.UnixNano(), r.Nonce)
}

// AuditorRegistry holds registered auditors and enforces Phase 6 Step 1.
type AuditorRegistry struct {
	mu sync.Mutex

	auditors map[string]*Auditor

	// seen holds nonces already used, so a captured request cannot be replayed.
	seen map[string]struct{}

	freshness time.Duration

	// now is injectable for the same reason the gateway's is: the harness
	// stamps requests from the trace's own clock, and checking them against
	// wall time would reject every one of them.
	now func() time.Time
}

// NewAuditorRegistry registers the auditors and the freshness bound.
func NewAuditorRegistry(auditors []Auditor, freshness time.Duration, now func() time.Time) (*AuditorRegistry, error) {
	if len(auditors) == 0 {
		return nil, fmt.Errorf("pai: no auditors registered; no audit query could be authorized")
	}
	if freshness <= 0 {
		return nil, fmt.Errorf("pai: audit freshness window must be positive, got %v", freshness)
	}
	if now == nil {
		now = time.Now
	}

	r := &AuditorRegistry{
		auditors:  make(map[string]*Auditor, len(auditors)),
		seen:      make(map[string]struct{}),
		freshness: freshness,
		now:       now,
	}
	for i := range auditors {
		a := auditors[i]
		if a.ID == "" || a.Key == nil || a.Policy == nil {
			return nil, fmt.Errorf("pai: auditor %d is incompletely registered", i)
		}
		if _, dup := r.auditors[a.ID]; dup {
			return nil, fmt.Errorf("pai: duplicate auditor %s", a.ID)
		}
		r.auditors[a.ID] = &a
	}
	return r, nil
}

// Authorize is Phase 6 Step 1: verify the auditor's signature, check freshness,
// and evaluate AuditAuth against the registered audit policy.
//
// policyIDs are the policies the target transaction's history was produced
// under; the caller reads them from the PAI. Passing them in rather than having
// this reach into the index keeps the authorization decision a function of its
// inputs, which is what makes it testable in isolation.
//
// A denial returns an error naming the reason. The query "proceeds only if the
// signature, freshness, and audit-authorization checks are valid; otherwise, it
// is rejected before provenance retrieval" — so a caller must not retrieve
// anything on error.
func (r *AuditorRegistry) Authorize(req *AuditRequest, policyIDs []string) error {
	if req == nil {
		return fmt.Errorf("pai: no audit request")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	a, ok := r.auditors[req.AuditorID]
	if !ok {
		return fmt.Errorf("pai: %s is not a registered auditor", req.AuditorID)
	}
	if req.Signature == nil {
		return fmt.Errorf("pai: audit request from %s is unsigned", req.AuditorID)
	}
	if !a.Key.Verify(req.Digest(), req.Signature) {
		return fmt.Errorf("pai: audit request from %s does not verify under its registered key", req.AuditorID)
	}

	// Freshness. Checked in both directions: a stale request is a replay, and
	// one stamped in the future would let an auditor mint a request that stays
	// valid indefinitely.
	age := r.now().Sub(req.Timestamp)
	if age > r.freshness || age < -r.freshness {
		return fmt.Errorf(
			"pai: audit request from %s is %v old, outside the %v freshness window",
			req.AuditorID, age, r.freshness)
	}

	// Nonce reuse is a replay even inside the window.
	key := req.AuditorID + "\x00" + string(req.Nonce)
	if _, used := r.seen[key]; used {
		return fmt.Errorf("pai: audit request from %s replays a used nonce", req.AuditorID)
	}

	if !a.Policy.Permits(policyIDs) {
		return fmt.Errorf(
			"pai: %s is not authorized to audit %s under its registered audit policy",
			req.AuditorID, req.TxID)
	}

	r.seen[key] = struct{}{}
	return nil
}

// Reset clears the used-nonce set.
//
// Needed for the same reason the gateway's deduplication state is rebuilt
// between replays: Exp 3 issues a query per repetition, and a registry that
// remembered nonces across them would reject every repetition after the first
// as a replay — which would present as an intermittent audit failure rather
// than as retained state.
func (r *AuditorRegistry) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = make(map[string]struct{})
}

// PolicyIDs returns the distinct policies a transaction's history was produced
// under, for AuditAuth.
func (ix *Index) PolicyIDs(txID string) ([]string, error) {
	ix.mu.RLock()
	defer ix.mu.RUnlock()

	st, ok := ix.state[txID]
	if !ok {
		return nil, fmt.Errorf("pai: transaction %s is not indexed", txID)
	}
	seen := make(map[string]struct{}, len(st.history))
	out := make([]string, 0, len(st.history))
	for _, rec := range st.history {
		if _, dup := seen[rec.PolicyID]; dup {
			continue
		}
		seen[rec.PolicyID] = struct{}{}
		out = append(out, rec.PolicyID)
	}
	return out, nil
}
