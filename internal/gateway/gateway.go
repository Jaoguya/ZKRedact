// Package gateway implements ZK-Redact's Phase 2 admission control.
//
// The Redaction Gateway authenticates each request, rejects stale and duplicate
// ones before any proof is verified, and strips the requester's identity before
// forwarding downstream.
//
// WHY PRE-FILTERING IS PART OF THE DESIGN, NOT AN OPTIMISATION. Phase 3 is the
// expensive stage: every accepted request costs a pairing check. A duplicate or
// stale request that reaches the verifier is a proof verified for nothing, and
// the manuscript's claim is that authenticated requests are pre-filtered before
// batch-parallel verification. Removing this stage would not fail a test — it
// would just make Exp 1 report a verification rate for a system doing more work
// than the design specifies.
package gateway

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"zkredact/pkg/crypto"
	"zkredact/pkg/scheme"
	"zkredact/pkg/zk"
)

// Rejection reasons. These are DENIALS, not errors: the request was well formed
// and the answer is no. Exp 1 counts denials separately from failures, and
// conflating them would let a gateway that rejects everything look like one
// that authorizes cheaply.
var (
	ErrBadSignature   = errors.New("gateway: request signature does not verify")
	ErrUnknownSender  = errors.New("gateway: requester is not registered")
	ErrStaleVersion   = errors.New("gateway: request targets a superseded transaction version")
	ErrStalePolicy    = errors.New("gateway: request cites a superseded policy version")
	ErrExpired        = errors.New("gateway: request is outside the freshness window")
	ErrDuplicate      = errors.New("gateway: a request with this deduplication id is already pending or processed")
	ErrUnknownPolicy  = errors.New("gateway: request names an unregistered policy")
	ErrPolicyMismatch = errors.New("gateway: policy commitment does not match the registered policy")
)

// Query is the authenticated request a requester submits: Q_i in the
// manuscript, (R_i, v_P, C_P, sigma_i, pi_i).
type Query struct {
	Request   *scheme.Request
	Statement *zk.Statement
	Proof     *zk.Proof

	// PolicyVersion and PolicyCommitment are carried explicitly so the gateway
	// can check them against the registry without opening the statement.
	PolicyVersion    uint64
	PolicyCommitment []byte

	Signature *crypto.SchnorrSignature
}

// Minimized is Q_i* = (DID_i, x_i, eta_i, pi_i): what the PVL and everything
// downstream receive.
//
// The requester's identity is ABSENT by construction rather than by convention.
// A field for it here would eventually be read by something downstream, and the
// scheme's anonymity claim is that nothing after the gateway sees it.
type Minimized struct {
	DID       []byte
	Statement *zk.Statement
	Digest    []byte
	Proof     *zk.Proof

	// TxVersion and PolicyVersion travel onward because Phase 4 revalidates
	// them; they say nothing about who asked.
	TxVersion     uint64
	PolicyVersion uint64

	AcceptedAt time.Time
}

// Registration is one requester's public key, as recorded at setup.
type Registration struct {
	ID  string
	Key *crypto.SchnorrPublicKey
}

// PolicyRecord is a registered policy and its commitment.
type PolicyRecord struct {
	Version    uint64
	Commitment []byte
}

// Gateway is the admission-control layer. Safe for concurrent use: Exp 1 drives
// it from every worker at once.
type Gateway struct {
	mu sync.Mutex

	keys     map[string]*crypto.SchnorrPublicKey
	policies map[string]PolicyRecord

	// seen holds DIDs that are pending or already processed. Phase 2 Step 3.
	seen map[string]struct{}

	// attribution maps DID back to the authenticated requester. The manuscript
	// is explicit that the gateway retains this: anonymity is against
	// downstream components, not against the gateway, and a redaction with no
	// accountable origin is not what the scheme claims.
	attribution map[string]string

	// txVersion and policyVersion are the current ledger state the gateway
	// checks freshness against.
	txVersion map[string]uint64

	window time.Duration
	now    func() time.Time
}

// Config carries the gateway's parameters. Every field is required: a defaulted
// freshness window would silently admit replays.
type Config struct {
	// FreshnessWindow bounds how old a request's timestamp may be.
	FreshnessWindow time.Duration

	// Now is injectable so freshness can be tested without sleeping.
	Now func() time.Time
}

// New builds a gateway over a registered population and policy set.
func New(cfg Config, regs []Registration, policies map[string]PolicyRecord, txVersions map[string]uint64) (*Gateway, error) {
	if cfg.FreshnessWindow <= 0 {
		return nil, fmt.Errorf("gateway: freshness window must be positive, got %s", cfg.FreshnessWindow)
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	keys := make(map[string]*crypto.SchnorrPublicKey, len(regs))
	for _, r := range regs {
		if r.Key == nil {
			return nil, fmt.Errorf("gateway: registration %s has no key", r.ID)
		}
		keys[r.ID] = r.Key
	}

	return &Gateway{
		keys:        keys,
		policies:    policies,
		seen:        make(map[string]struct{}),
		attribution: make(map[string]string),
		txVersion:   txVersions,
		window:      cfg.FreshnessWindow,
		now:         now,
	}, nil
}

// DedupID is DID_i = H(TID ‖ v ‖ Loc ‖ M ‖ PID).
//
// The transaction VERSION is included deliberately: it prevents reprocessing
// the same request against the same state while still permitting a new
// redaction once the state has advanced. Omitting it would make a transaction
// redactable exactly once, forever.
func DedupID(txID string, version uint64, loc uint64, mod []byte, policyID string) []byte {
	return zk.Hash(
		zk.FieldBytes([]byte(txID)),
		zk.Uint64Bytes(version),
		zk.Uint64Bytes(loc),
		zk.FieldBytes(mod),
		zk.FieldBytes([]byte(policyID)),
	)
}

// Admit runs Phase 2 Steps 3 and 4.
//
// Order matters and is the cheapest-first ordering that is still correct:
// signature, then freshness, then versions, then deduplication. Deduplication
// last because it MUTATES state — recording a DID for a request that then fails
// a later check would block the legitimate retry.
func (g *Gateway) Admit(q *Query) (*Minimized, error) {
	if q == nil || q.Request == nil || q.Statement == nil {
		return nil, fmt.Errorf("gateway: incomplete query")
	}
	req := q.Request

	// --- authenticate ---
	g.mu.Lock()
	pk, known := g.keys[req.RequesterID]
	g.mu.Unlock()
	if !known {
		return nil, fmt.Errorf("%w: %s", ErrUnknownSender, req.RequesterID)
	}
	if q.Signature == nil || !pk.Verify(q.Statement.Digest(), q.Signature) {
		return nil, ErrBadSignature
	}

	// --- freshness (t_i, nu_i) ---
	age := g.now().Sub(req.Timestamp)
	if age < 0 || age > g.window {
		return nil, fmt.Errorf("%w: age %s exceeds %s", ErrExpired, age, g.window)
	}

	// --- policy registration and version ---
	g.mu.Lock()
	pol, ok := g.policies[req.PolicyID]
	cur, txKnown := g.txVersion[req.TargetTxID]
	g.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownPolicy, req.PolicyID)
	}
	if q.PolicyVersion != pol.Version {
		return nil, fmt.Errorf("%w: request cites v%d, registry has v%d",
			ErrStalePolicy, q.PolicyVersion, pol.Version)
	}
	if string(q.PolicyCommitment) != string(pol.Commitment) {
		return nil, ErrPolicyMismatch
	}

	// --- transaction version ---
	if !txKnown {
		return nil, fmt.Errorf("%w: %s is not in the ledger", ErrStaleVersion, req.TargetTxID)
	}
	if q.Statement.TxVersion != cur {
		return nil, fmt.Errorf("%w: request targets v%d, ledger is at v%d",
			ErrStaleVersion, q.Statement.TxVersion, cur)
	}

	// --- deduplication, last because it mutates ---
	did := DedupID(req.TargetTxID, q.Statement.TxVersion, q.Statement.Loc,
		q.Statement.Mod, req.PolicyID)
	key := string(did)

	g.mu.Lock()
	if _, dup := g.seen[key]; dup {
		g.mu.Unlock()
		return nil, ErrDuplicate
	}
	g.seen[key] = struct{}{}
	g.attribution[key] = req.RequesterID
	g.mu.Unlock()

	return &Minimized{
		DID:           did,
		Statement:     q.Statement,
		Digest:        q.Statement.Digest(),
		Proof:         q.Proof,
		TxVersion:     q.Statement.TxVersion,
		PolicyVersion: q.PolicyVersion,
		AcceptedAt:    g.now(),
	}, nil
}

// Release removes a DID from the pending set.
//
// Phase 3 Step 4: a request whose proof fails verification has its identifier
// released "according to the request-management policy". Without this a
// requester who submitted one bad proof could never retry that redaction.
func (g *Gateway) Release(did []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.seen, string(did))
}

// Attribute returns the authenticated requester behind a DID.
//
// This is the accountability the scheme retains: anonymity holds against
// everything downstream of the gateway, not against the gateway itself.
func (g *Gateway) Attribute(did []byte) (string, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	id, ok := g.attribution[string(did)]
	return id, ok
}

// AdvanceTx records a new current version after a successful redaction, so
// subsequent requests against the old version are rejected as stale.
func (g *Gateway) AdvanceTx(txID string, version uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.txVersion[txID] = version
}

// Pending reports how many identifiers are held. Used by tests and by the
// runner's sanity checks; not part of the measured path.
func (g *Gateway) Pending() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.seen)
}
