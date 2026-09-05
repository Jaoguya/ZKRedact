// Package ref10 re-implements the EMT baseline.
//
// Paper: Wu, Wang, Zhang, Feng, "EMT: Extended Merkle Tree Structure for
// Inserted Data Redaction in Permissioned Blockchain," IEEE TNSE 2025.
// Spec: docs/baselines/ref10-emt.md
//
// Primary competitor for Exp 1 — the only baseline with a genuine per-request
// authorization protocol, and the only one already on Fabric, which minimises
// platform-induced difference.
//
// Algorithm mapping:
//
//	Algorithm 1 EMT Verification       -> Audit
//	Algorithm 2 Redaction Request      -> Authorize (CA validation, policy)
//	Algorithm 3 Smart Contract         -> Authorize (committee, voting)
//	Algorithm 4 Redaction Voting       -> Authorize (Schnorr signatures)
//	Algorithm 5 Local Redaction        -> Redact
package ref10

import (
	"context"
	"fmt"
	"sync"

	"zkredact/pkg/ch"
	"zkredact/pkg/scheme"
)

// Scheme is the EMT baseline.
type Scheme struct {
	mu    sync.RWMutex
	ready bool

	params scheme.SetupParams

	// committeeSize and voteThreshold come from an explicit fault assumption:
	// tolerate f Byzantine members, requiring 3f+1 members and 2f+1 approvals.
	// Undersizing these would make the primary Exp 1 competitor artificially
	// fast — the easiest objection for a reviewer to raise.
	committeeSize int
	voteThreshold int

	// voteWindowMS is a TIMEOUT, not a fixed wait. The round closes the moment
	// the threshold is reached. Waiting the full window instead would inflate
	// Ref[10]'s latency by a constant we chose rather than measuring its
	// protocol. See docs/baselines/ref10-emt.md §2.
	voteWindowMS int

	// attributePolicy is A_r, the paper's own default {S OR R OR V}. Anything
	// stricter would shrink the eligible committee and tilt Exp 1 our way.
	attributePolicy string
}

func New() *Scheme { return &Scheme{} }

func (s *Scheme) Name() string { return "ref10_emt" }

func (s *Scheme) Capabilities() scheme.Capabilities {
	return scheme.Capabilities{
		PrivacyPreservingAuth: false, // votes are attributable to identified nodes
		PolicyBound:           true,  // P_C constrains redactable transactions, partially
		DecentralizedAuth:     true,  // committee vote, no single authority
		ParallelVerification:  false, // voting rounds serialise
		BatchRedaction:        false, // per-request; this is the B_R=1 point
		PerTxProvenance:       false, // no per-transaction history index
		LedgerIndependentAudit: false, // locating redaction transactions scans
		StateFreshnessCheck:   false, // no execution-time revalidation
	}
}

func (s *Scheme) Setup(ctx context.Context, p scheme.SetupParams) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Refuse to run on a chameleon hash construction other than the one this
	// scheme's paper specifies. A substituted construction changes CryptoTime,
	// which Exp 2 reports as a headline metric, and would fail no other check.
	if err := ch.CheckRequired(s.Name()); err != nil {
		return fmt.Errorf("%s: %w", s.Name(), err)
	}

	if p.Dataset == nil {
		return fmt.Errorf("ref10: setup requires a dataset")
	}

	var err error
	if s.committeeSize, err = intParam(p.Params, "committee_size"); err != nil {
		return fmt.Errorf("ref10: %w", err)
	}
	if s.voteThreshold, err = intParam(p.Params, "vote_threshold"); err != nil {
		return fmt.Errorf("ref10: %w", err)
	}
	if s.voteWindowMS, err = intParam(p.Params, "vote_window_ms"); err != nil {
		return fmt.Errorf("ref10: %w", err)
	}
	if v, ok := p.Params["attribute_policy"].(string); ok {
		s.attributePolicy = v
	} else {
		return fmt.Errorf("ref10: missing parameter attribute_policy")
	}

	// Guard the fairness properties of the committee. A threshold that is not a
	// real majority would let two conflicting redactions both pass, and would
	// also make this baseline faster than its own design permits.
	if s.voteThreshold > s.committeeSize {
		return fmt.Errorf("ref10: threshold %d exceeds committee size %d",
			s.voteThreshold, s.committeeSize)
	}
	if s.voteThreshold <= s.committeeSize/2 {
		return fmt.Errorf("ref10: threshold %d is not a majority of %d",
			s.voteThreshold, s.committeeSize)
	}

	s.params = p

	// TODO: build the EMT — core branch and inserted branch per transaction,
	// H_tx = H(H_c || H_w) (Eq. 4). Materialise p.Dataset into it. Not timed.
	// TODO: deploy the redaction chaincode; register identities with {S,R,V}.
	return fmt.Errorf("ref10.Setup: %w", scheme.ErrNotImplemented)
}

// Authorize runs Algorithms 2, 3 and 4: CA validation, committee selection,
// vote collection, and aggregate signature verification.
//
// Measured boundary: request admitted -> threshold reached and Sigma verified.
// Votes must travel over the real network. Short-circuiting them to in-process
// calls would remove the very cost that distinguishes this scheme.
func (s *Scheme) Authorize(ctx context.Context, req *scheme.Request) (*scheme.Authorization, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	// TODO(alg2): verify requester validity V(n_i, C); build policy P_C with
	// T_rdbl = T_all \ (T_gen U T_rdt U T_con) (Eq. 6).
	// TODO(alg3): select committee via RS_SHA256(addr(con_k), N_all, A_r) (Eq. 7)
	// — genuinely hash-based over the full node set, not a fixed list.
	// TODO(alg4): collect real Schnorr signatures over the network; verify each;
	// close the round on threshold, treating voteWindowMS strictly as a timeout.
	// If that timeout ever fires, the run is invalid and must be discarded.
	return nil, fmt.Errorf("ref10.Authorize: %w", scheme.ErrNotImplemented)
}

// Redact runs Algorithm 5. This scheme has no batching, so the slice is
// processed one entry at a time — which is exactly what makes it the B_R=1
// reference point for Exp 2.
func (s *Scheme) Redact(ctx context.Context, batch []*scheme.Authorization) (*scheme.RedactionResult, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	// TODO(alg5): per entry, verify tx_rdt against Sigma, locate the block
	// holding tx_id, replace tx_n.d_w with a reference to tx_rdt, update the
	// ledger.
	// Redaction consensus IS included here, unlike the paper, which excluded it
	// (Ref[10].md:466). Excluding it would hide the cost ZK-Redact amortises,
	// which is the effect Exp 2 exists to measure.
	// LedgerTime is charged per request, not per batch — there is no batch.
	return nil, fmt.Errorf("ref10.Redact: %w", scheme.ErrNotImplemented)
}

// Audit reconstructs a transaction's redaction history by locating every
// redaction transaction referencing it, then verifying via Algorithm 1.
//
// There is no per-transaction provenance index, so cost is expected to grow
// with ledger size. BlocksTraversed must reflect that honestly.
func (s *Scheme) Audit(ctx context.Context, q *scheme.AuditQuery) (*scheme.AuditResult, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	// TODO(alg1): recompute H_c, H_w, H_tx and compare against the block record;
	// for redacted transactions confirm H_c is unchanged before validating H_tx'.
	// A redaction that altered core data MUST fail — see the fidelity checklist.
	return nil, fmt.Errorf("ref10.Audit: %w", scheme.ErrNotImplemented)
}

func (s *Scheme) Teardown(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ready = false
	return nil
}

func (s *Scheme) check() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.ready {
		return fmt.Errorf("ref10: Setup has not completed")
	}
	return nil
}

func intParam(m map[string]any, key string) (int, error) {
	v, ok := m[key]
	if !ok {
		return 0, fmt.Errorf("missing parameter %s", key)
	}
	switch n := v.(type) {
	case int:
		return n, nil
	case int64:
		return int(n), nil
	case float64:
		return int(n), nil
	default:
		return 0, fmt.Errorf("parameter %s has type %T, want a number", key, v)
	}
}
