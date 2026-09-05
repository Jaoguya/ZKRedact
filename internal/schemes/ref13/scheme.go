// Package ref13 re-implements the VRBC baseline.
//
// Paper: Tian, Wei, Kutylowski, Susilo, Huang, Chen, "VRBC: A Verifiable
// Redactable Blockchain With Efficient Query and Integrity Auditing,"
// IEEE Transactions on Computers, 2023.
// Spec: docs/baselines/ref13-vrbc.md
//
// Primary competitor for Exp 3 — the only baseline with a real audit protocol.
// In Exp 1 it is a lower bound only: the scheme defines no per-request
// authorization, and we do not invent one on its behalf.
package ref13

import (
	"context"
	"fmt"
	"sync"

	"zkredact/pkg/scheme"
)

// Scheme is the VRBC baseline.
type Scheme struct {
	mu    sync.RWMutex
	ready bool

	params scheme.SetupParams

	// arityQ is the BAT fan-out. It trades costs in opposite directions —
	// append cost rises with q while redaction and audit costs fall — so it is
	// swept rather than fixed. A single value would let that choice decide the
	// outcome of Exps 2 and 3.
	arityQ int

	// vectorDimension is derived, not configured: a node commits to its own
	// data plus its q children, so N = q + 1. The paper's pairs confirm it
	// (q = 2,5,10 with N = 3,6,11).
	vectorDimension int

	// challengedBlocks is the audit sample size, from Ateniese et al.'s PDP
	// analysis at 1% corruption. The derivation is what transfers, not the
	// number — if corruptedRate changes, these must be recomputed.
	challengedBlocks int
	corruptedRate    float64

	// optimizedAuditing selects the §4.1 path-union strategy. Enabled, because
	// it is the configuration under which the paper reports its results.
	optimizedAuditing bool
}

func New() *Scheme { return &Scheme{} }

func (s *Scheme) Name() string { return "ref13_vrbc" }

func (s *Scheme) Capabilities() scheme.Capabilities {
	return scheme.Capabilities{
		PrivacyPreservingAuth: false, // authority rests on trapdoor possession
		PolicyBound:           false, // no policy evaluation per request
		DecentralizedAuth:     false, // single system manager holds the trapdoor
		ParallelVerification:  false, // that manager is a serialization point
		BatchRedaction:        false, // delayed redaction proposed but unspecified
		PerTxProvenance:       false, // audits ledger integrity, not tx history
		LedgerIndependentAudit: true, // BAT gives sublinear audit cost
		StateFreshnessCheck:   false,
	}
}

func (s *Scheme) Setup(ctx context.Context, p scheme.SetupParams) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if p.Dataset == nil {
		return fmt.Errorf("ref13: setup requires a dataset")
	}

	var err error
	if s.arityQ, err = intParam(p.Params, "arity_q"); err != nil {
		return fmt.Errorf("ref13: %w", err)
	}
	if s.arityQ < 2 {
		return fmt.Errorf("ref13: arity_q must be >= 2, got %d", s.arityQ)
	}
	// Derived, never read from config — an independently configured N could
	// silently contradict the tree structure.
	s.vectorDimension = s.arityQ + 1

	if s.challengedBlocks, err = intParam(p.Params, "challenged_blocks"); err != nil {
		return fmt.Errorf("ref13: %w", err)
	}
	if v, ok := p.Params["corrupted_block_rate"].(float64); ok {
		s.corruptedRate = v
	} else {
		return fmt.Errorf("ref13: missing parameter corrupted_block_rate")
	}
	// The sample size is only meaningful at the corruption rate it was derived
	// for. Silently accepting a different rate would leave challengedBlocks
	// claiming a detection precision it no longer provides.
	if s.corruptedRate != 0.01 {
		return fmt.Errorf(
			"ref13: challenged_blocks=%d derives from Ateniese et al. at 1%% corruption; "+
				"corrupted_block_rate=%v requires recomputing it",
			s.challengedBlocks, s.corruptedRate)
	}

	if v, ok := p.Params["optimized_auditing"].(bool); ok {
		s.optimizedAuditing = v
	} else {
		return fmt.Errorf("ref13: missing parameter optimized_auditing")
	}

	s.params = p

	// TODO: generate CH keys and vector-commitment public parameters over
	// BLS12-381 (NOT BN254 — see config security notes).
	// TODO: build the q-ary BAT over the materialised ledger; commitments must
	// be real cryptographic commitments, not hash placeholders.
	return fmt.Errorf("ref13.Setup: %w", scheme.ErrNotImplemented)
}

// Authorize verifies trapdoor possession.
//
// This scheme specifies no per-request authorization protocol: redaction
// authority rests with the system manager who holds the trapdoor. We measure
// exactly that and do not synthesise a richer protocol for it — inventing one
// would be fabricating a result.
//
// It will therefore appear very fast at low concurrency. Under load, the single
// trapdoor holder is a genuine serialization point, which is a real property of
// the design rather than an artefact of the harness.
func (s *Scheme) Authorize(ctx context.Context, req *scheme.Request) (*scheme.Authorization, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	// TODO: verify the caller holds the system-manager trapdoor. Must be a real
	// check that can fail — a stub returning true would benchmark beautifully
	// and measure nothing.
	return nil, fmt.Errorf("ref13.Authorize: %w", scheme.ErrNotImplemented)
}

// Redact computes a CH collision and updates node commitments along the path
// from the redacted block to the BAT root. Per-request by construction.
//
// Delayed redaction (§4.1) is deliberately not implemented: the paper proposes
// it but specifies no batch-formation policy, wait bound, or conflict handling,
// and never measures it. Building it would mean inventing those and then
// benchmarking our own design under their name.
func (s *Scheme) Redact(ctx context.Context, batch []*scheme.Authorization) (*scheme.RedactionResult, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	// TODO: per entry, CH.Adapt then update commitments for every node from the
	// redacted block to the root — no shortcuts; the path update is the cost.
	return nil, fmt.Errorf("ref13.Redact: %w", scheme.ErrNotImplemented)
}

// Audit runs the challenge-response protocol of §3.2.5.
//
// Semantics note: this verifies ledger integrity, not a transaction's redaction
// history. Exp 3 compares cost scaling against ledger size, which both schemes
// answer; it does not claim feature equivalence, which they do not have.
func (s *Scheme) Audit(ctx context.Context, q *scheme.AuditQuery) (*scheme.AuditResult, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	// TODO: issue Chal = (z, phi1, phi2); generate the integrity proof
	// (Algorithm 3); verify the aggregate pairing equation and then Eq. 12 over
	// every challenged block.
	// Result must carry Semantics = SemanticsLedgerIntegrity.
	// A tampered block MUST be detected — see the fidelity checklist.
	return nil, fmt.Errorf("ref13.Audit: %w", scheme.ErrNotImplemented)
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
		return fmt.Errorf("ref13: Setup has not completed")
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
