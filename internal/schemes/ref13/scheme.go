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
	"crypto/elliptic"
	"fmt"
	"sync"

	"zkredact/pkg/ch"
	"zkredact/pkg/scheme"
	"zkredact/pkg/vc"
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
	//
	// It restricts challenges to LEAF nodes. It does NOT produce a smaller path
	// union than uniform sampling — see docs/baselines/ref13-vrbc.md — so the
	// arm must not be reported as the cheaper configuration.
	optimizedAuditing bool

	// chCurve is the chameleon hash curve, from security.chameleon_hash_curve.
	chCurve string

	// --- built by build(), not configured ---

	curve    elliptic.Curve
	key      *ch.EphemeralKey
	vcParams *vc.Params
	bat      *BAT

	// blocks is the ledger, indexed by seq-1. Block indices start at 1 because
	// BAT node 0 is the root and holds no block.
	blocks  []*block
	blockOf map[string]int

	// versions counts redactions per block, indexed by seq. Redact compares it
	// against the authorization so a stale request is excluded rather than
	// silently applied.
	versions map[int]int

	// prevHash is h_{i-1} while the chain is being built. A redaction does NOT
	// disturb it: ch_i is invariant under a collision, which is the whole point.
	prevHash []byte
}

func New() *Scheme { return &Scheme{} }

func (s *Scheme) Name() string { return "ref13_vrbc" }

func (s *Scheme) Capabilities() scheme.Capabilities {
	return scheme.Capabilities{
		PrivacyPreservingAuth:  false, // authority rests on trapdoor possession
		PolicyBound:            false, // no policy evaluation per request
		DecentralizedAuth:      false, // single system manager holds the trapdoor
		ParallelVerification:   false, // that manager is a serialization point
		BatchRedaction:         false, // delayed redaction proposed but unspecified
		PerTxProvenance:        false, // audits ledger integrity, not tx history
		LedgerIndependentAudit: true,  // BAT gives sublinear audit cost
		StateFreshnessCheck:    false,
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

	if v, ok := p.Params["chameleon_hash_curve"].(string); ok {
		s.chCurve = v
	} else {
		return fmt.Errorf("ref13: missing parameter chameleon_hash_curve")
	}

	// The audit cannot challenge more blocks than the ledger holds. Left
	// unchecked, SelectChallenged would return fewer than z and the run would
	// silently measure a smaller audit than the config asked for.
	if s.challengedBlocks > len(p.Dataset.Transactions) {
		return fmt.Errorf(
			"ref13: challenged_blocks=%d exceeds the %d blocks in the dataset; "+
				"the audit would measure a smaller sample than configured",
			s.challengedBlocks, len(p.Dataset.Transactions))
	}

	s.params = p
	s.versions = make(map[int]int, len(p.Dataset.Transactions))

	if err := s.build(p); err != nil {
		return err
	}

	s.ready = true
	return nil
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
