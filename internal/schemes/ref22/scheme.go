// Package ref22 re-implements the Shen et al. baseline.
//
// Paper: Shen, Chen, Liu, Susilo, "Verifiable and Redactable Blockchains With
// Fully Editing Operations," IEEE TIFS 2023.
// Spec: docs/baselines/ref22-shen.md
//
// Contributes the only multi-item cost curve among the three baselines: Delete
// takes a SET of positions and reports consecutive and inconsecutive cases
// separately, which maps onto ZK-Redact's independent-vs-serialized split.
//
// In Exp 3 it is the linear-scan reference point that ZK-Redact's ledger
// independence is demonstrated against.
package ref22

import (
	"context"
	"fmt"
	"sync"

	"zkredact/pkg/scheme"
)

// Scheme is the Shen et al. baseline.
type Scheme struct {
	mu    sync.RWMutex
	ready bool

	params scheme.SetupParams

	// accumulatorBits sizes the trapdoorless universal accumulator. The paper
	// pairs RSA-3072 with P-256, both at 128-bit; the level must match every
	// other system or the comparison is void.
	accumulatorBits int

	// implementInsert is false. Block insertion is this paper's distinctive
	// capability, but no other scheme has a counterpart, so there is nothing to
	// compare it against. Acknowledged in related work rather than dropped
	// silently.
	implementInsert bool
}

func New() *Scheme { return &Scheme{} }

func (s *Scheme) Name() string { return "ref22_shen" }

func (s *Scheme) Capabilities() scheme.Capabilities {
	return scheme.Capabilities{
		PrivacyPreservingAuth: false, // regulator key possession
		PolicyBound:           false, // no per-request policy evaluation
		DecentralizedAuth:     false, // single regulator issues per-block keys
		ParallelVerification:  false, // that regulator is a serialization point
		BatchRedaction:        false, // Delete(L) is one op over many blocks,
		                              // not amortisation across authorized requests
		PerTxProvenance:       false,
		LedgerIndependentAudit: false, // ValChain traverses the whole chain
		StateFreshnessCheck:   false,
	}
}

func (s *Scheme) Setup(ctx context.Context, p scheme.SetupParams) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if p.Dataset == nil {
		return fmt.Errorf("ref22: setup requires a dataset")
	}

	var err error
	if s.accumulatorBits, err = intParam(p.Params, "accumulator_bits"); err != nil {
		return fmt.Errorf("ref22: %w", err)
	}
	// Guard the uniform security level. RSA-3072 is the 128-bit equivalence;
	// anything smaller would make this baseline faster for reasons unrelated to
	// its design.
	if p.SecurityBits >= 128 && s.accumulatorBits < 3072 {
		return fmt.Errorf(
			"ref22: accumulator_bits=%d is below the %d-bit target (RSA-3072 minimum)",
			s.accumulatorBits, p.SecurityBits)
	}

	if v, ok := p.Params["implement_insert"].(bool); ok {
		s.implementInsert = v
	}
	if s.implementInsert {
		return fmt.Errorf("ref22: implement_insert is not supported — " +
			"block insertion has no counterpart in the other schemes")
	}

	s.params = p

	// TODO: generate the double-trapdoor CH family over P-256 and the
	// trapdoorless universal accumulator. Both trapdoors must genuinely be used;
	// a single-trapdoor stand-in would change the cost profile.
	// TODO: Append blocks (Algorithm 1) with accumulator state A and witness w.
	return fmt.Errorf("ref22.Setup: %w", scheme.ErrNotImplemented)
}

// Authorize verifies regulator key possession.
//
// As with Ref[13], this scheme defines no per-request authorization protocol,
// and we do not invent one. Under load the single regulator is a real
// serialization point.
func (s *Scheme) Authorize(ctx context.Context, req *scheme.Request) (*scheme.Authorization, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	// TODO: verify the caller holds the regulator key for the target block
	// (KGenB). Must be a real check that can fail.
	return nil, fmt.Errorf("ref22.Authorize: %w", scheme.ErrNotImplemented)
}

// Redact runs Modify (Algorithm 5) per entry.
//
// Delete over a set L is measured separately by Exp 2 via DeleteSet below,
// because it is a different operation: one edit spanning many blocks, not
// amortisation across independently authorized requests. Presenting the two as
// equivalent would misstate what ZK-Redact's batching does.
func (s *Scheme) Redact(ctx context.Context, batch []*scheme.Authorization) (*scheme.RedactionResult, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	// TODO(alg5): per entry, CH.Adapt, then UA.Del the prior version and UA.Add
	// the new one, then regenerate membership and non-membership witnesses.
	// UA.Del is what resists reversion attacks — the fidelity test must confirm
	// a reverted block is actually caught.
	return nil, fmt.Errorf("ref22.Redact: %w", scheme.ErrNotImplemented)
}

// DeleteSet runs Delete (Algorithm 7) over a set of block positions.
//
// Not part of scheme.Scheme, because no other system has the operation. Exp 2
// calls it directly to obtain the consecutive/inconsecutive cost curves, which
// are compared against ZK-Redact's batch-size curve on shape, not on claimed
// equivalence.
func (s *Scheme) DeleteSet(ctx context.Context, positions []int, consecutive bool) (*scheme.RedactionResult, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	// TODO(alg7): compute H_prime for every deleted block and multiply; one
	// CH.Adapt behind each consecutive subset; append the recording block and
	// advance the largest sequence number.
	return nil, fmt.Errorf("ref22.DeleteSet: %w", scheme.ErrNotImplemented)
}

// Audit runs ValChain (Algorithm 9): collect the current version of every block
// and compare against the latest accumulator state.
//
// This is inherently a full scan, and that is the point — it is the linear
// baseline for Exp 3. BlocksTraversed must equal the ledger length. Caching it
// away would understate the baseline's cost and flatter ZK-Redact.
func (s *Scheme) Audit(ctx context.Context, q *scheme.AuditQuery) (*scheme.AuditResult, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	// TODO(alg9): traverse all blocks, compare against accumulator state.
	// Result must carry Semantics = SemanticsFullScan.
	return nil, fmt.Errorf("ref22.Audit: %w", scheme.ErrNotImplemented)
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
		return fmt.Errorf("ref22: Setup has not completed")
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
