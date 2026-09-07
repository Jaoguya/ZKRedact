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
	"crypto/elliptic"
	"fmt"
	"sync"

	"zkredact/pkg/ch"
	"zkredact/pkg/scheme"
)

// Scheme is the Shen et al. baseline.
type Scheme struct {
	mu    sync.RWMutex
	ready bool

	params scheme.SetupParams

	curve        elliptic.Curve
	chCurve      string
	ledger       *ledger
	regulatorKey *ch.DoubleTrapdoorKey

	// blockOf maps a source transaction onto its block. Ref[22] operates at
	// block granularity, so one transaction is one block.
	blockOf map[string]uint64

	// versions counts modifications per block, for the freshness check Redact
	// makes against the largest-sequence-number rule.
	versions map[uint64]uint64

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
		PerTxProvenance:        false,
		LedgerIndependentAudit: false, // ValChain traverses the whole chain
		StateFreshnessCheck:    false,
		ConsensusBoundAuth:     false, // regulator key possession is local
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

	// The chameleon-hash curve is a SHARED parameter, passed in from the
	// security block rather than duplicated here: a per-baseline copy could
	// drift and let one system run at a different level than the others.
	if s.chCurve, err = stringParam(p.Params, "ch_curve"); err != nil {
		return fmt.Errorf("ref22: %w", err)
	}

	s.params = p
	s.versions = make(map[uint64]uint64)

	if err := s.build(p); err != nil {
		return err
	}

	s.ready = true
	return nil
}

// stringParam reads a required string parameter.
func stringParam(m map[string]any, key string) (string, error) {
	v, ok := m[key]
	if !ok {
		return "", fmt.Errorf("missing parameter %s", key)
	}
	sv, ok := v.(string)
	if !ok || sv == "" {
		return "", fmt.Errorf("parameter %s must be a non-empty string", key)
	}
	return sv, nil
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
