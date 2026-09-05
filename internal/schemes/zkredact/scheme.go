// Package zkredact implements the ZK-Redact scheme.
//
// Spec: Reference/ZK-Redact Scheme/ZK-Redact.md
//
// Phase mapping onto the scheme.Scheme interface:
//
//	Phase 1 System Setup                     -> Setup
//	Phase 2 Request and ZK Authorization     -> Authorize
//	Phase 3 Sharded Batch ZKP Verification   -> Authorize (the measured path)
//	Phase 4 Batch-Verified Redaction         -> Redact
//	Phase 5 Authenticated Provenance         -> Redact (record generation)
//	Phase 6 Provenance Retrieval and Audit   -> Audit
package zkredact

import (
	"context"
	"fmt"
	"sync"

	"zkredact/pkg/ch"
	"zkredact/pkg/scheme"
)

// Scheme is the ZK-Redact system under test.
type Scheme struct {
	mu sync.RWMutex

	params  scheme.SetupParams
	ready   bool

	// shardCount is N from config. Authorize distributes proofs across this many
	// logical shards for parallel verification (Phase 3 Step 1).
	shardCount int

	// proofBatchSize and proofBatchWait are B and Delta (Phase 3 Step 2).
	proofBatchSize int
	proofBatchWait int

	// nativeBatchVerify selects whether the ZKP backend's batch verifier is
	// used. Both settings are measured: Phase 3 claims sharding provides
	// parallelism independently of native batch verification, and one setting
	// cannot test that claim.
	nativeBatchVerify bool
}

// New returns an unconfigured ZK-Redact scheme. Setup must be called first.
func New() *Scheme { return &Scheme{} }

func (s *Scheme) Name() string { return "zkredact" }

func (s *Scheme) Capabilities() scheme.Capabilities {
	return scheme.Capabilities{
		PrivacyPreservingAuth:  true, // ZK proof reveals no requester attributes
		PolicyBound:            true, // statement binds policy and its version
		DecentralizedAuth:      true, // no single trapdoor holder
		ParallelVerification:   true, // Phase 3 proof sharding
		BatchRedaction:         true, // Phase 4 batch-oriented processing
		PerTxProvenance:        true, // Phase 5 per-transaction history chain
		LedgerIndependentAudit: true, // Phase 6 targeted retrieval
		StateFreshnessCheck:    true, // Phase 4 Step 2 Fresh_i revalidation
	}
}

// Setup implements Phase 1: system parameters, key generation, proof-shard
// initialisation, and PAI initialisation. Not timed.
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
		return fmt.Errorf("zkredact: setup requires a dataset")
	}
	if p.SecurityBits <= 0 {
		return fmt.Errorf("zkredact: setup requires a security level")
	}

	// Scheme-specific parameters arrive from config/experiment.yaml. Absent
	// values are an error rather than a default: a silent default here would be
	// exactly the hardcoded parameter the project rules forbid.
	var err error
	if s.shardCount, err = intParam(p.Params, "shard_count"); err != nil {
		return fmt.Errorf("zkredact: %w", err)
	}
	if s.proofBatchSize, err = intParam(p.Params, "proof_batch_size"); err != nil {
		return fmt.Errorf("zkredact: %w", err)
	}
	if s.proofBatchWait, err = intParam(p.Params, "proof_batch_wait_ms"); err != nil {
		return fmt.Errorf("zkredact: %w", err)
	}
	if v, ok := p.Params["native_batch_verify"].(bool); ok {
		s.nativeBatchVerify = v
	} else {
		return fmt.Errorf("zkredact: missing parameter native_batch_verify")
	}

	if s.shardCount < 1 {
		return fmt.Errorf("zkredact: shard_count must be >= 1, got %d", s.shardCount)
	}

	s.params = p

	// TODO(phase1): generate CH keys, compile/load the circuit, derive the
	// proving and verifying keys, initialise proof shards and the PAI state.
	// TODO(phase1): materialise p.Dataset into the ledger. Not timed.
	return fmt.Errorf("zkredact.Setup: %w", scheme.ErrNotImplemented)
}

// Authorize implements Phases 2 and 3: statement construction, proof
// generation, shard assignment, and verification.
//
// This is the operation Exp 1 measures. The measured boundary starts when the
// request is admitted and ends when the authorization decision is final.
func (s *Scheme) Authorize(ctx context.Context, req *scheme.Request) (*scheme.Authorization, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	// TODO(phase2): build statement x_i binding policy, state version and
	// requester credential; produce proof pi_i.
	// TODO(phase3): assign to shard via H(request) mod N; form intra-shard
	// batch; verify (native batch verifier when nativeBatchVerify is set,
	// otherwise individually).
	return nil, fmt.Errorf("zkredact.Authorize: %w", scheme.ErrNotImplemented)
}

// Redact implements Phase 4 and the record generation of Phase 5.
//
// The cost split reported in RedactionResult is the point of Exp 2: CH.Adapt is
// per-request and cannot be amortised, while chaincode, validation, commitment
// and ledger write are amortised across the batch.
func (s *Scheme) Redact(ctx context.Context, batch []*scheme.Authorization) (*scheme.RedactionResult, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	if len(batch) == 0 {
		return &scheme.RedactionResult{}, nil
	}
	// TODO(phase4): revalidate Fresh_i for each entry; exclude stale requests
	// and count them in StaleExcluded rather than retrying.
	// TODO(phase4): serialise same-target requests, run independent ones in
	// parallel.
	// TODO(phase4): CH.Adapt per request, timed into CryptoTime.
	// TODO(phase4): one chaincode round for the batch, timed into LedgerTime.
	// TODO(phase5): build provenance records and append to per-tx chains.
	return nil, fmt.Errorf("zkredact.Redact: %w", scheme.ErrNotImplemented)
}

// Audit implements Phase 6: auditor authentication, targeted retrieval, and
// independent verification against the anchored PAI state.
func (s *Scheme) Audit(ctx context.Context, q *scheme.AuditQuery) (*scheme.AuditResult, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	// TODO(phase6): verify auditor signature, freshness and AuditAuth — timed
	// into AuthorizationTime, reported separately from the audit itself.
	// TODO(phase6): retrieve the target's history and Merkle authentication
	// path; verify against the anchored state.
	// BlocksTraversed must stay flat as the ledger grows. If it does not, the
	// ledger-independence claim is false and Exp 3 must report that.
	return nil, fmt.Errorf("zkredact.Audit: %w", scheme.ErrNotImplemented)
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
		return fmt.Errorf("zkredact: Setup has not completed")
	}
	return nil
}

// intParam reads a required integer parameter. YAML decodes integers as int,
// but a value that arrived through JSON will be float64, so both are accepted.
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
