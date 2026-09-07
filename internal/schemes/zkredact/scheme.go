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
	"time"

	"zkredact/internal/gateway"
	"zkredact/internal/pai"
	"zkredact/internal/pvl"
	"zkredact/internal/redactor"
	"zkredact/pkg/ch"
	"zkredact/pkg/crypto"
	"zkredact/pkg/scheme"
	"zkredact/pkg/zk"
)

// Scheme is the ZK-Redact system under test.
type Scheme struct {
	mu sync.RWMutex

	params scheme.SetupParams
	ready  bool

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

	// --- Phase 1 material, built in Setup ---

	zkParams *zk.Params
	registry *zk.Registry

	policies    map[string]*zk.Policy
	credentials map[string]*credential

	// registryRoot is the credential registry's public root. Phase 6 needs it to
	// verify stored proofs independently, and holding it here keeps the audit
	// from reaching into the registry object the prover also uses.
	registryRoot []byte

	// --- Phases 4 to 6 ---

	// chKey holds tk_ch. The trapdoor never leaves this scheme; the ledger is
	// given the key rather than the scheme handing the trapdoor around.
	chKey *ch.PrivateKey

	// ledger is the permissioned blockchain, and the authority on transaction
	// versions. There is deliberately no second copy: a map of versions kept
	// beside it would be one more thing that could disagree with the state
	// Fresh_i is checked against.
	ledger *redactor.Ledger

	// index is the PAI; exec runs Phase 4 against both.
	index *pai.Index
	exec  *redactor.Executor

	// auditors is the registered auditor set; auditorKeys holds their signing
	// keys, because the harness plays the auditor in Phase 6 Step 1.
	auditors    *pai.AuditorRegistry
	auditorKeys map[string]*crypto.SchnorrPrivateKey

	gw  *gateway.Gateway
	pvl *pvl.PVL

	// pvlSvc is the standing verification layer Authorize submits into.
	// Verifying one proof per call would make sharding and batching no-ops:
	// there is never more than one proof in flight to distribute or group.
	pvlSvc *pvl.Service

	// queueDepth bounds each shard's queue. Sized from the highest offered
	// load, so a submitter never blocks on the channel — that wait would be
	// recorded as verification latency.
	queueDepth int

	// prepared holds requester-side material per request, built by
	// PrepareTrace. Authorize refuses a request that is absent here rather than
	// proving inline; see PrepareTrace.
	prepared map[string]*prepared

	// proofCache keys proofs by statement digest. Identical statements yield
	// identical proofs, so a replayed request reuses one rather than paying to
	// generate it again — which is what keeps the untimed preparation
	// affordable across a sweep.
	proofCache map[string]*zk.Proof

	// signatureCurve, freshnessWindow, scopeHigh and redactionLoc are shared
	// parameters from config, not choices made here.
	signatureCurve  string
	freshnessWindow time.Duration
	scopeHigh       uint64
	redactionLoc    uint64

	// blockTx is block_max_transactions, shared with every other scheme so the
	// ledgers Exp 3 sweeps are the same height for the same corpus.
	blockTx int

	// auditorCount is how many auditors Phase 1 registers.
	auditorCount int
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

		// Phase 2/3 authorize at the gateway and the verification layer. No
		// consensus is required to decide a request, and that is the design
		// claim Exp 1 exists to test — not an artefact of running in-process.
		ConsensusBoundAuth: false,
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

	// Shared parameters, passed in from the security and environment blocks
	// rather than duplicated under this scheme. A per-scheme copy could drift
	// and would let ZK-Redact run at a different level than the baselines.
	if s.signatureCurve, err = stringParam(p.Params, "signature_curve"); err != nil {
		return fmt.Errorf("zkredact: %w", err)
	}
	freshnessMS, err := intParam(p.Params, "freshness_window_ms")
	if err != nil {
		return fmt.Errorf("zkredact: %w", err)
	}
	if freshnessMS <= 0 {
		return fmt.Errorf("zkredact: freshness_window_ms must be positive, got %d", freshnessMS)
	}
	s.freshnessWindow = time.Duration(freshnessMS) * time.Millisecond

	// The redactable payload bounds the policy scope, and the redaction
	// location must lie inside it. Both come from the dataset's configured
	// payload size; a constant here would reject valid locations on a
	// differently sized corpus.
	payload, err := intParam(p.Params, "redactable_payload_bytes")
	if err != nil {
		return fmt.Errorf("zkredact: %w", err)
	}
	if payload <= 0 {
		return fmt.Errorf("zkredact: redactable_payload_bytes must be positive, got %d", payload)
	}
	s.scopeHigh = uint64(payload)
	// Redactions target the start of the redactable region. The location is
	// bound into the statement and range-checked in-circuit; the workload does
	// not vary it, so varying it here would invent a dimension the corpus does
	// not have.
	s.redactionLoc = 0

	// Each shard's queue must hold the whole offered load, or a submitter
	// blocks on the channel and that wait is recorded as verification latency.
	// Exp 1's highest concurrency level is the bound.
	depth, err := intParam(p.Params, "max_concurrency")
	if err != nil {
		return fmt.Errorf("zkredact: %w", err)
	}
	if depth < 1 {
		return fmt.Errorf("zkredact: max_concurrency must be >= 1, got %d", depth)
	}
	s.queueDepth = depth

	// SHARED with every other scheme, from the environment and security blocks.
	// A per-scheme copy could drift and would let ZK-Redact's ledger be a
	// different height, or its hash a different function, than the baselines'.
	if s.blockTx, err = intParam(p.Params, "block_max_transactions"); err != nil {
		return fmt.Errorf("zkredact: %w", err)
	}
	hashName, err := stringParam(p.Params, "hash")
	if err != nil {
		return fmt.Errorf("zkredact: %w", err)
	}
	if err := crypto.RequireHash(hashName); err != nil {
		return fmt.Errorf("zkredact: %w", err)
	}

	if s.auditorCount, err = intParam(p.Params, "auditor_count"); err != nil {
		return fmt.Errorf("zkredact: %w", err)
	}

	// Setup can be re-run — Exp 3 rebuilds the ledger at every swept size — and
	// the previous PVL's shard workers are goroutines. Without this they
	// accumulate one full shard set per rebuild, still holding queues and
	// verification keys.
	if s.pvlSvc != nil {
		s.pvlSvc.Stop()
		s.pvlSvc = nil
	}

	s.proofCache = make(map[string]*zk.Proof)
	s.params = p

	if err := s.buildAuthorization(p); err != nil {
		return err
	}

	s.ready = true
	return nil
}

// stringParam reads a required string parameter.
func stringParam(params map[string]any, key string) (string, error) {
	v, ok := params[key]
	if !ok {
		return "", fmt.Errorf("missing parameter %s", key)
	}
	sv, ok := v.(string)
	if !ok || sv == "" {
		return "", fmt.Errorf("parameter %s must be a non-empty string", key)
	}
	return sv, nil
}

// Teardown releases the PVL's shard workers.
//
// Not merely bookkeeping: each shard is a goroutine holding a queue and a
// reference to the verification key, and Exp 3 tears a scheme down and sets it
// up again at every ledger size.
func (s *Scheme) Teardown(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pvlSvc != nil {
		s.pvlSvc.Stop()
		s.pvlSvc = nil
	}
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
