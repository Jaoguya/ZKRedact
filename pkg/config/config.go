// Package config loads config/experiment.yaml.
//
// One schema definition, used by both the validator and the experiment runner.
// Two copies would drift, and a drifted schema silently ignores a field — which
// means a parameter the researcher set is not the parameter the run used.
//
// Pointer types are deliberate throughout: they distinguish "absent or null"
// from a valid zero. A shard count of 0 and a missing shard count are different
// bugs and must not collapse into one.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config mirrors config/experiment.yaml.
type Config struct {
	Meta        Meta        `yaml:"meta"`
	Security    Security    `yaml:"security"`
	Environment Environment `yaml:"environment"`
	Dataset     Dataset     `yaml:"dataset"`
	Workload    Workload    `yaml:"workload"`
	ZKRedact    ZKRedact    `yaml:"zkredact"`
	Baselines   Baselines   `yaml:"baselines"`
	Experiments Experiments `yaml:"experiments"`
	Output      Output      `yaml:"output"`
}

type Meta struct {
	ConfigVersion string `yaml:"config_version"`
	Seed          *int64 `yaml:"seed"`
	Repetitions   *int   `yaml:"repetitions"`
}

type Security struct {
	TargetBits         *int    `yaml:"target_bits"`
	Hash               string  `yaml:"hash"`
	SignatureCurve     *string `yaml:"signature_curve"`
	PairingCurve       *string `yaml:"pairing_curve"`
	ChameleonHashCurve *string `yaml:"chameleon_hash_curve"`
	AccumulatorBits    *int    `yaml:"accumulator_bits"`
	ZKProofSystem      *string `yaml:"zk_proof_system"`
}

type Environment struct {
	InstanceType      string  `yaml:"instance_type"`
	VCPUs             *int    `yaml:"vcpus"`
	MemoryGB          *int    `yaml:"memory_gb"`
	PeerCPULimit      *string `yaml:"peer_cpu_limit"`
	PeerMemoryLimit   *string `yaml:"peer_memory_limit"`
	Network           Network `yaml:"network"`
	RecordFingerprint bool    `yaml:"record_fingerprint"`
}

type Network struct {
	Organizations        *int   `yaml:"organizations"`
	PeersPerOrg          *int   `yaml:"peers_per_org"`
	OrdererNodes         *int   `yaml:"orderer_nodes"`
	Consensus            string `yaml:"consensus"`
	BlockMaxTransactions *int   `yaml:"block_max_transactions"`
	BlockTimeoutMS       *int   `yaml:"block_timeout_ms"`
}

type Dataset struct {
	BaseTransactions *int              `yaml:"base_transactions"`
	Transaction      TransactionSizes  `yaml:"transaction"`
	Identities       IdentitiesConfig  `yaml:"identities"`
	Policies         PoliciesConfig    `yaml:"policies"`
}

type TransactionSizes struct {
	CorePayloadBytes       *int `yaml:"core_payload_bytes"`
	RedactablePayloadBytes *int `yaml:"redactable_payload_bytes"`
}

type IdentitiesConfig struct {
	Count      *int     `yaml:"count"`
	Attributes []string `yaml:"attributes"`
}

type PoliciesConfig struct {
	Count          *int `yaml:"count"`
	PredicateDepth *int `yaml:"predicate_depth"`
}

type Workload struct {
	TotalRequests      *int      `yaml:"total_requests"`
	TargetDistribution string    `yaml:"target_distribution"`
	ZipfS              *float64  `yaml:"zipf_s"`
	ConflictRatios     []float64 `yaml:"conflict_ratios"`
	Arrival            string    `yaml:"arrival"`
}

type ZKRedact struct {
	Sharding       Sharding       `yaml:"sharding"`
	ProofBatch     ProofBatch     `yaml:"proof_batch"`
	RedactionBatch RedactionBatch `yaml:"redaction_batch"`
	Circuit        Circuit        `yaml:"circuit"`
}

type Sharding struct {
	Counts []int `yaml:"counts"`
}

type ProofBatch struct {
	Sizes             []int  `yaml:"sizes"`
	WaitBoundMS       []int  `yaml:"wait_bound_ms"`
	NativeBatchVerify []bool `yaml:"native_batch_verify"`
}

type RedactionBatch struct {
	Sizes        []int `yaml:"sizes"`
	WaitBoundsMS []int `yaml:"wait_bounds_ms"`
}

type Circuit struct {
	ConstraintCount  *int `yaml:"constraint_count"`
	PublicInputCount *int `yaml:"public_input_count"`
}

type Baselines struct {
	Ref10 Ref10 `yaml:"ref10_emt"`
	Ref13 Ref13 `yaml:"ref13_vrbc"`
	Ref22 Ref22 `yaml:"ref22_shen"`
}

type Ref10 struct {
	Enabled         bool    `yaml:"enabled"`
	CommitteeSize   *int    `yaml:"committee_size"`
	VoteThreshold   *int    `yaml:"vote_threshold"`
	FaultToleranceF *int    `yaml:"fault_tolerance_f"`
	VoteWindowMS    *int    `yaml:"vote_window_ms"`
	AttributePolicy *string `yaml:"attribute_policy"`
	VoteTransport   *string `yaml:"vote_transport"`
}

type Ref13 struct {
	Enabled                bool      `yaml:"enabled"`
	ArityQ                 []int     `yaml:"arity_q"`
	VectorDimensionFormula *string   `yaml:"vector_dimension_formula"`
	ChallengedBlocks       []int     `yaml:"challenged_blocks"`
	CorruptedBlockRate     *float64  `yaml:"corrupted_block_rate"`
	DetectionPrecision     []float64 `yaml:"detection_precision"`
	OptimizedAuditing      *bool     `yaml:"optimized_auditing"`
	DelayedRedaction       *bool     `yaml:"delayed_redaction"`
}

type Ref22 struct {
	Enabled             bool     `yaml:"enabled"`
	AccumulatorBits     *int     `yaml:"accumulator_bits"`
	DeleteSetSizes      []int    `yaml:"delete_set_sizes"`
	DeleteSetStructures []string `yaml:"delete_set_structures"`
	ImplementInsert     *bool    `yaml:"implement_insert"`
}

type Experiments struct {
	VerificationThroughput ExpVerification `yaml:"verification_throughput"`
	RedactionThroughput    ExpRedaction    `yaml:"redaction_throughput"`
	ProvenanceAudit        ExpAudit        `yaml:"provenance_audit"`
}

type ExpVerification struct {
	Enabled           bool       `yaml:"enabled"`
	ConcurrencyLevels []int      `yaml:"concurrency_levels"`
	Systems           []string   `yaml:"systems"`
	Metrics           []string   `yaml:"metrics"`
	Ablations         []Ablation `yaml:"ablations"`
}

type Ablation struct {
	Sharding bool `yaml:"sharding"`
	Batching bool `yaml:"batching"`
}

type ExpRedaction struct {
	Enabled              bool     `yaml:"enabled"`
	Systems              []string `yaml:"systems"`
	DecomposeCost        *bool    `yaml:"decompose_cost"`
	Metrics              []string `yaml:"metrics"`
	FindOptimalBatchSize *bool    `yaml:"find_optimal_batch_size"`
}

type ExpAudit struct {
	Enabled                  bool     `yaml:"enabled"`
	Systems                  []string `yaml:"systems"`
	LedgerSizes              []int    `yaml:"ledger_sizes"`
	HistoryDepths            []int    `yaml:"history_depths"`
	Metrics                  []string `yaml:"metrics"`
	ReportAuthCostSeparately *bool    `yaml:"report_auth_cost_separately"`
}

type Output struct {
	ResultsDir            string       `yaml:"results_dir"`
	PlotsDir              string       `yaml:"plots_dir"`
	Formats               []string     `yaml:"formats"`
	Record                RecordConfig `yaml:"record"`
	AllowPublishedNumbers *bool        `yaml:"allow_published_numbers_in_tables"`
}

type RecordConfig struct {
	ResolvedConfig         *bool `yaml:"resolved_config"`
	Seed                   *bool `yaml:"seed"`
	DatasetID              *bool `yaml:"dataset_id"`
	GitCommit              *bool `yaml:"git_commit"`
	EnvironmentFingerprint *bool `yaml:"environment_fingerprint"`
	Timestamp              *bool `yaml:"timestamp"`
}

// -----------------------------------------------------------------------------
// Loading
// -----------------------------------------------------------------------------

// DefaultPath is the config location assumed by the Makefile targets.
const DefaultPath = "config/experiment.yaml"

// Load reads and parses a config file.
//
// Unknown fields are tolerated: the file carries extensive rationale comments
// and documentation-only keys, and rejecting those would couple the schema to
// the prose.
func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultPath
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return &c, nil
}

// -----------------------------------------------------------------------------
// Accessors
//
// Each returns an error rather than a zero value when a parameter is missing. A
// silent default here would be exactly the hardcoded parameter the project
// rules forbid — and would be invisible in the results.
// -----------------------------------------------------------------------------

func (c *Config) Seed() (int64, error) {
	if c.Meta.Seed == nil {
		return 0, fmt.Errorf("meta.seed is not set; runs would not be reproducible")
	}
	return *c.Meta.Seed, nil
}

func (c *Config) Repetitions() (int, error) {
	if c.Meta.Repetitions == nil {
		return 0, fmt.Errorf("meta.repetitions is not set")
	}
	return *c.Meta.Repetitions, nil
}

func (c *Config) TargetBits() (int, error) {
	if c.Security.TargetBits == nil {
		return 0, fmt.Errorf("security.target_bits is not set")
	}
	return *c.Security.TargetBits, nil
}

// -----------------------------------------------------------------------------
// Bridges to runtime types
// -----------------------------------------------------------------------------

// WorkloadParams is the subset of config needed to generate the shared dataset
// and request trace.
//
// Returned as a plain struct rather than pkg/workload.Config so that pkg/config
// does not import pkg/workload; the runner converts. Keeping the dependency in
// one direction avoids a cycle once workload generation needs config-derived
// helpers of its own.
type WorkloadParams struct {
	Seed                   int64
	BaseTransactions       int
	CorePayloadBytes       int
	RedactablePayloadBytes int
	IdentityCount          int
	IdentityAttributes     []string
	PolicyCount            int
	PredicateDepth         int
	TotalRequests          int
	TargetDistribution     string
	ZipfS                  float64
	ConflictRatio          float64
}

// WorkloadParams assembles generation parameters for one conflict ratio.
//
// The ratio is a parameter rather than a field of the config struct because
// Exp 2 sweeps it: each value is a distinct measurement point, and each needs
// its own trace.
func (c *Config) WorkloadParams(conflictRatio float64) (WorkloadParams, error) {
	var w WorkloadParams

	seed, err := c.Seed()
	if err != nil {
		return w, err
	}

	missing := func(field string) error {
		return fmt.Errorf("%s is not set", field)
	}
	switch {
	case c.Dataset.BaseTransactions == nil:
		return w, missing("dataset.base_transactions")
	case c.Dataset.Transaction.CorePayloadBytes == nil:
		return w, missing("dataset.transaction.core_payload_bytes")
	case c.Dataset.Transaction.RedactablePayloadBytes == nil:
		return w, missing("dataset.transaction.redactable_payload_bytes")
	case c.Dataset.Identities.Count == nil:
		return w, missing("dataset.identities.count")
	case c.Dataset.Policies.Count == nil:
		return w, missing("dataset.policies.count")
	case c.Dataset.Policies.PredicateDepth == nil:
		return w, missing("dataset.policies.predicate_depth")
	case c.Workload.TotalRequests == nil:
		return w, missing("workload.total_requests")
	}

	zipfS := 0.0
	if c.Workload.ZipfS != nil {
		zipfS = *c.Workload.ZipfS
	}

	return WorkloadParams{
		Seed:                   seed,
		BaseTransactions:       *c.Dataset.BaseTransactions,
		CorePayloadBytes:       *c.Dataset.Transaction.CorePayloadBytes,
		RedactablePayloadBytes: *c.Dataset.Transaction.RedactablePayloadBytes,
		IdentityCount:          *c.Dataset.Identities.Count,
		IdentityAttributes:     c.Dataset.Identities.Attributes,
		PolicyCount:            *c.Dataset.Policies.Count,
		PredicateDepth:         *c.Dataset.Policies.PredicateDepth,
		TotalRequests:          *c.Workload.TotalRequests,
		TargetDistribution:     c.Workload.TargetDistribution,
		ZipfS:                  zipfS,
		ConflictRatio:          conflictRatio,
	}, nil
}

// SchemeParams returns the static setup parameters for one scheme, keyed as the
// scheme's Setup expects.
//
// Swept parameters — shard count, batch size, BAT arity — are NOT included.
// Those vary per measurement point and are merged in by the experiment runner,
// so that a scheme cannot accidentally read a sweep's first element and hold it
// for the whole run.
func (c *Config) SchemeParams(name string) (map[string]any, error) {
	switch name {
	case "zkredact":
		return map[string]any{}, nil

	case "ref10_emt":
		b := c.Baselines.Ref10
		if b.CommitteeSize == nil || b.VoteThreshold == nil ||
			b.VoteWindowMS == nil || b.AttributePolicy == nil ||
			b.VoteTransport == nil {
			return nil, fmt.Errorf("baselines.ref10_emt is incompletely configured")
		}
		// signature_curve, hash and block_max_transactions are SHARED
		// parameters, passed in from the security and environment blocks rather
		// than duplicated under this baseline. A per-baseline copy could drift
		// and would let one system run at a different level or block cadence
		// than the others.
		if c.Security.SignatureCurve == nil {
			return nil, fmt.Errorf("security.signature_curve is not set, required by ref10_emt")
		}
		if c.Environment.Network.BlockMaxTransactions == nil {
			return nil, fmt.Errorf("environment.network.block_max_transactions is not set, required by ref10_emt")
		}
		return map[string]any{
			"committee_size":         *b.CommitteeSize,
			"vote_threshold":         *b.VoteThreshold,
			"vote_window_ms":         *b.VoteWindowMS,
			"attribute_policy":       *b.AttributePolicy,
			"vote_transport":         *b.VoteTransport,
			"signature_curve":        *c.Security.SignatureCurve,
			"hash":                   c.Security.Hash,
			"block_max_transactions": *c.Environment.Network.BlockMaxTransactions,
		}, nil

	case "ref13_vrbc":
		b := c.Baselines.Ref13
		if b.CorruptedBlockRate == nil || b.OptimizedAuditing == nil {
			return nil, fmt.Errorf("baselines.ref13_vrbc is incompletely configured")
		}
		if len(b.ChallengedBlocks) == 0 {
			return nil, fmt.Errorf("baselines.ref13_vrbc.challenged_blocks is empty")
		}
		return map[string]any{
			// arity_q is swept; the runner injects the value for each point.
			"challenged_blocks":    b.ChallengedBlocks[0],
			"corrupted_block_rate": *b.CorruptedBlockRate,
			"optimized_auditing":   *b.OptimizedAuditing,
		}, nil

	case "ref22_shen":
		b := c.Baselines.Ref22
		if b.AccumulatorBits == nil {
			return nil, fmt.Errorf("baselines.ref22_shen.accumulator_bits is not set")
		}
		implementInsert := false
		if b.ImplementInsert != nil {
			implementInsert = *b.ImplementInsert
		}
		return map[string]any{
			"accumulator_bits": *b.AccumulatorBits,
			"implement_insert": implementInsert,
		}, nil

	default:
		return nil, fmt.Errorf("unknown scheme %q", name)
	}
}

// EnabledSchemes lists the baselines switched on, plus ZK-Redact.
func (c *Config) EnabledSchemes() []string {
	out := []string{"zkredact"}
	if c.Baselines.Ref10.Enabled {
		out = append(out, "ref10_emt")
	}
	if c.Baselines.Ref13.Enabled {
		out = append(out, "ref13_vrbc")
	}
	if c.Baselines.Ref22.Enabled {
		out = append(out, "ref22_shen")
	}
	return out
}
