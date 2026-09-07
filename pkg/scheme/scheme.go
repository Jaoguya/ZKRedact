// Package scheme defines the contract every system under test implements —
// ZK-Redact and all three re-implemented baselines.
//
// This interface is the fairness mechanism. The experiment harness talks only
// to Scheme, so no system can be driven through a code path the others do not
// share, timed at a boundary the others do not use, or handed a workload the
// others did not receive. docs/experiments.md states that contract in prose;
// this file is where it is actually enforced.
//
// Three design decisions are load-bearing:
//
//   - Redact takes a SLICE. ZK-Redact batches; the baselines do not. Rather
//     than giving ZK-Redact a wider interface, every scheme accepts a batch and
//     the baselines simply process it one request at a time. B_R=1 then falls
//     out as the natural point where all four meet, exactly as Exp 2 requires.
//
//   - RedactionResult separates crypto time from ledger time. CH adaptation is
//     per-request and cannot be amortised; only blockchain-side work can. A
//     single aggregate duration would make it impossible to say which improved,
//     and would let the paper imply batching accelerates redaction cryptography.
//     It does not (ZK-Redact.md:645-647).
//
//   - Capabilities is reported by the implementation, not written by hand. The
//     capability matrix in the paper is generated from what the code actually
//     provides, so it cannot drift away from reality.
package scheme

import (
	"context"
	"errors"
	"time"
)

// ErrNotImplemented is returned by a scheme operation that has not been built
// yet. The harness treats it as fatal rather than skipping the scheme: a
// comparison silently missing one system is worse than no comparison.
var ErrNotImplemented = errors.New("not implemented")

// ErrStale reports that a request failed freshness revalidation and must be
// re-authorized. It is an expected outcome under batching, not a failure of the
// scheme — Exp 2 measures how often it happens.
var ErrStale = errors.New("request stale: state version changed since authorization")

// -----------------------------------------------------------------------------
// Scheme
// -----------------------------------------------------------------------------

// Scheme is one system under test.
//
// Implementations must be safe for concurrent use by multiple goroutines:
// Exp 1 drives Authorize at concurrency levels up to 1024.
type Scheme interface {
	// Name identifies the scheme in results and plots, e.g. "zkredact",
	// "ref10_emt". Must match the key used in config/experiment.yaml.
	Name() string

	// Capabilities reports what this scheme actually provides. Used to generate
	// the capability matrix, which carries the interpretation of Exp 1 where two
	// baselines are fast because they do less work.
	Capabilities() Capabilities

	// Setup materialises the shared source dataset into this scheme's own
	// on-chain representation and prepares keys and network state.
	//
	// NOT TIMED. The four schemes cannot share a ledger format, so each ingests
	// identical source data into its own structure before measurement begins.
	Setup(ctx context.Context, p SetupParams) error

	// Authorize decides whether one redaction request is permitted.
	//
	// This is the operation Exp 1 measures. Its cost differs enormously across
	// schemes — a ZK proof verification, a committee vote, or a key-possession
	// check — which is the finding, not a flaw in the comparison.
	//
	// The returned Authorization is the input to Redact.
	Authorize(ctx context.Context, req *Request) (*Authorization, error)

	// Redact executes already-authorized redactions and commits them.
	//
	// The batch may hold one element (every baseline, and ZK-Redact at B_R=1) or
	// many (ZK-Redact above that). Implementations that do not batch must still
	// accept a slice and process it sequentially — that is precisely what makes
	// them the B_R=1 reference point.
	//
	// Requests whose state version moved since authorization must be excluded
	// and counted in RedactionResult.StaleExcluded, not silently retried.
	Redact(ctx context.Context, batch []*Authorization) (*RedactionResult, error)

	// Audit retrieves and verifies the redaction history of one transaction.
	//
	// Schemes without per-transaction provenance answer the nearest question
	// their design supports, and say so in AuditResult.Semantics. Exp 3 compares
	// cost scaling against ledger size, which all four can answer; it does not
	// claim feature equivalence, which they cannot.
	Audit(ctx context.Context, q *AuditQuery) (*AuditResult, error)

	// Teardown releases network and process resources.
	Teardown(ctx context.Context) error
}

// -----------------------------------------------------------------------------
// Capabilities
// -----------------------------------------------------------------------------

// Capabilities describes what a scheme provides, independent of how fast it is.
//
// Exp 1 will show two baselines outperforming ZK-Redact at low load because a
// key-possession check is cheaper than a proof verification. Published without
// this context, that table would misrepresent every scheme in it.
type Capabilities struct {
	// PrivacyPreservingAuth: authorization without revealing requester identity
	// or attributes.
	PrivacyPreservingAuth bool

	// PolicyBound: redaction rights evaluated against a policy, not merely key
	// possession.
	PolicyBound bool

	// DecentralizedAuth: no single entity can authorize unilaterally.
	DecentralizedAuth bool

	// ParallelVerification: authorization scales across workers rather than
	// serialising through one point.
	ParallelVerification bool

	// BatchRedaction: blockchain-side cost amortised across multiple
	// independently authorized requests.
	BatchRedaction bool

	// PerTxProvenance: retrievable redaction history for a single transaction.
	PerTxProvenance bool

	// LedgerIndependentAudit: audit cost scales with the target's history, not
	// with total ledger size.
	LedgerIndependentAudit bool

	// StateFreshnessCheck: revalidation that the authorized state still holds at
	// execution time.
	StateFreshnessCheck bool

	// ConsensusBoundAuth: authorization requires agreement among nodes, so it
	// cannot complete without the ledger.
	//
	// EXP 1'S LATENCY COLUMN IS UNREADABLE WITHOUT THIS. Only Ref[10] declares
	// it: its Algorithm 3 vote genuinely needs consensus, while ZK-Redact's
	// Phase 2/3, Ref[13]'s trapdoor check and Ref[22]'s key check complete
	// in-process by design. A reader comparing 2 s against 1.34 ms is otherwise
	// comparing a networked protocol with a function call and has nothing in
	// the results telling them so — and the difference is the finding, not an
	// implementation gap.
	//
	// A scheme declaring this is expected to record non-zero ConsensusBlocks
	// and RoundTrips in AuthCost.
	ConsensusBoundAuth bool
}

// AuthCost is the STRUCTURAL cost of one authorization: what the scheme did,
// counted, rather than how long it took.
//
// WHY THIS EXISTS. Wall-clock latency for Ref[10] is dominated by block
// cadence, a network parameter, and every figure it produces is therefore only
// meaningful beside the block time that produced it. Counting the blocks, round
// trips and signature verifications instead gives a reader something they can
// re-derive under their own configuration, and makes the asymmetry visible
// rather than buried inside a duration: three of the four systems report zero
// blocks and zero round trips because they genuinely touch no network.
//
// It advantages no scheme. Each reports what its own design performs.
type AuthCost struct {
	// ConsensusBlocks is how many ledger blocks one authorization waits for.
	ConsensusBlocks int `json:"consensus_blocks"`

	// RoundTrips is how many times one authorization crosses the network.
	RoundTrips int `json:"round_trips"`

	// SignatureVerifications counts the public-key verifications performed.
	// Non-zero for every scheme; it is the part of the work that does not
	// depend on the network at all.
	SignatureVerifications int `json:"signature_verifications"`
}

// AuthCostReporter is an OPTIONAL interface for a scheme that can report the
// structural cost of one authorization.
//
// Optional rather than part of Scheme because a scheme that cannot count these
// honestly must not guess: a fabricated zero would read as "touches no network"
// and that is exactly the claim the counters exist to substantiate.
type AuthCostReporter interface {
	// AuthCost reports the structural cost of a single authorization under the
	// scheme's CURRENT configuration. It must not be a stored constant if the
	// configuration can change it — Ref[10]'s transport changes it.
	AuthCost() AuthCost
}

// -----------------------------------------------------------------------------
// Setup
// -----------------------------------------------------------------------------

// Retransporter is an OPTIONAL interface for a scheme whose authorization can
// travel by more than one transport.
//
// WHY EXP 1 SWEEPS THIS RATHER THAN RUNNING TWICE. Only Ref[10] implements it,
// and its two transports answer different questions: in_process is the
// like-for-like control against the three schemes that authorize locally by
// design, while fabric is the deployed cost. Publishing either alone
// misrepresents the comparison — the first understates Ref[10], the second
// compares a networked protocol against three function calls.
//
// They must be arms of ONE run, not two. cmd/plot keeps only the newest results
// document per experiment, deliberately, so that runs under different configs
// are never pooled — two separate runs would mean the second silently replaced
// the first.
type Retransporter interface {
	// Retransport switches the authorization transport. It must rebuild
	// whatever the transport owns rather than mutating a field a running
	// component already snapshotted.
	Retransport(name string) error

	// Transport reports the transport currently in use, for the results row.
	Transport() string
}

// Resharder is an OPTIONAL interface for a scheme with logical proof shards.
//
// Exp 1 sweeps the shard count, and re-running Setup to do it would recompile
// the circuit and redo the trusted setup at every point — work that has nothing
// to do with sharding and would dominate the measurement. The circuit does not
// depend on N: sharding is runtime dispatch.
//
// A scheme without shards does not implement it and is swept only over
// concurrency, because fabricating a shard-count curve for a system that has no
// shards is the same error exp2 refuses for batch sizes.
type Resharder interface {
	Reshard(shardCount int) error
}

// BatchVerifierTuner is an OPTIONAL interface for a scheme whose proof
// verification can run per-record or as a batch.
//
// Exp 1's ablation grid needs both arms measured: the manuscript's Phase 3
// claims sharding gives parallelism INDEPENDENTLY of native batch-verification
// support, and one setting cannot test that. A scheme without two distinct
// paths does not implement this and is measured once.
//
// The arms must do genuinely different work. Two settings that reach the same
// code produce two sets of numbers that are the same measurement twice — and a
// plot would present them as a comparison.
type BatchVerifierTuner interface {
	SetNativeBatchVerify(native bool) error
}

// Rebatcher is an OPTIONAL interface for a scheme with an intra-shard batch
// size, B in Phase 3 Step 2.
//
// It exists for the same reason as Resharder: B is runtime dispatch, so
// re-running Setup to sweep it would recompile the circuit at every point.
//
// WITHOUT IT THE BATCHING ABLATION CANNOT RUN. A batch of one is the
// batching-DISABLED arm — a single proof never reaches an aggregated pairing
// check, so native_batch_verify true and false take the identical path and the
// grid reports one measurement twice under two labels. Sweeping the verifier
// mode is not enough on its own; B has to move with it.
type Rebatcher interface {
	Rebatch(batchSize int) error
}

// TracePreparer is an OPTIONAL interface for per-replay work that is not part
// of what an experiment measures.
//
// WHY IT EXISTS. Exp 1 times Authorize, and for ZK-Redact that must mean
// verifying a proof, not producing one. Proof generation is the REQUESTER's
// work — docs/experiments.md §2.2 lists ZK-Redact's authorization work as
// "verify ZK proof, shard assignment, intra-shard batching" — and Groth16
// proving costs roughly an order of magnitude more than verification. Folding
// it into the measured path would not fail any test; it would simply report
// ZK-Redact as an order of magnitude slower than it is and invert the Exp 1
// comparison.
//
// The same hook resets any per-replay state, which is the in-memory analogue of
// bringing a baseline's ledger up fresh between replays.
//
// A scheme that does not implement it is driven exactly as before, so the
// baselines are unaffected. A scheme that DOES implement it must fail Authorize
// loudly for an unprepared request rather than silently doing the work inline —
// a lazy fallback would put the excluded cost straight back into the
// measurement with nothing to show it had happened.
type TracePreparer interface {
	// PrepareTrace is called before each timed replay, and is NOT timed.
	PrepareTrace(ctx context.Context, trace []*Request) error
}

// SetupParams carries the shared substrate. Every scheme receives the identical
// value in a given run.
type SetupParams struct {
	// Dataset is the source corpus, identical across schemes.
	Dataset *Dataset

	// Seed drives every randomised protocol choice. Recorded into results so a
	// run can be reproduced exactly.
	Seed int64

	// SecurityBits is the uniform target level. Implementations MUST fail setup
	// rather than silently using weaker parameters — a scheme running below the
	// common level would appear faster for reasons that have nothing to do with
	// its design.
	SecurityBits int

	// Params holds scheme-specific configuration from config/experiment.yaml,
	// e.g. committee size for Ref[10] or BAT arity for Ref[13].
	Params map[string]any
}

// Dataset is the generated source corpus. See pkg/workload.
type Dataset struct {
	ID           string // content hash; recorded in results
	Transactions []Transaction
	Identities   []Identity
	Policies     []Policy
}

// Transaction is one source record. The split between core and redactable
// payload is what makes the corpus usable by every scheme: Ref[10]'s EMT needs
// the two branches, and redaction targets only the second.
type Transaction struct {
	ID         string
	Core       []byte // immutable
	Redactable []byte // redaction target
}

// Identity is a registered requester.
type Identity struct {
	ID         string
	Attributes map[string]string
}

// Policy governs which identities may redact which transactions.
type Policy struct {
	ID        string
	Version   uint64
	Predicate string
}

// -----------------------------------------------------------------------------
// Authorization — Exp 1
// -----------------------------------------------------------------------------

// Request is one redaction request, drawn from the shared trace.
type Request struct {
	ID          string
	RequesterID string
	TargetTxID  string
	NewContent  []byte
	PolicyID    string
	Timestamp   time.Time
	Nonce       []byte
}

// Authorization is the outcome of Authorize and the input to Redact.
type Authorization struct {
	Request *Request

	// Granted reports the decision. A denial is a valid, measurable outcome —
	// schemes must not treat rejection as an error.
	Granted bool

	// Reason explains a denial, for debugging and for confirming that authorization
	// logic is genuinely running rather than always approving.
	Reason string

	// Evidence is scheme-specific proof of authorization: a ZK proof, an
	// aggregate signature, a key-possession token. Retained for Exp 3, where
	// ZK-Redact binds it into the provenance record.
	Evidence []byte

	// TxVersion and PolicyVersion are captured at authorization time. Redact
	// compares them against current values to detect staleness.
	TxVersion     uint64
	PolicyVersion uint64

	// AuthorizedAt supports staleness analysis: the gap between this and
	// execution is what makes larger batches fail freshness more often.
	AuthorizedAt time.Time
}

// -----------------------------------------------------------------------------
// Redaction — Exp 2
// -----------------------------------------------------------------------------

// RedactionResult reports the outcome of one Redact call, with cost split into
// the part batching can amortise and the part it cannot.
type RedactionResult struct {
	Succeeded int

	// StaleExcluded counts requests that failed freshness revalidation. This is
	// the honest cost of batching: longer waits amortise better but strand more
	// requests. Exp 2 plots it against the amortisation gain to locate the
	// optimal batch size.
	StaleExcluded int

	// Failed counts requests that failed for reasons other than staleness.
	Failed int

	// CryptoTime is per-request cryptographic work — chameleon hash adaptation
	// and anything else that must run once per redaction. Grows linearly with
	// batch size. This is the floor batching cannot go below.
	CryptoTime time.Duration

	// LedgerTime is blockchain-side work: chaincode invocation, validation,
	// commitment, consensus, ledger write. Roughly constant per batch, and
	// therefore the only part batching actually amortises.
	//
	// Reporting CryptoTime + LedgerTime as one number would make Exp 2
	// unanswerable.
	LedgerTime time.Duration

	// Total is wall-clock for the whole call. It may exceed CryptoTime +
	// LedgerTime where a scheme overlaps them; the difference is itself
	// informative.
	Total time.Duration

	// BatchCommitment identifies the committed batch, for provenance linkage.
	BatchCommitment []byte
}

// -----------------------------------------------------------------------------
// Audit — Exp 3
// -----------------------------------------------------------------------------

// AuditQuery requests the redaction history of one transaction.
type AuditQuery struct {
	AuditorID  string
	TargetTxID string

	// StateEpoch selects the anchored state to verify against. Zero means latest.
	StateEpoch uint64
}

// AuditSemantics records what a scheme's audit path actually answers.
//
// The four schemes do not answer the same question. VRBC audits ledger
// integrity; ZK-Redact retrieves a transaction's redaction history. Both scale
// with ledger size, which is what Exp 3 compares — but presenting them as
// feature-equivalent would be misleading, so each result says which it is.
type AuditSemantics string

const (
	// SemanticsPerTxProvenance: the scheme returned the target transaction's own
	// redaction history.
	SemanticsPerTxProvenance AuditSemantics = "per_tx_provenance"

	// SemanticsLedgerIntegrity: the scheme verified that ledger contents are
	// untampered, without per-transaction history.
	SemanticsLedgerIntegrity AuditSemantics = "ledger_integrity"

	// SemanticsFullScan: the scheme could only answer by traversing the chain.
	SemanticsFullScan AuditSemantics = "full_scan"
)

// AuditResult reports one audit.
type AuditResult struct {
	// Semantics states which question this scheme actually answered.
	Semantics AuditSemantics

	// Verified is the verification outcome. A scheme whose verification never
	// returns false is not verifying anything — the fidelity tests in
	// docs/baselines/*.md exist to prove each path can reject.
	Verified bool

	// History is the retrieved redaction history, empty for schemes without
	// per-transaction provenance.
	History []ProvenanceRecord

	// RetrievalTime covers fetching evidence; VerificationTime covers checking
	// it. Reported separately because they scale differently: retrieval tends to
	// track ledger size, verification tends to track proof structure.
	RetrievalTime    time.Duration
	VerificationTime time.Duration

	// AuthorizationTime covers auditor authentication — signature verification,
	// freshness, and audit-policy evaluation.
	//
	// Reported SEPARATELY as a constant adder. No baseline has this step, so
	// folding it into the total would penalise ZK-Redact for providing a
	// capability the others simply lack.
	AuthorizationTime time.Duration

	// EvidenceBytes is what crossed the wire. For full-scan schemes this is the
	// traversed ledger portion, which is the point of the comparison.
	EvidenceBytes int

	// BlocksTraversed exposes whether a scheme touched the whole ledger. A
	// scheme claiming ledger independence whose value grows with ledger size is
	// contradicting itself, and the harness should catch that.
	BlocksTraversed int
}

// ProvenanceRecord is one entry in a transaction's redaction history.
type ProvenanceRecord struct {
	TxID          string
	FromVersion   uint64
	ToVersion     uint64
	PolicyID      string
	PolicyVersion uint64
	OldDigest     []byte
	NewDigest     []byte
	AuthEvidence  []byte
	BatchRoot     []byte
	CompletedAt   time.Time
}
