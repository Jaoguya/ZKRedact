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
}

// -----------------------------------------------------------------------------
// Setup
// -----------------------------------------------------------------------------

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
	ID        string
	Core      []byte // immutable
	Redactabl []byte // redaction target
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
