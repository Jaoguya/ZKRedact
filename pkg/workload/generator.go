// Package workload generates the shared source dataset and request trace.
//
// Everything here is deterministic from a seed. That is not a convenience — it
// is what makes the comparison legitimate. All four schemes must see identical
// transactions in identical order, and a run must be reproducible from
// config/experiment.yaml plus a seed alone (SKILL.md).
//
// The generator deliberately does NOT know about any scheme. It emits neutral
// source data; each scheme materialises it into its own on-chain form during
// Setup, which is not timed.
package workload

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/rand"
	"time"

	"zkredact/pkg/scheme"
)

// Config controls dataset and trace generation. Values come from
// config/experiment.yaml; nothing here has a built-in default, because a
// silently defaulted parameter is exactly the magic number the project rules
// forbid.
type Config struct {
	Seed int64

	// Dataset
	BaseTransactions      int
	CorePayloadBytes      int
	RedactablePayloadBytes int
	IdentityCount         int
	IdentityAttributes    []string
	PolicyCount           int
	PredicateDepth        int

	// Trace
	TotalRequests      int
	TargetDistribution string // "uniform" | "zipf"
	ZipfS              float64
	ConflictRatio      float64
}

// Validate reports configuration that cannot produce a usable workload.
func (c Config) Validate() error {
	switch {
	case c.BaseTransactions <= 0:
		return fmt.Errorf("base_transactions must be positive, got %d", c.BaseTransactions)
	case c.CorePayloadBytes <= 0 || c.RedactablePayloadBytes <= 0:
		return fmt.Errorf("payload sizes must be positive")
	case c.IdentityCount <= 0:
		return fmt.Errorf("identity count must be positive, got %d", c.IdentityCount)
	case c.PolicyCount <= 0:
		return fmt.Errorf("policy count must be positive, got %d", c.PolicyCount)
	case c.TotalRequests <= 0:
		return fmt.Errorf("total_requests must be positive, got %d", c.TotalRequests)
	case c.ConflictRatio < 0 || c.ConflictRatio > 1:
		return fmt.Errorf("conflict_ratio must be in [0,1], got %v", c.ConflictRatio)
	case c.TargetDistribution == "zipf" && c.ZipfS <= 1:
		return fmt.Errorf("zipf_s must exceed 1, got %v", c.ZipfS)
	case c.TargetDistribution != "uniform" && c.TargetDistribution != "zipf":
		return fmt.Errorf("unknown target_distribution %q", c.TargetDistribution)
	}
	return nil
}

// -----------------------------------------------------------------------------
// Dataset
// -----------------------------------------------------------------------------

// GenerateDataset builds the source corpus. Identical Config yields a
// byte-identical dataset, including its ID.
func GenerateDataset(c Config) (*scheme.Dataset, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}

	// Independent streams per entity kind, so changing the transaction count
	// does not shift the identities or policies that get generated. Without
	// this, a dataset-size sweep would silently vary the participants too.
	txRNG := rand.New(rand.NewSource(c.Seed))
	idRNG := rand.New(rand.NewSource(c.Seed + 1))
	polRNG := rand.New(rand.NewSource(c.Seed + 2))

	ds := &scheme.Dataset{
		Transactions: make([]scheme.Transaction, c.BaseTransactions),
		Identities:   make([]scheme.Identity, c.IdentityCount),
		Policies:     make([]scheme.Policy, c.PolicyCount),
	}

	for i := range ds.Identities {
		attrs := make(map[string]string, len(c.IdentityAttributes))
		for _, a := range c.IdentityAttributes {
			switch a {
			case "org":
				attrs[a] = fmt.Sprintf("org%d", idRNG.Intn(4)+1)
			case "role":
				attrs[a] = []string{"operator", "auditor", "admin"}[idRNG.Intn(3)]
			default:
				// sender / receiver / validator are boolean roles
				attrs[a] = fmt.Sprint(idRNG.Intn(2) == 1)
			}
		}
		ds.Identities[i] = scheme.Identity{
			ID:         fmt.Sprintf("id-%06d", i),
			Attributes: attrs,
		}
	}

	for i := range ds.Policies {
		ds.Policies[i] = scheme.Policy{
			ID:        fmt.Sprintf("pol-%04d", i),
			Version:   1,
			Predicate: buildPredicate(polRNG, c.PredicateDepth),
		}
	}

	for i := range ds.Transactions {
		ds.Transactions[i] = scheme.Transaction{
			ID:        fmt.Sprintf("tx-%08d", i),
			Core:      randomBytes(txRNG, c.CorePayloadBytes),
			Redactable: randomBytes(txRNG, c.RedactablePayloadBytes),
		}
	}

	ds.ID = datasetID(c)
	return ds, nil
}

// buildPredicate produces a policy expression of the configured depth.
// Depth drives ZK circuit size and therefore the Exp 1 verification floor, so
// it must come from config rather than being fixed here.
func buildPredicate(r *rand.Rand, depth int) string {
	terms := []string{"sender", "receiver", "validator", "role=operator", "role=admin"}
	if depth <= 1 {
		return terms[r.Intn(len(terms))]
	}
	expr := terms[r.Intn(len(terms))]
	for i := 1; i < depth; i++ {
		op := "AND"
		if r.Intn(2) == 0 {
			op = "OR"
		}
		expr = fmt.Sprintf("(%s %s %s)", expr, op, terms[r.Intn(len(terms))])
	}
	return expr
}

func randomBytes(r *rand.Rand, n int) []byte {
	b := make([]byte, n)
	// Read on a seeded Rand is deterministic and never returns an error.
	_, _ = r.Read(b)
	return b
}

// datasetID hashes the parameters that determine dataset content. Recorded in
// results so a reader can confirm two runs used the same corpus.
func datasetID(c Config) string {
	h := sha256.New()
	write := func(vals ...int64) {
		var buf [8]byte
		for _, v := range vals {
			binary.LittleEndian.PutUint64(buf[:], uint64(v))
			h.Write(buf[:])
		}
	}
	write(c.Seed,
		int64(c.BaseTransactions),
		int64(c.CorePayloadBytes),
		int64(c.RedactablePayloadBytes),
		int64(c.IdentityCount),
		int64(c.PolicyCount),
		int64(c.PredicateDepth))
	for _, a := range c.IdentityAttributes {
		h.Write([]byte(a))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// -----------------------------------------------------------------------------
// Request trace
// -----------------------------------------------------------------------------

// GenerateTrace builds the ordered request sequence. Every scheme replays this
// same slice, in this same order.
func GenerateTrace(c Config, ds *scheme.Dataset) ([]*scheme.Request, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if len(ds.Transactions) == 0 {
		return nil, fmt.Errorf("dataset has no transactions")
	}

	// Stream distinct from dataset generation, so sweeping the trace does not
	// perturb the corpus.
	r := rand.New(rand.NewSource(c.Seed + 100))

	trace := make([]*scheme.Request, c.TotalRequests)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// used tracks transactions already targeted, so conflicts can be drawn from
	// them. Conflicting requests are what force serialization in ZK-Redact
	// Phase 4 and map onto Ref[22]'s consecutive delete sets.
	used := make([]int, 0, c.TotalRequests)

	for i := range trace {
		var txIdx int
		if len(used) > 0 && r.Float64() < c.ConflictRatio {
			txIdx = used[r.Intn(len(used))]
		} else {
			txIdx = pickTarget(r, c, len(ds.Transactions))
			used = append(used, txIdx)
		}

		trace[i] = &scheme.Request{
			ID:          fmt.Sprintf("req-%08d", i),
			RequesterID: ds.Identities[r.Intn(len(ds.Identities))].ID,
			TargetTxID:  ds.Transactions[txIdx].ID,
			NewContent:  randomBytes(r, c.RedactablePayloadBytes),
			PolicyID:    ds.Policies[r.Intn(len(ds.Policies))].ID,
			Timestamp:   base.Add(time.Duration(i) * time.Millisecond),
			Nonce:       randomBytes(r, 16),
		}
	}
	return trace, nil
}

// pickTarget selects a transaction index under the configured distribution.
func pickTarget(r *rand.Rand, c Config, n int) int {
	if c.TargetDistribution == "zipf" {
		return zipfIndex(r, c.ZipfS, n)
	}
	return r.Intn(n)
}

// zipfIndex draws from a Zipf distribution over [0,n) by inverse-CDF sampling
// on the tail approximation. math/rand's ZipfGenerator is avoided because it
// carries state, which would couple draw order to unrelated calls on the same
// stream and break reproducibility across code changes.
func zipfIndex(r *rand.Rand, s float64, n int) int {
	u := r.Float64()
	// Continuous approximation of the discrete Zipf inverse CDF.
	idx := int(math.Pow(float64(n), math.Pow(u, 1/(s-1)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= n {
		idx = n - 1
	}
	return idx
}

// ConflictRate reports the observed fraction of requests targeting a
// transaction that an earlier request already targeted.
//
// Provided so the harness can verify the generated trace matches the configured
// ratio rather than assuming it. A trace that silently deviates would make the
// Exp 2 serialization results wrong in a way nothing else would reveal.
func ConflictRate(trace []*scheme.Request) float64 {
	if len(trace) == 0 {
		return 0
	}
	seen := make(map[string]bool, len(trace))
	repeats := 0
	for _, req := range trace {
		if seen[req.TargetTxID] {
			repeats++
		}
		seen[req.TargetTxID] = true
	}
	return float64(repeats) / float64(len(trace))
}
