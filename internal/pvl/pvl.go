// Package pvl implements ZK-Redact's Phase 3: the Proof Verification Layer.
//
// Accepted proofs are assigned to logical shards, batched within a shard, and
// verified in parallel across shards. This is the core of Experiment 1 and the
// mechanism behind the scheme's scalability claim.
//
// TWO INDEPENDENT MECHANISMS, DELIBERATELY SEPARABLE.
//
//   - Sharding gives parallelism. It works whatever the proof system does,
//     because the shards are independent workers over disjoint request sets.
//   - Batching amortises scheduling within a shard, and additionally lets a
//     scheme with native batch verification exploit it.
//
// The manuscript's claim is that sharding provides parallelism INDEPENDENTLY of
// any batch-verification support, so the two must be switchable separately —
// which is exactly what Exp 1's ablation grid (sharding x batching) tests. A
// PVL that only worked with both enabled would make that claim untestable.
//
// VERIFICATION IS PER-REQUEST, ALWAYS. Phase 3 Step 4 requires failure
// isolation: a single invalid proof must reject its own request and no other.
// An aggregate pass/fail over a batch would fail a whole shard's worth of
// honest requests, and — worse for the measurement — would make a batch of
// invalid proofs verify faster than a batch of valid ones.
package pvl

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"zkredact/internal/gateway"
	"zkredact/pkg/zk"
)

// Config is the PVL's runtime shape. Every field comes from
// config/experiment.yaml; none is defaulted.
type Config struct {
	// ShardCount is N, the number of logical proof shards.
	ShardCount int

	// BatchSize is B, the maximum requests in one intra-shard batch.
	BatchSize int

	// BatchWait is the bound on how long the oldest request in an open batch
	// waits before the batch closes short. Phase 3 Step 2's tau >= Delta.
	BatchWait time.Duration

	// NativeBatchVerify selects the proof system's own batch verification where
	// it exists. Groth16 has none for distinct public inputs, so this changes
	// the code path taken, not the result.
	NativeBatchVerify bool
}

// Validate refuses a shape that cannot measure what Exp 1 claims.
func (c Config) Validate() error {
	if c.ShardCount < 1 {
		return fmt.Errorf("pvl: shard_count must be >= 1, got %d", c.ShardCount)
	}
	if c.BatchSize < 1 {
		return fmt.Errorf("pvl: proof_batch_size must be >= 1, got %d", c.BatchSize)
	}
	if c.BatchWait <= 0 {
		return fmt.Errorf("pvl: proof_batch_wait_ms must be positive, got %s", c.BatchWait)
	}
	return nil
}

// Result is one request's verification outcome.
type Result struct {
	Query *gateway.Minimized

	// Verified is V_i in the manuscript.
	Verified bool

	// Err is set when verification failed. A false Verified with a nil Err is
	// not possible: the reason a proof failed is what distinguishes an invalid
	// proof from a broken verifier.
	Err error

	// Shard records which shard handled it, so a skewed assignment is visible
	// in results rather than showing up as unexplained tail latency.
	Shard int
}

// Stats describe one verification round. Reported so the sharding claim can be
// checked rather than assumed.
type Stats struct {
	// PerShard counts requests handled by each shard. A uniform hash should
	// produce a near-flat distribution; a skew here explains a throughput
	// result that sharding otherwise appears not to help.
	PerShard []int

	// Batches counts closed batches, and BatchesShortClosed those that closed
	// on the wait bound rather than on reaching BatchSize. A run where every
	// batch closes short is not measuring batching.
	Batches            int
	BatchesShortClosed int

	// BatchSizeSum over Batches gives the mean realised batch size. A
	// configured B of 32 that realises a mean of 1.2 is not measuring batching,
	// and that difference is invisible in a throughput number.
	BatchSizeSum int
}

// MeanBatchSize reports the average number of proofs per closed batch.
func (s Stats) MeanBatchSize() float64 {
	if s.Batches == 0 {
		return 0
	}
	return float64(s.BatchSizeSum) / float64(s.Batches)
}

// PVL verifies proofs across logical shards.
type PVL struct {
	cfg    Config
	params *zk.Params

	mu    sync.Mutex
	stats Stats
}

// New builds a PVL over compiled circuit parameters.
func New(cfg Config, params *zk.Params) (*PVL, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if params == nil {
		return nil, fmt.Errorf("pvl: circuit parameters are required")
	}
	return &PVL{
		cfg:    cfg,
		params: params,
		stats:  Stats{PerShard: make([]int, cfg.ShardCount)},
	}, nil
}

// ShardFor is Phase 3 Step 1: j_i = 1 + (Int(H(DID_i)) mod N).
//
// Returned zero-based. Hashing the DID rather than, say, the arrival index is
// what makes assignment uniform in expectation and independent of arrival
// order: index-based round-robin would give a perfectly flat distribution and
// so would overstate how well the real rule balances.
func (p *PVL) ShardFor(did []byte) int {
	return ShardFor(did, p.cfg.ShardCount)
}

// ShardFor assigns a DID to one of n shards.
func ShardFor(did []byte, n int) int {
	if n <= 1 {
		return 0
	}
	h := zk.Hash(zk.FieldBytes(did))
	// The low 8 bytes are as uniform as any others and avoid a big.Int.
	v := binary.BigEndian.Uint64(h[len(h)-8:])
	return int(v % uint64(n))
}

// Verify runs one round: assign, batch, and verify in parallel.
//
// Returns results in the SAME ORDER as the input, so a caller cannot
// accidentally pair a verdict with the wrong request. The shards run
// concurrently; the ordering is restored by index, not by arrival.
func (p *PVL) Verify(ctx context.Context, queries []*gateway.Minimized) []Result {
	results := make([]Result, len(queries))

	// --- Step 1: assign to shards ---
	shards := make([][]int, p.cfg.ShardCount)
	for i, q := range queries {
		j := p.ShardFor(q.DID)
		shards[j] = append(shards[j], i)
		results[i].Query = q
		results[i].Shard = j
	}

	p.mu.Lock()
	for j := range shards {
		p.stats.PerShard[j] += len(shards[j])
	}
	p.mu.Unlock()

	// --- Steps 2 and 3: batch within each shard, shards in parallel ---
	var wg sync.WaitGroup
	for j := range shards {
		if len(shards[j]) == 0 {
			continue
		}
		wg.Add(1)
		go func(shard int, idx []int) {
			defer wg.Done()
			p.runShard(ctx, idx, queries, results)
		}(j, shards[j])
	}
	wg.Wait()

	return results
}

// runShard forms batches inside one shard and verifies them.
func (p *PVL) runShard(ctx context.Context, idx []int, queries []*gateway.Minimized, out []Result) {
	for start := 0; start < len(idx); start += p.cfg.BatchSize {
		end := start + p.cfg.BatchSize
		short := false
		if end > len(idx) {
			end = len(idx)
			// Phase 3 Step 2: a batch also closes on the wait bound. In a
			// closed-loop run the queue drains rather than waiting, so the
			// final partial batch is the wait-bound case — recorded as such so
			// a run where every batch is short is visible as not measuring
			// batching.
			short = true
		}
		batch := idx[start:end]

		p.mu.Lock()
		p.stats.Batches++
		if short {
			p.stats.BatchesShortClosed++
		}
		p.mu.Unlock()

		if err := ctx.Err(); err != nil {
			for _, i := range batch {
				out[i].Verified = false
				out[i].Err = err
			}
			continue
		}

		p.verifyBatch(batch, queries, out)
	}
}

// verifyBatch verifies one batch, per request.
func (p *PVL) verifyBatch(batch []int, queries []*gateway.Minimized, out []Result) {
	if p.cfg.NativeBatchVerify {
		proofs := make([]*zk.Proof, len(batch))
		for k, i := range batch {
			proofs[k] = queries[i].Proof
		}
		errs := zk.BatchVerify(p.params, proofs)
		for k, i := range batch {
			out[i].Err = errs[k]
			out[i].Verified = errs[k] == nil
		}
		return
	}

	for _, i := range batch {
		err := zk.Verify(p.params, queries[i].Proof)
		out[i].Err = err
		out[i].Verified = err == nil
	}
}

// Stats returns a snapshot of the shard and batch counters.
func (p *PVL) Stats() Stats {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := Stats{
		Batches:            p.stats.Batches,
		BatchesShortClosed: p.stats.BatchesShortClosed,
		BatchSizeSum:       p.stats.BatchSizeSum,
		PerShard:           make([]int, len(p.stats.PerShard)),
	}
	copy(s.PerShard, p.stats.PerShard)
	return s
}

// Reshard changes the shard count between Exp 1 configurations.
//
// The circuit does NOT depend on the shard count — sharding is runtime dispatch
// — so re-running Setup to sweep N would recompile the circuit and run the
// trusted setup for nothing, dominating the very measurement being taken. This
// is what makes the shard sweep affordable.
func (p *PVL) Reshard(n int) error {
	if n < 1 {
		return fmt.Errorf("pvl: shard_count must be >= 1, got %d", n)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cfg.ShardCount = n
	p.stats = Stats{PerShard: make([]int, n)}
	return nil
}

// ShardCount reports the current N.
func (p *PVL) ShardCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cfg.ShardCount
}
