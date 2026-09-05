package pvl

import (
	"context"
	"math"
	"testing"
	"time"

	"zkredact/internal/gateway"
	"zkredact/pkg/zk"
)

// The test circuit is small: depth 3 matches the configured predicate depth,
// tree depth 3 holds 8 credentials. Setup is the expensive part, so it is done
// once for the package.
const (
	testPredicateDepth = 3
	testTreeDepth      = 3
	testTargetBits     = 128
)

var testParams *zk.Params

func params(t *testing.T) *zk.Params {
	t.Helper()
	if testParams == nil {
		p, err := zk.Setup(testPredicateDepth, testTreeDepth, testTargetBits)
		if err != nil {
			t.Fatalf("zk.Setup: %v", err)
		}
		testParams = p
	}
	return testParams
}

func testConfig() Config {
	return Config{ShardCount: 4, BatchSize: 8, BatchWait: 50 * time.Millisecond}
}

// fakeQuery builds a Minimized carrying no proof. Used where only routing is
// under test, so the expensive proving step is not paid for.
func fakeQuery(n int) *gateway.Minimized {
	return &gateway.Minimized{DID: zk.Hash(zk.Uint64Bytes(uint64(n)))}
}

// -----------------------------------------------------------------------------
// Sharding
// -----------------------------------------------------------------------------

// TestShardAssignmentIsDeterministic pins that the same request always lands on
// the same shard. A rule that moved requests between rounds would make the
// per-shard counts meaningless and could let one request be verified twice.
func TestShardAssignmentIsDeterministic(t *testing.T) {
	did := zk.Hash(zk.Uint64Bytes(42))
	for n := 1; n <= 64; n *= 2 {
		first := ShardFor(did, n)
		for i := 0; i < 100; i++ {
			if got := ShardFor(did, n); got != first {
				t.Fatalf("n=%d: shard moved from %d to %d", n, first, got)
			}
		}
	}
}

func TestShardAssignmentStaysInRange(t *testing.T) {
	for n := 1; n <= 64; n *= 2 {
		for i := 0; i < 1000; i++ {
			j := ShardFor(zk.Hash(zk.Uint64Bytes(uint64(i))), n)
			if j < 0 || j >= n {
				t.Fatalf("n=%d: request %d assigned to shard %d", n, i, j)
			}
		}
	}
}

// TestShardAssignmentIsBalanced checks the hash rule spreads load.
//
// A skewed assignment would cap throughput at the busiest shard, and Exp 1
// would report that as a limit of sharding rather than of the assignment rule.
// The bound is loose — this tests for gross skew, not for uniformity.
func TestShardAssignmentIsBalanced(t *testing.T) {
	const requests = 20000
	for _, n := range []int{2, 4, 8, 16, 32, 64} {
		counts := make([]int, n)
		for i := 0; i < requests; i++ {
			counts[ShardFor(zk.Hash(zk.Uint64Bytes(uint64(i))), n)]++
		}
		expected := float64(requests) / float64(n)
		for j, c := range counts {
			dev := math.Abs(float64(c)-expected) / expected
			if dev > 0.25 {
				t.Errorf("n=%d shard %d holds %d requests, expected ~%.0f (%.1f%% off): "+
					"a skew this large caps throughput at the busiest shard and reads "+
					"as a limit of sharding", n, j, c, expected, dev*100)
			}
		}
	}
}

// TestShardCountOneIsTheDisabledAblation pins that N=1 really is "sharding
// off": every request on one shard. Exp 1's ablation grid depends on it.
func TestShardCountOneIsTheDisabledAblation(t *testing.T) {
	for i := 0; i < 1000; i++ {
		if j := ShardFor(zk.Hash(zk.Uint64Bytes(uint64(i))), 1); j != 0 {
			t.Fatalf("with N=1 request %d went to shard %d", i, j)
		}
	}
}

// TestVerifyRoutesEveryRequest checks nothing is dropped or duplicated when
// shards run concurrently.
func TestVerifyRoutesEveryRequest(t *testing.T) {
	p, err := New(testConfig(), params(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const n = 500
	queries := make([]*gateway.Minimized, n)
	for i := range queries {
		queries[i] = fakeQuery(i)
	}

	results := p.Verify(context.Background(), queries)
	if len(results) != n {
		t.Fatalf("got %d results for %d queries", len(results), n)
	}
	for i, r := range results {
		if r.Query != queries[i] {
			t.Fatalf("result %d is paired with the wrong query; a verdict on one "+
				"request would be recorded against another", i)
		}
	}

	total := 0
	for _, c := range p.Stats().PerShard {
		total += c
	}
	if total != n {
		t.Errorf("shard counters total %d, want %d", total, n)
	}
}

// -----------------------------------------------------------------------------
// Failure isolation — Phase 3 Step 4
// -----------------------------------------------------------------------------

// TestOneBadProofRejectsOnlyItself is the isolation requirement.
//
// An aggregate verdict over a batch would reject a whole shard's honest
// requests, and would make a batch of INVALID proofs verify faster than a batch
// of valid ones — a scheme that rejects everything would post the best Exp 1
// numbers in the study.
func TestOneBadProofRejectsOnlyItself(t *testing.T) {
	pr := params(t)

	good := mustProve(t, pr)
	bad := &zk.Proof{Proof: nil, Witness: good.Witness} // structurally invalid

	for _, native := range []bool{false, true} {
		cfg := testConfig()
		cfg.ShardCount = 1 // one shard, so all proofs share a batch
		cfg.NativeBatchVerify = native

		p, err := New(cfg, pr)
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		queries := []*gateway.Minimized{
			{DID: zk.Uint64Bytes(1), Proof: good},
			{DID: zk.Uint64Bytes(2), Proof: bad},
			{DID: zk.Uint64Bytes(3), Proof: good},
		}
		results := p.Verify(context.Background(), queries)

		if !results[0].Verified || !results[2].Verified {
			t.Errorf("native=%v: a valid proof was rejected alongside an invalid one; "+
				"failure is not isolated", native)
		}
		if results[1].Verified {
			t.Errorf("native=%v: an invalid proof verified", native)
		}
		if results[1].Err == nil {
			t.Errorf("native=%v: a rejected proof carries no reason, so an invalid "+
				"proof cannot be told from a broken verifier", native)
		}
	}
}

// TestValidProofsVerify is the positive control for the test above: without it,
// a verifier that rejected everything would satisfy the isolation test.
func TestValidProofsVerify(t *testing.T) {
	pr := params(t)
	proof := mustProve(t, pr)

	p, err := New(testConfig(), pr)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	queries := []*gateway.Minimized{{DID: zk.Uint64Bytes(7), Proof: proof}}
	results := p.Verify(context.Background(), queries)

	if !results[0].Verified {
		t.Fatalf("a valid proof did not verify: %v", results[0].Err)
	}
}

// -----------------------------------------------------------------------------
// Batching
// -----------------------------------------------------------------------------

// TestBatchesRespectTheSizeBound pins B. A batch larger than configured would
// report a batching benefit the configuration did not ask for.
func TestBatchesRespectTheSizeBound(t *testing.T) {
	cfg := testConfig()
	cfg.ShardCount = 1
	cfg.BatchSize = 4

	p, err := New(cfg, params(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	queries := make([]*gateway.Minimized, 10)
	for i := range queries {
		queries[i] = fakeQuery(i)
	}
	p.Verify(context.Background(), queries)

	// 10 requests at B=4 is two full batches and one short.
	st := p.Stats()
	if st.Batches != 3 {
		t.Errorf("got %d batches for 10 requests at B=4, want 3", st.Batches)
	}
	if st.BatchesShortClosed != 1 {
		t.Errorf("got %d short-closed batches, want 1", st.BatchesShortClosed)
	}
}

// TestBatchSizeOneIsTheDisabledAblation pins that B=1 means one request per
// batch, which is Exp 1's batching-off arm.
func TestBatchSizeOneIsTheDisabledAblation(t *testing.T) {
	cfg := testConfig()
	cfg.ShardCount = 1
	cfg.BatchSize = 1

	p, err := New(cfg, params(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	queries := make([]*gateway.Minimized, 6)
	for i := range queries {
		queries[i] = fakeQuery(i)
	}
	p.Verify(context.Background(), queries)

	if got := p.Stats().Batches; got != 6 {
		t.Errorf("B=1 produced %d batches for 6 requests, want 6", got)
	}
}

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

func TestConfigRefusesUnmeasurableShapes(t *testing.T) {
	cases := map[string]Config{
		"zero shards":     {ShardCount: 0, BatchSize: 1, BatchWait: time.Second},
		"zero batch size": {ShardCount: 1, BatchSize: 0, BatchWait: time.Second},
		"zero wait":       {ShardCount: 1, BatchSize: 1, BatchWait: 0},
	}
	for name, cfg := range cases {
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// TestReshardDoesNotRequireRecompilation pins the property that makes Exp 1's
// shard sweep affordable: N is runtime dispatch, not circuit shape.
func TestReshardDoesNotRequireRecompilation(t *testing.T) {
	p, err := New(testConfig(), params(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, n := range []int{1, 2, 8, 64} {
		if err := p.Reshard(n); err != nil {
			t.Fatalf("Reshard(%d): %v", n, err)
		}
		if got := p.ShardCount(); got != n {
			t.Errorf("ShardCount() = %d after Reshard(%d)", got, n)
		}
		if got := len(p.Stats().PerShard); got != n {
			t.Errorf("stats track %d shards after Reshard(%d)", got, n)
		}
	}
	if err := p.Reshard(0); err == nil {
		t.Error("Reshard(0) was accepted")
	}
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// mustProve builds one valid proof, reused across tests because proving is the
// slowest operation in the package.
func mustProve(t *testing.T, pr *zk.Params) *zk.Proof {
	t.Helper()

	pol, err := zk.CompilePolicy(
		policyFixture(), testPredicateDepth, 512)
	if err != nil {
		t.Fatalf("CompilePolicy: %v", err)
	}

	attrs := [zk.NumAttributes]uint64{
		zk.AttrSender: 1, zk.AttrReceiver: 1, zk.AttrValidator: 1, zk.AttrRole: zk.RoleAdmin,
	}
	secret := zk.Uint64Bytes(9001)
	reg, err := zk.NewRegistry([][]byte{zk.CredentialLeaf(secret, attrs)}, testTreeDepth)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	st, err := zk.BuildStatement(requestFixture(), pol, 0, 128)
	if err != nil {
		t.Fatalf("BuildStatement: %v", err)
	}
	a, err := zk.NewAssignment(st, pol, attrs, secret, reg)
	if err != nil {
		t.Fatalf("NewAssignment: %v", err)
	}
	proof, err := zk.Prove(pr, a)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}
	return proof
}
