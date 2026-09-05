package pvl

import (
	"context"
	"sync"
	"testing"
	"time"

	"zkredact/internal/gateway"
	"zkredact/pkg/zk"
)

// serviceFixture starts a service and stops it with the test.
func serviceFixture(t *testing.T, cfg Config) *Service {
	t.Helper()
	p, err := New(cfg, params(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	svc, err := NewService(p, 4096)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	svc.Start()
	t.Cleanup(svc.Stop)
	return svc
}

// TestServiceAnswersEverySubmitter pins that no request is lost or left
// blocked. A dropped reply would hang an Exp 1 worker for the whole run.
func TestServiceAnswersEverySubmitter(t *testing.T) {
	svc := serviceFixture(t, Config{
		ShardCount: 4, BatchSize: 8, BatchWait: 20 * time.Millisecond,
	})

	const n = 200
	var wg sync.WaitGroup
	answered := make([]bool, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			r := svc.Submit(ctx, fakeQuery(k))
			answered[k] = r.Err == nil || r.Err != context.DeadlineExceeded
		}(i)
	}
	wg.Wait()

	for i, ok := range answered {
		if !ok {
			t.Fatalf("submitter %d never received a verdict", i)
		}
	}
}

// TestSparseArrivalsCloseOnTheWaitBound pins Phase 3 Step 2's tau >= Delta.
//
// Without it a lone request would wait for a batch that never fills, and the
// hang would be attributed to verification cost rather than to batching.
func TestSparseArrivalsCloseOnTheWaitBound(t *testing.T) {
	const wait = 50 * time.Millisecond
	svc := serviceFixture(t, Config{
		ShardCount: 1, BatchSize: 64, BatchWait: wait,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	r := svc.Submit(ctx, fakeQuery(1))
	elapsed := time.Since(start)

	if r.Err != nil && r.Err == context.DeadlineExceeded {
		t.Fatal("a single request never came back: the batch never closed")
	}
	if elapsed < wait {
		t.Errorf("returned in %s, before the %s wait bound — the batch closed early", elapsed, wait)
	}
	if elapsed > wait*10 {
		t.Errorf("took %s against a %s wait bound; the timer is not driving closure", elapsed, wait)
	}
}

// TestFullBatchesCloseOnSize pins the other half of the rule: under load a
// batch must close on B rather than waiting out Delta every time, which would
// add the wait bound to every request's latency.
func TestFullBatchesCloseOnSize(t *testing.T) {
	const wait = 2 * time.Second
	svc := serviceFixture(t, Config{
		ShardCount: 1, BatchSize: 16, BatchWait: wait,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			svc.Submit(ctx, fakeQuery(k))
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	if elapsed >= wait {
		t.Errorf("a full batch of 16 took %s, at least the %s wait bound: it closed "+
			"on the timer rather than on size, so every request pays Delta", elapsed, wait)
	}
}

// TestBatchesActuallyFill is the check that a configured B is realised.
//
// A run where B is 32 but the mean realised batch is 1.2 is not measuring
// batching, and nothing in a throughput number would say so.
func TestBatchesActuallyFill(t *testing.T) {
	cfg := Config{ShardCount: 1, BatchSize: 16, BatchWait: 500 * time.Millisecond}
	p, err := New(cfg, params(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	svc, err := NewService(p, 4096)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	svc.Start()

	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 320; i++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			svc.Submit(ctx, fakeQuery(k))
		}(i)
	}
	wg.Wait()
	svc.Stop()

	st := p.Stats()
	if mean := st.MeanBatchSize(); mean < 2 {
		t.Errorf("mean realised batch size %.2f against a configured B of %d: "+
			"batching is configured but not happening", mean, cfg.BatchSize)
	}
}

// TestShardsRunInParallel is the sharding claim itself.
//
// With one shard the batches are serial; with several they overlap. Measured as
// wall time for a fixed amount of work, because that is what Exp 1 reports.
func TestShardsRunInParallel(t *testing.T) {
	pr := params(t)
	proof := mustProve(t, pr)

	const requests = 128
	run := func(shards int) time.Duration {
		p, err := New(Config{
			ShardCount: shards, BatchSize: 8, BatchWait: 20 * time.Millisecond,
		}, pr)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		svc, err := NewService(p, 4096)
		if err != nil {
			t.Fatalf("NewService: %v", err)
		}
		svc.Start()
		defer svc.Stop()

		ctx := context.Background()
		var wg sync.WaitGroup
		start := time.Now()
		for i := 0; i < requests; i++ {
			wg.Add(1)
			go func(k int) {
				defer wg.Done()
				q := &gateway.Minimized{DID: zk.Hash(zk.Uint64Bytes(uint64(k))), Proof: proof}
				svc.Submit(ctx, q)
			}(i)
		}
		wg.Wait()
		return time.Since(start)
	}

	one := run(1)
	many := run(8)

	t.Logf("%d proofs: 1 shard %s, 8 shards %s (%.2fx)",
		requests, one.Round(time.Millisecond), many.Round(time.Millisecond),
		float64(one)/float64(many))

	// A loose bound: this asserts sharding helps at all, not by how much, since
	// the speedup depends on available cores.
	if many >= one {
		t.Errorf("8 shards (%s) were no faster than 1 (%s); shards are not running "+
			"in parallel, and Exp 1's sharding curve would be flat for a reason "+
			"that has nothing to do with the design", many, one)
	}
}
