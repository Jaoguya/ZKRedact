package pvl

import (
	"context"
	"fmt"
	"sync"
	"time"

	"zkredact/internal/gateway"
)

// Service is the PVL driven as Phase 3 actually describes it: a standing layer
// that concurrent requests submit into, where proofs accumulate into
// intra-shard batches and shards verify in parallel.
//
// WHY THIS EXISTS RATHER THAN CALLING Verify PER REQUEST. Verifying one proof
// at a time makes sharding and batching literally no-ops — there is never more
// than one proof in flight to distribute or group. Measured that way, Exp 1
// reported identical throughput at N = 1, 4 and 16 shards, which is not a
// finding about sharding but about the harness never exercising it.
//
// Phase 3 Step 2 is the batch-closing rule this implements:
//
//	Close(B) = (|B| = B) OR (tau >= Delta)
//
// so a batch closes on size under load and on the wait bound when arrivals are
// sparse. Both halves matter: without the size rule a busy shard would wait out
// Delta every time; without the wait bound a half-full batch would hang until
// enough traffic arrived, and the tail latency would be attributed to
// verification.
type Service struct {
	cfg    Config
	pvl    *PVL
	queues []chan *job

	mu      sync.Mutex
	started bool
	stop    chan struct{}
	wg      sync.WaitGroup
}

// job is one request waiting on its verdict.
type job struct {
	query *gateway.Minimized
	reply chan Result
	shard int
}

// NewService builds a standing verification layer.
//
// queueDepth bounds how many requests may wait per shard. It comes from the
// caller because the right value is the offered load: Exp 1 drives up to
// concurrency_levels requests at once, and a queue shorter than that would
// serialise submitters on the channel and report the wait as verification cost.
func NewService(p *PVL, queueDepth int) (*Service, error) {
	if p == nil {
		return nil, fmt.Errorf("pvl: service needs a PVL")
	}
	if queueDepth < 1 {
		return nil, fmt.Errorf("pvl: queue depth must be >= 1, got %d", queueDepth)
	}

	s := &Service{cfg: p.cfg, pvl: p, stop: make(chan struct{})}
	s.queues = make([]chan *job, p.cfg.ShardCount)
	for i := range s.queues {
		s.queues[i] = make(chan *job, queueDepth)
	}
	return s, nil
}

// Start launches one worker per shard. Shards are independent, which is where
// the parallelism comes from — it does not depend on the proof system offering
// batch verification.
func (s *Service) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return
	}
	s.started = true

	for i := range s.queues {
		s.wg.Add(1)
		go func(shard int) {
			defer s.wg.Done()
			s.runShardLoop(shard)
		}(i)
	}
}

// Stop drains and shuts the workers down.
func (s *Service) Stop() {
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return
	}
	s.started = false
	close(s.stop)
	s.mu.Unlock()

	s.wg.Wait()
}

// Submit hands one request to its shard and waits for the verdict.
//
// Blocking is the point: the caller is one of Exp 1's concurrent workers, and
// the time it spends here — queueing plus batch verification — is exactly the
// authorization latency the experiment measures.
func (s *Service) Submit(ctx context.Context, q *gateway.Minimized) Result {
	shard := s.pvl.ShardFor(q.DID)

	s.pvl.mu.Lock()
	if shard < len(s.pvl.stats.PerShard) {
		s.pvl.stats.PerShard[shard]++
	}
	s.pvl.mu.Unlock()

	j := &job{query: q, reply: make(chan Result, 1), shard: shard}

	select {
	case s.queues[shard] <- j:
	case <-ctx.Done():
		return Result{Query: q, Shard: shard, Err: ctx.Err()}
	}

	select {
	case r := <-j.reply:
		return r
	case <-ctx.Done():
		return Result{Query: q, Shard: shard, Err: ctx.Err()}
	}
}

// runShardLoop accumulates a batch and verifies it, per Phase 3 Step 2.
func (s *Service) runShardLoop(shard int) {
	q := s.queues[shard]
	batch := make([]*job, 0, s.cfg.BatchSize)

	// timer fires Delta after the OLDEST request in the open batch, which is
	// what tau measures. Started when a batch opens, stopped when it closes.
	var timer *time.Timer
	var timeout <-chan time.Time

	closeBatch := func(short bool) {
		if len(batch) == 0 {
			return
		}
		s.verify(batch, short)
		batch = batch[:0]
		if timer != nil {
			timer.Stop()
			timer = nil
		}
		timeout = nil
	}

	for {
		select {
		case <-s.stop:
			// Drain what is queued rather than abandoning waiters, which would
			// surface as a context error indistinguishable from a failed proof.
			for {
				select {
				case j := <-q:
					batch = append(batch, j)
					if len(batch) >= s.cfg.BatchSize {
						closeBatch(false)
					}
					continue
				default:
				}
				break
			}
			closeBatch(true)
			return

		case j := <-q:
			batch = append(batch, j)
			if len(batch) == 1 {
				timer = time.NewTimer(s.cfg.BatchWait)
				timeout = timer.C
			}
			if len(batch) >= s.cfg.BatchSize {
				closeBatch(false)
			}

		case <-timeout:
			// tau >= Delta: close short rather than making the oldest request
			// wait for traffic that may not arrive.
			closeBatch(true)
		}
	}
}

// verify runs one closed batch and replies to every waiter in it.
func (s *Service) verify(batch []*job, short bool) {
	s.pvl.mu.Lock()
	s.pvl.stats.Batches++
	if short {
		s.pvl.stats.BatchesShortClosed++
	}
	s.pvl.stats.BatchSizeSum += len(batch)
	s.pvl.mu.Unlock()

	queries := make([]*gateway.Minimized, len(batch))
	idx := make([]int, len(batch))
	for i, j := range batch {
		queries[i] = j.query
		idx[i] = i
	}

	out := make([]Result, len(batch))
	for i := range out {
		out[i].Query = queries[i]
		out[i].Shard = batch[i].shard
	}
	s.pvl.verifyBatch(idx, queries, out)

	for i, j := range batch {
		j.reply <- out[i]
	}
}
