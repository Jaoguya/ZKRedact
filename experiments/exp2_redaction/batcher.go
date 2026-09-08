package exp2_redaction

import (
	"context"
	"fmt"
	"sync"
	"time"

	"zkredact/pkg/scheme"
)

// The redaction batcher, and why Exp 2 could not measure Delta_R without it.
//
// Phase 4's batch-closing rule is the same shape as Phase 3 Step 2's:
//
//	Close(B) = (|B| = B_R) OR (tau >= Delta_R)
//
// so a batch closes on SIZE under load and on the WAIT BOUND when arrivals are
// sparse. Until now Exp 2 implemented only the left half, and not as a rule but
// as a slicing loop: runOne walked a pre-collected list in steps of B_R and
// handed each slice straight to Redact. Every batch was therefore full the
// instant it existed, tau was always zero, and Delta_R had nothing to bound.
//
// That is not a missing timer. It is a missing ARRIVAL PROCESS. A wait bound
// answers "how long may the oldest request in an open batch wait for company",
// and a list that is entirely present before the loop starts has no such
// question to answer. The four Delta_R values in config/experiment.yaml
// therefore produced four bit-identical sets of measurements, and the sweep
// cost four times what one arm would have.
//
// internal/pvl/service.go records the identical defect on the Exp 1 side, in
// the same words: verifying one proof at a time "makes sharding and batching
// literally no-ops — there is never more than one proof in flight to distribute
// or group", and Exp 1 duly reported identical throughput at 1, 4 and 16
// shards. This is that fix, for redaction.
//
// ONE WORKER, NOT ONE PER SHARD. The PVL runs a worker per shard because shards
// are independent. Redaction rounds are not: internal/redactor/executor.go
// opens round e+1, appends its anchor, and the anchor chain would have a gap it
// could never close if two rounds committed out of order. Executor.Run holds a
// mutex over its whole body for the same reason. So the batcher serialises
// rounds by construction rather than contending on a lock inside the scheme.
type batcher struct {
	scheme    scheme.Scheme
	batchSize int
	wait      time.Duration

	queue chan *submission
	stop  chan struct{}
	wg    sync.WaitGroup

	mu    sync.Mutex
	stats batchStats
	err   error
}

// batchStats is what makes the fix falsifiable.
//
// Without these a corrected Delta_R is indistinguishable from the broken one:
// both produce a cost curve, and neither says whether any batch ever closed on
// the wait bound. ShortClosed is the direct evidence that tau >= Delta_R fired,
// and MeanSize is the evidence that B_R was reachable at the offered load —
// a mean far below B_R means concurrency, not the knob, decided the batch size.
type batchStats struct {
	Closed      int
	ShortClosed int
	SizeSum     int

	Succeeded     int
	StaleExcluded int
	Failed        int
	CryptoTime    time.Duration
	LedgerTime    time.Duration
}

// submission is one authorized request waiting for the batch that carries it.
type submission struct {
	auth *scheme.Authorization
	done chan error
}

// newBatcher builds a standing redaction batcher.
//
// queueDepth bounds how many requests may wait. It comes from the caller for
// the reason pvl.NewService gives: a queue shorter than the offered load would
// serialise submitters on the channel and report that wait as redaction cost.
func newBatcher(s scheme.Scheme, batchSize int, wait time.Duration, queueDepth int) (*batcher, error) {
	if s == nil {
		return nil, fmt.Errorf("exp2: batcher needs a scheme")
	}
	if batchSize < 1 {
		return nil, fmt.Errorf("exp2: batch size must be >= 1, got %d", batchSize)
	}
	if queueDepth < 1 {
		return nil, fmt.Errorf("exp2: queue depth must be >= 1, got %d", queueDepth)
	}
	return &batcher{
		scheme:    s,
		batchSize: batchSize,
		wait:      wait,
		queue:     make(chan *submission, queueDepth),
		stop:      make(chan struct{}),
	}, nil
}

func (b *batcher) start(ctx context.Context) {
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		b.run(ctx)
	}()
}

// submit hands one authorization to the batcher and blocks until the batch
// carrying it has executed.
//
// Blocking is the point: the caller is one of Exp 2's concurrent submitters
// under a closed-loop arrival process, so the time it spends here — queueing,
// waiting out Delta_R, and the round itself — is exactly the redaction latency
// the experiment is trying to charge batching for.
func (b *batcher) submit(ctx context.Context, a *scheme.Authorization) error {
	s := &submission{auth: a, done: make(chan error, 1)}
	select {
	case b.queue <- s:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-s.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// finish drains the open batch and shuts the worker down.
func (b *batcher) finish() batchStats {
	close(b.stop)
	b.wg.Wait()
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stats
}

func (b *batcher) failure() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.err
}

// run accumulates a batch and executes it, per the Close(B) rule above.
func (b *batcher) run(ctx context.Context) {
	batch := make([]*submission, 0, b.batchSize)

	// timer fires Delta_R after the OLDEST request in the open batch, which is
	// what tau measures. Started when a batch opens, stopped when it closes.
	var timer *time.Timer
	var timeout <-chan time.Time

	closeBatch := func(short bool) {
		if len(batch) == 0 {
			return
		}
		b.execute(ctx, batch, short)
		batch = batch[:0]
		if timer != nil {
			timer.Stop()
			timer = nil
		}
		timeout = nil
	}

	for {
		select {
		case <-b.stop:
			// Drain what is queued rather than abandoning waiters, which would
			// surface as a context error indistinguishable from a failed
			// redaction.
			for {
				select {
				case s := <-b.queue:
					batch = append(batch, s)
					if len(batch) >= b.batchSize {
						closeBatch(false)
					}
					continue
				default:
				}
				break
			}
			closeBatch(true)
			return

		case s := <-b.queue:
			batch = append(batch, s)
			if len(batch) == 1 && b.wait > 0 {
				// A scheme that does not batch runs at B_R=1 with no wait
				// bound, so the size rule fires on this same request and the
				// timer would only ever be stopped unused.
				timer = time.NewTimer(b.wait)
				timeout = timer.C
			}
			if len(batch) >= b.batchSize {
				closeBatch(false)
			}

		case <-timeout:
			// tau >= Delta_R: close short rather than making the oldest request
			// wait for traffic that may never arrive.
			closeBatch(true)
		}
	}
}

// execute runs one closed batch and releases every waiter in it.
func (b *batcher) execute(ctx context.Context, batch []*submission, short bool) {
	auths := make([]*scheme.Authorization, len(batch))
	for i, s := range batch {
		auths[i] = s.auth
	}

	r, err := b.scheme.Redact(ctx, auths)

	b.mu.Lock()
	b.stats.Closed++
	if short {
		b.stats.ShortClosed++
	}
	b.stats.SizeSum += len(batch)
	if err != nil {
		if b.err == nil {
			b.err = err
		}
	} else {
		b.stats.Succeeded += r.Succeeded
		b.stats.StaleExcluded += r.StaleExcluded
		b.stats.Failed += r.Failed
		b.stats.CryptoTime += r.CryptoTime
		b.stats.LedgerTime += r.LedgerTime
	}
	b.mu.Unlock()

	for _, s := range batch {
		s.done <- err
	}
}
