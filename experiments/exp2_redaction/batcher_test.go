package exp2_redaction

import (
	"context"
	"sync"
	"testing"
	"time"

	"zkredact/pkg/scheme"
)

// The batcher tests exist to make Delta_R FALSIFIABLE.
//
// Before batcher.go the wait bound was a parameter written onto the output
// record and applied to nothing, and the sweep's four values produced four
// identical sets of measurements. Nothing failed. No test caught it, because
// no test asserted that Delta_R changes anything — the runner's contract was
// "call Redact with slices of B_R", which it satisfied perfectly.
//
// So these assert on the two observable consequences of the closing rule
//
//	Close(B) = (|B| = B_R) OR (tau >= Delta_R)
//
// rather than on the code path: that a batch closes SHORT when arrivals stop,
// and that it closes FULL when they do not. A future refactor that silently
// drops the timer again fails the first; one that ignores B_R fails the second.

// recorder is a scheme that records the batch sizes it was handed.
//
// A stub rather than the real ZK-Redact: what is under test is the closing
// rule, and Groth16 proving would make these tests minutes long without
// exercising a single line of the batcher.
type recorder struct {
	mu    sync.Mutex
	sizes []int

	// delay simulates the ledger round trip. Without it every batch executes
	// instantly, submitters return immediately, and the queue never has more
	// than one request in it — which would make the size rule untestable for
	// the same reason the old slicing loop made the wait bound untestable.
	delay time.Duration
}

func (r *recorder) Name() string { return "recorder" }
func (r *recorder) Capabilities() scheme.Capabilities {
	return scheme.Capabilities{BatchRedaction: true}
}
func (r *recorder) Setup(context.Context, scheme.SetupParams) error { return nil }
func (r *recorder) Teardown(context.Context) error                  { return nil }
func (r *recorder) Authorize(context.Context, *scheme.Request) (*scheme.Authorization, error) {
	return &scheme.Authorization{Granted: true}, nil
}
func (r *recorder) Audit(context.Context, *scheme.AuditQuery) (*scheme.AuditResult, error) {
	return &scheme.AuditResult{}, nil
}

func (r *recorder) Redact(_ context.Context, batch []*scheme.Authorization) (*scheme.RedactionResult, error) {
	if r.delay > 0 {
		time.Sleep(r.delay)
	}
	r.mu.Lock()
	r.sizes = append(r.sizes, len(batch))
	r.mu.Unlock()
	return &scheme.RedactionResult{
		Succeeded:  len(batch),
		CryptoTime: time.Duration(len(batch)) * time.Millisecond,
		LedgerTime: time.Millisecond,
	}, nil
}

func (r *recorder) recorded() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]int(nil), r.sizes...)
}

func auths(n int) []*scheme.Authorization {
	out := make([]*scheme.Authorization, n)
	for i := range out {
		out[i] = &scheme.Authorization{Granted: true}
	}
	return out
}

// TestSparseArrivalsCloseOnTheWaitBound pins tau >= Delta_R.
//
// Concurrency 1 against B_R 16: only one request can ever be in flight, so a
// full batch is unreachable and every batch MUST close on the wait bound. Under
// the old slicing loop this configuration produced batches of 16 regardless,
// because the slice was cut from a list that was already entirely present.
func TestSparseArrivalsCloseOnTheWaitBound(t *testing.T) {
	r := &recorder{}
	p, err := runOne(context.Background(), r, auths(8), 16, 20, 1)
	if err != nil {
		t.Fatalf("runOne: %v", err)
	}

	if p.BatchesShortClosed == 0 {
		t.Fatalf("no batch closed on the wait bound; Delta_R did nothing "+
			"(closed=%d, sizes=%v)", p.BatchesClosed, r.recorded())
	}
	if p.MeanBatchSize > 1.5 {
		t.Errorf("mean batch size %.2f at concurrency 1: a batch cannot exceed "+
			"the offered load", p.MeanBatchSize)
	}
	if p.Succeeded != 8 {
		t.Errorf("succeeded = %d, want all 8 requests executed", p.Succeeded)
	}
}

// TestFullBatchesCloseOnSize pins |B| = B_R, the other half of the rule.
//
// Concurrency 8 against B_R 4, with a ledger delay long enough that submitters
// queue behind the executing round. Batches should fill by size and the wait
// bound should not fire.
func TestFullBatchesCloseOnSize(t *testing.T) {
	r := &recorder{delay: 15 * time.Millisecond}
	p, err := runOne(context.Background(), r, auths(32), 4, 500, 8)
	if err != nil {
		t.Fatalf("runOne: %v", err)
	}

	if p.MeanBatchSize < 3.0 {
		t.Errorf("mean batch size %.2f with 8 in flight and B_R 4: batches are "+
			"not filling by size (sizes=%v)", p.MeanBatchSize, r.recorded())
	}
	// The final drain closes whatever is open, so one short close is expected;
	// more than that means the size rule is not firing.
	if p.BatchesShortClosed > 1 {
		t.Errorf("%d batches closed short of B_R=4 at a 500 ms wait bound; "+
			"the size rule should have closed them (sizes=%v)",
			p.BatchesShortClosed, r.recorded())
	}
	if p.Succeeded != 32 {
		t.Errorf("succeeded = %d, want all 32 requests executed", p.Succeeded)
	}
}

// TestWaitBoundChangesTheMeasurement is the regression guard proper.
//
// Two runs identical but for Delta_R must not produce identical results. This
// is the assertion whose absence let four labelled-but-identical wait bounds
// ship: it does not care HOW the wait bound is implemented, only that changing
// it changes something a reader would plot.
//
// WHERE DELTA_R ACTUALLY BITES, which is not where one first expects. When the
// offered load can fill a batch, the size rule fires first and the wait bound
// is irrelevant no matter how it is set — at concurrency 32 against B_R 32 the
// batch is full in microseconds and 1 ms and 200 ms are equally slack. Delta_R
// only governs the case the size rule cannot reach: an UNDERFILLED batch, where
// it decides how long the requests already in hand wait for company that is not
// coming. So concurrency 8 against B_R 32 here.
//
// And what it moves there is elapsed time, not batch size: the batch closes at
// 8 either way, but one closes after 1 ms and the other after 200. That is why
// the assertion is on TotalTime. Delta_R is a latency and staleness knob, not a
// second batch-size knob — which is exactly why config/experiment.yaml calls it
// "the staleness knob" and why Exp 2 plots it against exclusion rate rather
// than against cost.
func TestWaitBoundChangesTheMeasurement(t *testing.T) {
	const (
		requests = 32
		batch    = 32 // unreachable at the concurrency below, by construction
		load     = 8
	)

	ps, err := runOne(context.Background(), &recorder{}, auths(requests), batch, 1, load)
	if err != nil {
		t.Fatalf("short bound: %v", err)
	}
	pl, err := runOne(context.Background(), &recorder{}, auths(requests), batch, 100, load)
	if err != nil {
		t.Fatalf("long bound: %v", err)
	}

	if ps.MeanBatchSize > load || pl.MeanBatchSize > load {
		t.Fatalf("a batch exceeded the offered load (%.2f, %.2f > %d): the "+
			"closed loop cannot have more than that in flight",
			ps.MeanBatchSize, pl.MeanBatchSize, load)
	}
	if ps.BatchesShortClosed == 0 || pl.BatchesShortClosed == 0 {
		t.Fatalf("B_R=%d is unreachable at concurrency %d, so every batch must "+
			"close on the wait bound; got short closes %d and %d",
			batch, load, ps.BatchesShortClosed, pl.BatchesShortClosed)
	}

	// Each round waits out its bound, so the long run must take materially
	// longer. Compared as a ratio rather than against a fixed duration, so a
	// loaded CI machine cannot fail it.
	if pl.TotalTime <= ps.TotalTime*4 {
		t.Errorf("Delta_R 1 ms and 100 ms produced comparable elapsed time "+
			"(%v vs %v): the wait bound is not driving the batcher",
			ps.TotalTime, pl.TotalTime)
	}
}

// TestEveryRequestIsOfferedExactlyOnce guards the work queue.
//
// The submitters draw from one channel, so a bug there would drop or duplicate
// requests — and either would move the cost-per-request curve without moving
// anything that looks like an error.
func TestEveryRequestIsOfferedExactlyOnce(t *testing.T) {
	r := &recorder{}
	const n = 100
	p, err := runOne(context.Background(), r, auths(n), 8, 5, 8)
	if err != nil {
		t.Fatalf("runOne: %v", err)
	}

	total := 0
	for _, s := range r.recorded() {
		total += s
	}
	if total != n {
		t.Errorf("scheme was handed %d requests, want %d", total, n)
	}
	if p.Requested != n {
		t.Errorf("Requested = %d, want %d", p.Requested, n)
	}
}
