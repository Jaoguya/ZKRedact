package exp1_verification

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"zkredact/pkg/scheme"
)

// This file exists because of a defect that shipped twice.
//
// Exp 1's sweeps are declared in config, plumbed through Config, and then read
// by the loop in Run. Twice now a dimension has been declared and plumbed but
// never read — first the shard sweep, then the batch-size sweep — and neither
// crashed, failed a test, or looked wrong in a plot. It simply measured the
// disabled arm of a knob it reported as swept.
//
// A coverage test is the only thing that catches that class: it asserts what
// the sweep PRODUCED against what the config asked for, rather than trusting
// that the loop reads every field.

// tunableScheme implements Scheme plus every optional knob Exp 1 sweeps, and
// records the configuration in force at each Authorize.
type tunableScheme struct {
	mu     sync.Mutex
	shards int
	batch  int
	native bool

	// seen records one entry per (shards, batch, native) actually exercised.
	seen map[string]int
}

func newTunableScheme() *tunableScheme {
	return &tunableScheme{shards: 1, batch: 1, seen: map[string]int{}}
}

func (f *tunableScheme) Name() string { return "fake" }

func (f *tunableScheme) Capabilities() scheme.Capabilities {
	// PolicyBound false keeps the all-granted guard out of the way; the scheme
	// still denies some requests so the all-denied guard stays satisfied.
	return scheme.Capabilities{ParallelVerification: true}
}

func (f *tunableScheme) Setup(context.Context, scheme.SetupParams) error { return nil }

func (f *tunableScheme) Authorize(_ context.Context, req *scheme.Request) (*scheme.Authorization, error) {
	f.mu.Lock()
	f.seen[fmt.Sprintf("%d/%d/%v", f.shards, f.batch, f.native)]++
	f.mu.Unlock()

	// Deny a fixed minority: a scheme that grants everything trips one guard,
	// one that denies everything trips the other.
	return &scheme.Authorization{Request: req, Granted: req.ID != "req-0"}, nil
}

func (f *tunableScheme) Redact(context.Context, []*scheme.Authorization) (*scheme.RedactionResult, error) {
	return nil, scheme.ErrNotImplemented
}

func (f *tunableScheme) Audit(context.Context, *scheme.AuditQuery) (*scheme.AuditResult, error) {
	return nil, scheme.ErrNotImplemented
}

func (f *tunableScheme) Teardown(context.Context) error { return nil }

func (f *tunableScheme) Reshard(n int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shards = n
	return nil
}

func (f *tunableScheme) Rebatch(b int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.batch = b
	return nil
}

func (f *tunableScheme) SetNativeBatchVerify(native bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.native = native
	return nil
}

func fakeTrace(n int) []*scheme.Request {
	trace := make([]*scheme.Request, n)
	for i := range trace {
		trace[i] = &scheme.Request{ID: fmt.Sprintf("req-%d", i)}
	}
	return trace
}

// TestRunSweepsEveryConfiguredDimension is the guard. Every combination the
// config asks for must appear in the points, and every knob must actually have
// reached the scheme.
func TestRunSweepsEveryConfiguredDimension(t *testing.T) {
	cfg := Config{
		ConcurrencyLevels: []int{1, 4},
		Repetitions:       1,
		ShardCounts:       []int{1, 4},
		BatchSizes:        []int{1, 8},
		NativeBatchVerify: []bool{false, true},
	}

	f := newTunableScheme()
	res, err := Run(context.Background(), cfg, []scheme.Scheme{f}, fakeTrace(8))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// 2 shards x 2 batch sizes x 2 modes x 2 concurrency levels x 1 repetition.
	if want := 16; len(res.Points) != want {
		t.Errorf("got %d points, want %d — a declared sweep is not being executed",
			len(res.Points), want)
	}

	// Every cell of the knob grid must have been exercised at the scheme.
	for _, shards := range cfg.ShardCounts {
		for _, batch := range cfg.BatchSizes {
			for _, native := range cfg.NativeBatchVerify {
				key := fmt.Sprintf("%d/%d/%v", shards, batch, native)
				if f.seen[key] == 0 {
					t.Errorf("configuration %s never reached the scheme", key)
				}
			}
		}
	}
}

// TestPointsRecordTheConfigurationTheyWereMeasuredAt pins the other half: a
// swept dimension that is not recorded per point cannot be separated afterwards,
// so two arms would be plotted as one curve.
func TestPointsRecordTheConfigurationTheyWereMeasuredAt(t *testing.T) {
	cfg := Config{
		ConcurrencyLevels: []int{1},
		Repetitions:       1,
		ShardCounts:       []int{2},
		BatchSizes:        []int{4},
		NativeBatchVerify: []bool{true},
	}

	res, err := Run(context.Background(), cfg, []scheme.Scheme{newTunableScheme()}, fakeTrace(4))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Points) != 1 {
		t.Fatalf("got %d points, want 1", len(res.Points))
	}

	p := res.Points[0]
	if p.ShardCount != 2 {
		t.Errorf("ShardCount = %d, want 2", p.ShardCount)
	}
	if p.BatchSize != 4 {
		t.Errorf("BatchSize = %d, want 4", p.BatchSize)
	}
	if !p.NativeBatchVerify {
		t.Error("NativeBatchVerify = false, want true")
	}
	if p.Ablation == nil {
		t.Fatal("Ablation not recorded")
	}
	if !p.Ablation.Sharding || !p.Ablation.Batching {
		t.Errorf("Ablation = %+v, want both arms on at shards=2 batch=4", *p.Ablation)
	}
}

// TestBatchSizeOneIsTheDisabledArm pins the convention the config relies on:
// B=1 is batching OFF, whatever the verification mode says. This is the exact
// condition that made the two native_batch_verify arms identical.
func TestBatchSizeOneIsTheDisabledArm(t *testing.T) {
	cfg := Config{
		ConcurrencyLevels: []int{1},
		Repetitions:       1,
		ShardCounts:       []int{1},
		BatchSizes:        []int{1},
		NativeBatchVerify: []bool{true},
	}

	res, err := Run(context.Background(), cfg, []scheme.Scheme{newTunableScheme()}, fakeTrace(4))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Points[0].Ablation.Batching {
		t.Error("Ablation.Batching true at B=1; a batch of one never aggregates, " +
			"so recording it as batching-on would label the disabled arm as enabled")
	}
}
