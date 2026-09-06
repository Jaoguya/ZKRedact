package exp3_audit

import (
	"context"
	"fmt"
	"testing"

	"zkredact/pkg/scheme"
)

// The same guard as experiments/exp1_verification/runner_test.go, for the same
// reason. A sweep declared in config, plumbed through Config, and then not read
// by the loop has shipped four times in this project — shard counts, the
// ablation grid, proof batch size, and arity_q. None of them crashed.
//
// arity_q is different from the others in one way worth stating: it is a
// SETUP-time parameter, so the runner re-runs Setup rather than reconfiguring
// in place. That makes it easier, not harder, to forget.

type fakeScheme struct {
	name  string
	setup []map[string]any // every override map Setup was called with
}

func (f *fakeScheme) Name() string { return f.name }
func (f *fakeScheme) Capabilities() scheme.Capabilities {
	return scheme.Capabilities{LedgerIndependentAudit: true}
}
func (f *fakeScheme) Setup(context.Context, scheme.SetupParams) error { return nil }
func (f *fakeScheme) Authorize(_ context.Context, req *scheme.Request) (*scheme.Authorization, error) {
	return &scheme.Authorization{Request: req, Granted: true}, nil
}
func (f *fakeScheme) Redact(context.Context, []*scheme.Authorization) (*scheme.RedactionResult, error) {
	return &scheme.RedactionResult{}, nil
}
func (f *fakeScheme) Audit(context.Context, *scheme.AuditQuery) (*scheme.AuditResult, error) {
	return &scheme.AuditResult{
		Semantics: scheme.SemanticsLedgerIntegrity,
		Verified:  true,
		// Constant, so the scaling classifier sees a flat curve rather than
		// noise it might read as linear.
		BlocksTraversed: 4,
		EvidenceBytes:   256,
	}, nil
}
func (f *fakeScheme) Teardown(context.Context) error { return nil }

// TestRunSweepsEverySetupCombination asserts that every combination SetupSweeps
// offers actually reaches Prepare and is recorded on the points.
func TestRunSweepsEverySetupCombination(t *testing.T) {
	f := &fakeScheme{name: "fake"}

	sweeps := []map[string]any{
		{"arity_q": 2, "challenged_blocks": 300},
		{"arity_q": 2, "challenged_blocks": 460},
		{"arity_q": 5, "challenged_blocks": 300},
		{"arity_q": 5, "challenged_blocks": 460},
	}

	var prepared []map[string]any
	cfg := Config{
		LedgerSizes:   []int{100, 1000},
		HistoryDepths: []int{1},
		Repetitions:   1,
		AuditorID:     "auditor",
		SetupSweeps: func(scheme.Scheme) ([]map[string]any, error) {
			return sweeps, nil
		},
		Prepare: func(_ context.Context, _ scheme.Scheme, _ int, overrides map[string]any) (map[int][]string, error) {
			prepared = append(prepared, overrides)
			return map[int][]string{1: {"tx-1"}}, nil
		},
	}

	res, err := Run(context.Background(), cfg, []scheme.Scheme{f})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// 4 setup combinations x 2 ledger sizes x 1 depth x 1 repetition.
	if want := 8; len(res.Points) != want {
		t.Errorf("got %d points, want %d — a declared setup sweep is not being executed",
			len(res.Points), want)
	}

	// Every combination must have reached Prepare.
	for _, sw := range sweeps {
		found := false
		for _, got := range prepared {
			if fmt.Sprint(got) == fmt.Sprint(sw) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("setup combination %v never reached Prepare", sw)
		}
	}

	// And be recorded, or the curves cannot be separated afterwards.
	for i, p := range res.Points {
		if p.SetupParams == nil {
			t.Errorf("point %d records no setup parameters", i)
		}
	}
}

// TestSchemeWithoutSetupKnobsIsMeasuredOnce is the other half. Measuring a
// scheme repeatedly under parameters it does not have would multiply its points
// and read as variance.
func TestSchemeWithoutSetupKnobsIsMeasuredOnce(t *testing.T) {
	f := &fakeScheme{name: "plain"}

	calls := 0
	cfg := Config{
		LedgerSizes:   []int{100, 1000},
		HistoryDepths: []int{1},
		Repetitions:   1,
		SetupSweeps: func(scheme.Scheme) ([]map[string]any, error) {
			return []map[string]any{nil}, nil
		},
		Prepare: func(_ context.Context, _ scheme.Scheme, _ int, overrides map[string]any) (map[int][]string, error) {
			calls++
			if overrides != nil {
				t.Errorf("a scheme with no setup knobs was given overrides %v", overrides)
			}
			return map[int][]string{1: {"tx-1"}}, nil
		},
	}

	res, err := Run(context.Background(), cfg, []scheme.Scheme{f})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if want := 2; len(res.Points) != want {
		t.Errorf("got %d points, want %d (one per ledger size)", len(res.Points), want)
	}
	if calls != 2 {
		t.Errorf("Prepare called %d times, want 2", calls)
	}
}

// TestRunWithoutSetupSweepsStillWorks keeps the hook optional, so a caller that
// has no setup sweeps is not forced to supply one.
func TestRunWithoutSetupSweepsStillWorks(t *testing.T) {
	f := &fakeScheme{name: "plain"}
	cfg := Config{
		LedgerSizes:   []int{100, 1000},
		HistoryDepths: []int{1},
		Repetitions:   1,
		Prepare: func(_ context.Context, _ scheme.Scheme, _ int, _ map[string]any) (map[int][]string, error) {
			return map[int][]string{1: {"tx-1"}}, nil
		},
	}
	res, err := Run(context.Background(), cfg, []scheme.Scheme{f})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Points) != 2 {
		t.Errorf("got %d points, want 2", len(res.Points))
	}
}
