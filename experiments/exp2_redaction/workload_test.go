package exp2_redaction

import "testing"

// workloadsFor decides which workload sizes an arm measures. It is the x-axis
// of the Exp 2 figure, and it carries the cost policy: sweeping it on every arm
// would multiply the whole run by len(WorkloadSizes), so only the headline arm
// gets the sweep. Both halves of that are pinned here, because a regression in
// either is silent — the figure would still draw, with one point per curve or
// with a run that takes days.

func TestWorkloadsForSweepsOnlyTheHeadlineArm(t *testing.T) {
	cfg := Config{WorkloadSizes: []int{100, 250, 500}}

	got := workloadsFor(cfg, 500, true)
	want := []int{100, 250, 500}
	if !equalInts(got, want) {
		t.Errorf("headline arm: got %v, want the full sweep %v", got, want)
	}

	// Every other arm runs the full trace once. Sweeping here is what turns a
	// 12-hour run into a 100-hour one.
	if got := workloadsFor(cfg, 500, false); !equalInts(got, []int{500}) {
		t.Errorf("non-headline arm: got %v, want [500] — the workload axis must "+
			"not multiply the Delta_R and conflict sweeps", got)
	}
}

func TestWorkloadsForDefaultsToTheWholeTrace(t *testing.T) {
	if got := workloadsFor(Config{}, 320, true); !equalInts(got, []int{320}) {
		t.Errorf("unconfigured: got %v, want [320]", got)
	}
}

func TestWorkloadsForClampsAndDeduplicates(t *testing.T) {
	// A size longer than the trace is the same measurement as the whole trace.
	// Clamping can therefore produce duplicates, and a duplicate would be
	// measured twice and plotted as one point with twice the samples.
	cfg := Config{WorkloadSizes: []int{50, 200, 400}}
	got := workloadsFor(cfg, 200, true)
	if !equalInts(got, []int{50, 200}) {
		t.Errorf("got %v, want [50 200]: sizes above the trace clamp to it and "+
			"the resulting duplicate is dropped", got)
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
