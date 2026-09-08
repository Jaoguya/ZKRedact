package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	exp1 "zkredact/experiments/exp1_verification"
	exp3 "zkredact/experiments/exp3_audit"
	"zkredact/pkg/metrics"
)

// TestRepetitionsArePooledAndOnlyRepetitions is the property this whole command
// rests on. Two points may be averaged only if they differ in nothing but the
// repetition index.
func TestRepetitionsArePooledAndOnlyRepetitions(t *testing.T) {
	c := NewCollector()

	// Same configuration, three repetitions -> one point, N=3.
	for _, y := range []float64{100, 110, 120} {
		c.Add("zkredact", map[string]string{"shards": "16"}, 8, y)
	}
	// A different shard count is a DIFFERENT series, not more repetitions.
	c.Add("zkredact", map[string]string{"shards": "1"}, 8, 500)

	series := c.Series()
	if len(series) != 2 {
		t.Fatalf("got %d series, want 2 — configurations were pooled together", len(series))
	}

	var pooled, alone Series
	for _, s := range series {
		if s.Dims["shards"] == "16" {
			pooled = s
		} else {
			alone = s
		}
	}

	if len(pooled.Points) != 1 || pooled.Points[0].N != 3 {
		t.Fatalf("shards=16: got %d points with N=%v, want 1 point with N=3",
			len(pooled.Points), pooled.Points[0].N)
	}
	if got := pooled.Points[0].Mean; got != 110 {
		t.Errorf("mean = %v, want 110", got)
	}
	if pooled.Points[0].Min != 100 || pooled.Points[0].Max != 120 {
		t.Errorf("spread = [%v, %v], want [100, 120]",
			pooled.Points[0].Min, pooled.Points[0].Max)
	}
	if alone.Points[0].Mean != 500 {
		t.Errorf("the shards=1 point was contaminated: mean = %v, want 500",
			alone.Points[0].Mean)
	}
}

// TestPoolingAcrossArityWouldBeCaught is the failure mode stated in
// aggregate.go, exercised directly: averaging arity 2 with arity 10 yields a
// smooth curve at a value neither configuration measured.
func TestPoolingAcrossArityWouldBeCaught(t *testing.T) {
	c := NewCollector()
	c.Add("ref13_vrbc", map[string]string{"arity_q": "2"}, 1000, 40)
	c.Add("ref13_vrbc", map[string]string{"arity_q": "10"}, 1000, 10)

	series := c.Series()
	if len(series) != 2 {
		t.Fatalf("got %d series, want 2 — the arities were pooled", len(series))
	}
	for _, s := range series {
		if got := s.Points[0].Mean; got == 25 {
			t.Fatal("a series has the average of the two arities (25), which is a " +
				"value neither configuration ever measured")
		}
		if s.Points[0].N != 1 {
			t.Errorf("N = %d, want 1: each arity was measured once", s.Points[0].N)
		}
	}
}

// TestSingleObservationsAreFlagged pins that a lone repetition is not presented
// as though its spread were known.
func TestSingleObservationsAreFlagged(t *testing.T) {
	c := NewCollector()
	c.Add("s", nil, 1, 10)
	c.Add("s", nil, 2, 20)
	c.Add("s", nil, 2, 22)

	s := c.Series()[0]
	if got := s.SingleObservationPoints(); got != 1 {
		t.Errorf("SingleObservationPoints = %d, want 1", got)
	}
	for _, p := range s.Points {
		if p.N == 1 && p.CV() != 0 {
			t.Error("a single observation reported a non-zero spread")
		}
	}
}

// TestLabelIsStable keeps legends and CSV rows from reordering between runs,
// which would make two identical figures look different.
func TestLabelIsStable(t *testing.T) {
	a := Series{Scheme: "x", Dims: map[string]string{"b": "2", "a": "1"}}
	b := Series{Scheme: "x", Dims: map[string]string{"a": "1", "b": "2"}}
	if a.Label() != b.Label() {
		t.Errorf("labels differ by map order: %q vs %q", a.Label(), b.Label())
	}
	if !strings.Contains(a.Label(), "a=1") || !strings.Contains(a.Label(), "b=2") {
		t.Errorf("label %q does not carry its dimensions", a.Label())
	}
}

// --- end to end ------------------------------------------------------------

func writeDoc(t *testing.T, dir, name string, experiment string, result any) {
	t.Helper()
	doc := map[string]any{
		"metadata": map[string]any{"experiment": experiment, "seed": 1},
		"result":   result,
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestRunProducesFiguresAndData is the end-to-end check: results in, SVG and
// CSV out, with the CSV carrying the numbers behind the picture.
func TestRunProducesFiguresAndData(t *testing.T) {
	in, out := t.TempDir(), t.TempDir()

	r1 := exp1.Result{
		SaturationPoint: map[string]int{"zkredact": 64},
		Points: []exp1.Point{
			// The headline figure draws the COMPLETE system, so the fixture has
			// to supply it: shards and batch at 64 with native verification on.
			// Points at 1/1 are the ablation's disabled cell and appear on
			// exp1-ablation instead, which is what this fixture used to hold
			// exclusively — leaving the comparison figure with no ZK-Redact at all.
			{Scheme: "zkredact", Concurrency: 1, ShardCount: 64, BatchSize: 64,
				NativeBatchVerify: true, Throughput: 100,
				Latency: metrics.Summary{P50: 1_000_000}, Repetition: 0},
			{Scheme: "zkredact", Concurrency: 1, ShardCount: 64, BatchSize: 64,
				NativeBatchVerify: true, Throughput: 120,
				Latency: metrics.Summary{P50: 1_100_000}, Repetition: 1},
			{Scheme: "zkredact", Concurrency: 8, ShardCount: 64, BatchSize: 64,
				NativeBatchVerify: true, Throughput: 800,
				Latency: metrics.Summary{P50: 2_000_000}, Repetition: 0},
			{Scheme: "zkredact", Concurrency: 1, ShardCount: 1, BatchSize: 1, Throughput: 60,
				Latency: metrics.Summary{P50: 1_500_000}, Repetition: 0},
			{Scheme: "ref22_shen", Concurrency: 1, Throughput: 9000,
				Latency: metrics.Summary{P50: 100}, Repetition: 0},
			{Scheme: "ref22_shen", Concurrency: 8, Throughput: 9500,
				Latency: metrics.Summary{P50: 120}, Repetition: 0},
		},
	}
	writeDoc(t, in, "exp1_verification-20260101-000000.json", "exp1_verification", r1)

	r3 := exp3.Result{
		LedgerScaling: map[string]exp3.ScalingClass{
			"ref10_emt": {CostRatio: 9.8, SizeRatio: 10, Class: "linear", ClaimHolds: false},
		},
		Points: []exp3.Point{
			{Scheme: "ref10_emt", LedgerSize: 1000, HistoryDepth: 1, TotalTime: 1_000_000, EvidenceBytes: 100},
			{Scheme: "ref10_emt", LedgerSize: 10000, HistoryDepth: 1, TotalTime: 10_000_000, EvidenceBytes: 1000},
		},
	}
	writeDoc(t, in, "exp3_audit-20260101-000000.json", "exp3_audit", r3)

	if err := run(in, out); err != nil {
		t.Fatalf("run: %v", err)
	}

	for _, name := range []string{
		"exp1-throughput.svg", "exp1-throughput.csv",
		"exp1-latency-p50.svg",
		"exp3-audit-cost.svg", "exp3-audit-cost.csv",
	} {
		p := filepath.Join(out, name)
		st, err := os.Stat(p)
		if err != nil {
			t.Errorf("missing %s", name)
			continue
		}
		if st.Size() == 0 {
			t.Errorf("%s is empty", name)
		}
	}

	// The CSV must carry the aggregation, not just the means.
	raw, err := os.ReadFile(filepath.Join(out, "exp1-throughput.csv"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{"repetitions", "median", "min", "max", "spread_over_mean", "zkredact"} {
		if !strings.Contains(text, want) {
			t.Errorf("CSV does not carry %q", want)
		}
	}
	// Ref[22] — and Ref[13] — are measured in Exp 1 but are NOT on this figure:
	// neither defines a per-request authorization protocol, so their curve
	// prices checking nothing. Their presence here would mean exp1Series had
	// stopped excluding them, which is the whole point of that function.
	for _, absent := range []string{"ref22_shen", "ref13_vrbc"} {
		if strings.Contains(text, absent) {
			t.Errorf("exp1-throughput carries %q; Exp 1 compares ZK-Redact "+
				"against Ref[10] and against itself only", absent)
		}
	}
	// The two-repetition point must show N=2, or repetitions are still not
	// being consumed.
	if !strings.Contains(text, ",2,") {
		t.Error("no pooled point in the CSV; repetitions are not being aggregated")
	}
}

// TestContradictedLedgerClaimIsSurfaced pins that a scheme declaring a
// ledger-independent audit and then scaling linearly is called out ON THE
// FIGURE. Leaving it to a reader to notice is how a wrong claim reaches a paper.
func TestContradictedLedgerClaimIsSurfaced(t *testing.T) {
	in := t.TempDir()
	r3 := exp3.Result{
		LedgerScaling: map[string]exp3.ScalingClass{
			"ref10_emt": {CostRatio: 9.8, SizeRatio: 10, Class: "linear", ClaimHolds: false},
		},
		Points: []exp3.Point{
			{Scheme: "ref10_emt", LedgerSize: 1000, HistoryDepth: 1, TotalTime: 1_000_000},
			{Scheme: "ref10_emt", LedgerSize: 10000, HistoryDepth: 1, TotalTime: 10_000_000},
		},
	}
	writeDoc(t, in, "exp3_audit-20260101-000000.json", "exp3_audit", r3)

	charts, err := loadAll(in)
	if err != nil {
		t.Fatalf("loadAll: %v", err)
	}
	found := false
	for _, c := range charts {
		for _, w := range c.Caveats {
			if strings.Contains(w, "WARNING") && strings.Contains(w, "ref10_emt") {
				found = true
			}
		}
	}
	if !found {
		t.Error("a contradicted ledger-independence claim did not reach the figure")
	}
}

// TestSVGIsWellFormedEnoughToRender is a shape check, not a rendering test.
func TestSVGIsWellFormedEnoughToRender(t *testing.T) {
	c := chart{
		Name: "t", Title: "T", XLabel: "x", YLabel: "y", XLog: true, YLog: true,
		Series: []Series{{
			Scheme: "s",
			Points: []Point{{X: 1, Mean: 10, Min: 9, Max: 11, N: 3}, {X: 10, Mean: 100, N: 1}},
		}},
	}
	svg := renderSVG(c)
	for _, want := range []string{"<svg", "</svg>", "viewBox", "<path", "<circle"} {
		if !strings.Contains(svg, want) {
			t.Errorf("SVG lacks %q", want)
		}
	}
	if strings.Count(svg, "<svg") != 1 {
		t.Error("more than one root element")
	}
}

// TestTitlesAreEscaped keeps a scheme name or label from breaking the document.
func TestTitlesAreEscaped(t *testing.T) {
	c := chart{Name: "t", Title: `a & b <c>`, Series: []Series{{Scheme: "s"}}}
	svg := renderSVG(c)
	if strings.Contains(svg, "<c>") || !strings.Contains(svg, "&amp;") {
		t.Error("title was not escaped into the SVG")
	}
}

// TestEmptyResultsDirIsAnError keeps `make plots` from reporting success when
// there is nothing to plot.
func TestEmptyResultsDirIsAnError(t *testing.T) {
	if _, err := loadAll(t.TempDir()); err == nil {
		t.Error("an empty results directory produced no error")
	}
}
