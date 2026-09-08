package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	exp1 "zkredact/experiments/exp1_verification"
	exp2 "zkredact/experiments/exp2_redaction"
	exp3 "zkredact/experiments/exp3_audit"
)

// Loading results, and why the experiment packages' own types are used.
//
// The runners define the Point structs and their JSON tags. Re-declaring them
// here would create a second schema that drifts from the first, and a drifted
// schema does not error — it silently reads zero for a field that was renamed,
// so a plot would show a sweep collapsed onto x=0. pkg/config's own doc comment
// makes the same argument about the config schema.

// document is one results file. Result stays raw until the experiment is known.
type document struct {
	Metadata struct {
		Experiment string `json:"experiment"`
		Seed       int64  `json:"seed"`
		Partial    any    `json:"partial_comparison,omitempty"`
	} `json:"metadata"`
	Result json.RawMessage `json:"result"`
}

// chart is one rendered figure.
type chart struct {
	Name    string
	Title   string
	XLabel  string
	YLabel  string
	XLog    bool
	YLog    bool
	Series  []Series
	Caveats []string
}

// loadAll reads every results file in dir and builds the charts.
//
// Files are processed newest-last so that when several runs of one experiment
// are present the most recent wins. Mixing runs would pool measurements taken
// under different configs and different code.
func loadAll(dir string) ([]chart, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no results files in %s", dir)
	}
	sort.Strings(paths) // names carry a timestamp, so this is chronological

	// Latest document per experiment.
	latest := make(map[string]document)
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", p, err)
		}
		// A UTF-8 BOM is an encoding artefact, not corruption — Windows editors
		// and PowerShell's Out-File both add one — and encoding/json rejects it
		// with a message that reads like a malformed file. Strip it rather than
		// send someone hunting a parse error in a document that is fine.
		raw = bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})

		var doc document
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("parse %s: %w", p, err)
		}
		if doc.Metadata.Experiment == "" {
			return nil, fmt.Errorf("%s has no metadata.experiment", p)
		}
		latest[doc.Metadata.Experiment] = doc
	}

	var charts []chart
	for _, name := range sortedKeys(latest) {
		doc := latest[name]
		var (
			cs  []chart
			err error
		)
		switch name {
		case "exp1_verification":
			cs, err = chartsExp1(doc)
		case "exp2_redaction":
			cs, err = chartsExp2(doc)
		case "exp3_audit":
			cs, err = chartsExp3(doc)
		default:
			return nil, fmt.Errorf("unknown experiment %q", name)
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		// A partial comparison must never be read as a comparison. The runner
		// records the flag; the chart repeats it where a reader will see it.
		if doc.Metadata.Partial != nil {
			for i := range cs {
				cs[i].Caveats = append(cs[i].Caveats,
					"PARTIAL COMPARISON — not all systems were run; this is not a comparison")
			}
		}
		charts = append(charts, cs...)
	}
	return charts, nil
}

// chartsExp1 plots throughput against concurrency.
//
// Every point carries a shard count, a batch size and a verification mode. All
// three are series dimensions: pooling them would average the sharded and
// unsharded arms into a curve neither one produced, which is exactly what the
// ablation grid exists to keep apart.
// ONE LINE PER SYSTEM. A comparison figure compares systems, not settings.
//
// ZK-Redact's sweep crosses 7 shard counts x 7 batch sizes x 2 verification
// modes, and drawing them all put 98 curves for one system against 1 each for
// the baselines — 101 series, unreadable, and a category error besides: a
// reader asking "how does this compare to prior work" is not asking about our
// batch size. The headline figures carry four curves, one per system.
//
// ZK-Redact's curve is the COMPLETE system: sharding and batching at the top of
// their sweeps with native batch verification on. That is the scheme as
// proposed, and it is what a baseline comparison is a comparison against.
// Selecting a mid-sweep point would report a system nobody designed.
//
// The ablation is a different question — which component contributes what — and
// it gets its own figure rather than crowding this one.
const (
	exp1FullShards = 64
	exp1FullBatch  = 64
)

// headlineArm reports whether a point belongs on a four-curve comparison.
func headlineArm(shards, batch int, native, hasAblation bool) bool {
	if !hasAblation && shards == 0 && batch == 0 {
		return true // a baseline: no knobs, one curve
	}
	return shards == exp1FullShards && batch == exp1FullBatch && native
}

// ablationArm names the four cells the grid exists to separate, for the figure
// that reports them. config/experiment.yaml: "Sharding and batching must be
// separable, or the Phase 3 independence claim cannot be evaluated at all."
func ablationArm(shards, batch int, native bool) (string, bool) {
	if native {
		return "", false // the ablation is about the two knobs, not the third
	}
	switch {
	case shards == 1 && batch == 1:
		return "neither", true
	case shards == exp1FullShards && batch == 1:
		return "sharding only", true
	case shards == 1 && batch == exp1FullBatch:
		return "batching only", true
	case shards == exp1FullShards && batch == exp1FullBatch:
		return "both", true
	}
	return "", false
}

func chartsExp1(doc document) ([]chart, error) {
	var r exp1.Result
	if err := json.Unmarshal(doc.Result, &r); err != nil {
		return nil, err
	}
	if len(r.Points) == 0 {
		return nil, fmt.Errorf("no points")
	}

	tp := NewCollector()
	lat := NewCollector()
	abl := NewCollector()
	for _, p := range r.Points {
		if headlineArm(p.ShardCount, p.BatchSize, p.NativeBatchVerify, p.Ablation != nil) {
			tp.Add(p.Scheme, map[string]string{}, float64(p.Concurrency), p.Throughput)
			lat.Add(p.Scheme, map[string]string{}, float64(p.Concurrency), float64(p.Latency.P50)/1e6)
		}
		if p.Scheme == "zkredact" {
			if arm, ok := ablationArm(p.ShardCount, p.BatchSize, p.NativeBatchVerify); ok {
				abl.Add(p.Scheme, map[string]string{"arm": arm}, float64(p.Concurrency), p.Throughput)
			}
		}
	}

	return []chart{
		{
			Name:   "exp1-throughput",
			Title:  "Exp 1 — Verification throughput vs concurrency",
			XLabel: "concurrency (closed loop)",
			YLabel: "authorizations / second",
			XLog:   true, YLog: true,
			Series: tp.Series(),
			Caveats: []string{
				"Log-log. The crossover is the finding: the trapdoor baselines lead " +
					"at low load because their authorization is a key check, not a protocol.",
				"One curve per system. ZK-Redact is the complete scheme — sharding " +
					"and batching at 64, native batch verification on; see " +
					"exp1-ablation for what each contributes.",
			},
		},
		{
			Name:   "exp1-latency-p50",
			Title:  "Exp 1 — Median authorization latency vs concurrency",
			XLabel: "concurrency (closed loop)",
			YLabel: "p50 latency (ms)",
			XLog:   true, YLog: true,
			Series: lat.Series(),
			Caveats: []string{
				"ZK-Redact at its full configuration; the ablation is reported separately.",
			},
		},
		{
			Name:   "exp1-ablation",
			Title:  "Exp 1 — ZK-Redact ablation: sharding and batching separated",
			XLabel: "concurrency (closed loop)",
			YLabel: "authorizations / second",
			XLog:   true, YLog: true,
			Series: abl.Series(),
			Caveats: []string{
				"ZK-Redact only. The baselines have neither knob, so they appear " +
					"on the comparison figure rather than here.",
				"On means the top of each sweep, 64. The claim under test is that " +
					"the mechanisms scale, which a mid-sweep point would not address.",
			},
		},
	}, nil
}

// chartsExp2 plots the cost decomposition against batch size.
//
// Two separate charts, not one stacked total. The experiment's whole question is
// which PART of the cost batching amortises: CryptoTime is per-request and
// cannot be amortised, LedgerTime is per-batch and is the only part that can.
// A single total would make that unanswerable, which the exp2 package comment
// says in as many words.
func chartsExp2(doc document) ([]chart, error) {
	var r exp2.Result
	if err := json.Unmarshal(doc.Result, &r); err != nil {
		return nil, err
	}
	if len(r.Points) == 0 {
		return nil, fmt.Errorf("no points")
	}

	cost := NewCollector()
	share := NewCollector()
	stale := NewCollector()
	wait := NewCollector()
	conf := NewCollector()

	// The headline figure of Exp 2. x is the workload size, not the batch size:
	// per-request overhead is shown converging as the workload grows. Only the
	// plotted batch sizes appear, because the runner sweeps the workload axis
	// on the headline arm alone and a curve per B_R would otherwise crowd four
	// systems off the figure.
	overhead := NewCollector()
	plottedBR := map[int]bool{1: true, 8: true, 64: true}

	// The headline holds the two knobs FIXED, for the same reason Exp 1 does:
	// a comparison figure compares systems. wait_bound takes the shortest
	// configured value and conflict_ratio takes 0.0, which config/experiment.yaml
	// describes as isolating the fully independent path — and which is the
	// baseline the optimal batch size is computed at. The sweeps over each knob
	// are reported beside it.
	// The wait bound is read from the schemes that HAVE one. A baseline does not
	// batch and records 0, so taking the minimum over every point selected 0 and
	// then matched no ZK-Redact point at all — three curves where there should
	// have been four, and an empty conflict figure.
	headWait, headRatio := math.MaxInt32, math.MaxFloat64
	for _, p := range r.Points {
		if p.WaitBoundMS > 0 && p.WaitBoundMS < headWait {
			headWait = p.WaitBoundMS
		}
		if p.ConflictRatio < headRatio {
			headRatio = p.ConflictRatio
		}
	}
	if headWait == math.MaxInt32 {
		headWait = 0
	}

	// batches reports whether this point comes from a scheme with a wait bound.
	batches := func(p exp2.Point) bool { return p.WaitBoundMS > 0 }

	for _, p := range r.Points {
		x := float64(p.BatchSize)
		if (!batches(p) || p.WaitBoundMS == headWait) && p.ConflictRatio == headRatio {
			dims := map[string]string{}
			cost.Add(p.Scheme, dims, x, float64(p.CostPerRequest)/1e6)
			share.Add(p.Scheme, dims, x, p.CryptoShare)
			stale.Add(p.Scheme, dims, x, p.StaleExclusionRate)
		}
		if p.WorkloadSize > 0 &&
			(!batches(p) || p.WaitBoundMS == headWait) &&
			p.ConflictRatio == headRatio &&
			(plottedBR[p.BatchSize] || !batches(p)) {
			dims := map[string]string{}
			if batches(p) {
				dims["B_R"] = strconv.Itoa(p.BatchSize)
			}
			overhead.Add(p.Scheme, dims, float64(p.WorkloadSize),
				float64(p.CostPerRequest)/1e6)
		}
		if p.Scheme == "zkredact" {
			if p.ConflictRatio == headRatio {
				wait.Add(p.Scheme, map[string]string{"wait_ms": strconv.Itoa(p.WaitBoundMS)},
					x, p.StaleExclusionRate)
			}
			if !batches(p) || p.WaitBoundMS == headWait {
				conf.Add(p.Scheme, map[string]string{"conflict": fmtRatio(p.ConflictRatio)},
					x, float64(p.CostPerRequest)/1e6)
			}
		}
	}

	return []chart{
		{
			Name:   "exp2-overhead",
			Title:  "Exp 2 — Average processing overhead vs workload size",
			XLabel: "number of redaction requests",
			YLabel: "average processing overhead (ms/request)",
			XLog:   true, YLog: true,
			Series: overhead.Series(),
			Caveats: []string{
				"ZK-Redact at B_R in {1, 8, 64}; the baselines do not batch and " +
					"sit at B_R=1 by construction.",
				"Wait bound and conflict ratio are held at the headline arm, " +
					"which is the only arm the workload axis is swept on.",
			},
		},
		{
			Name:   "exp2-cost-per-request",
			Title:  "Exp 2 — Cost per redaction vs batch size",
			XLabel: "B_R (redactions per batch)",
			YLabel: "cost per request (ms)",
			XLog:   true, YLog: true,
			Series: cost.Series(),
			Caveats: []string{
				"B_R=1 is the batching-disabled arm and the point every baseline sits at.",
				"One curve per system. The wait bound and conflict ratio are held " +
					"at their lowest configured values; both are swept in their own " +
					"figures.",
			},
		},
		{
			Name:   "exp2-crypto-share",
			Title:  "Exp 2 — Share of cost that is per-request cryptography",
			XLabel: "B_R (redactions per batch)",
			YLabel: "CryptoTime / TotalTime",
			XLog:   true,
			Series: share.Series(),
			Caveats: []string{
				"Rising toward 1 means batching has amortised what it can: the " +
					"remainder is the irreducible per-request crypto floor.",
			},
		},
		{
			Name:   "exp2-staleness",
			Title:  "Exp 2 — Staleness exclusion vs batch size",
			XLabel: "B_R (redactions per batch)",
			YLabel: "fraction excluded on freshness",
			XLog:   true,
			Series: stale.Series(),
			Caveats: []string{
				"The price of amortisation. Plotted beside the cost curve because " +
					"an optimal batch size is only meaningful with both.",
			},
		},
		{
			Name:   "exp2-wait-bound",
			Title:  "Exp 2 — Staleness vs batch size, by wait bound",
			XLabel: "B_R (redactions per batch)",
			YLabel: "fraction excluded on freshness",
			XLog:   true,
			Series: wait.Series(),
			Caveats: []string{
				"ZK-Redact only; no baseline batches, so none has a wait bound.",
				"Delta_R is the staleness knob: a longer wait fills a batch more " +
					"often and leaves each request in it longer.",
			},
		},
		{
			Name:   "exp2-conflict",
			Title:  "Exp 2 — Cost per redaction vs batch size, by conflict ratio",
			XLabel: "B_R (redactions per batch)",
			YLabel: "cost per request (ms)",
			XLog:   true, YLog: true,
			Series: conf.Series(),
			Caveats: []string{
				"ZK-Redact only. Same-target requests serialize, so the conflict " +
					"ratio is what decides how much of a batch can proceed at once.",
			},
		},
	}, nil
}

// fmtRatio renders a conflict ratio for a legend without trailing noise.
func fmtRatio(r float64) string {
	return strconv.FormatFloat(r, 'g', -1, 64)
}

// chartsExp3 plots audit cost against ledger size at fixed history depth.
//
// History depth is a series dimension, not an averaged-over one: the experiment
// holds it FIXED and grows the ledger, so pooling depths would destroy the
// comparison the chart exists to make.
func chartsExp3(doc document) ([]chart, error) {
	var r exp3.Result
	if err := json.Unmarshal(doc.Result, &r); err != nil {
		return nil, err
	}
	if len(r.Points) == 0 {
		return nil, fmt.Errorf("no points")
	}

	cost := NewCollector()
	bytes := NewCollector()
	depth := NewCollector()

	// The headline figure of Exp 3. x is the history depth and each scheme is
	// drawn once per ledger size, so the SLOPE of a curve is the scheme's
	// dependence on depth and the GAP between its pair is its dependence on
	// ledger size. A ledger-independent audit therefore appears as coincident
	// curves, which is the claim being tested rather than an inference from a
	// fitted scaling class.
	//
	// Verification time, not total: retrieval is a transport cost and is
	// reported separately, so folding it in would move the curves for a reason
	// unrelated to the audit algorithm.
	audit := NewCollector()

	// The headline holds history depth FIXED and grows the ledger, which is
	// what config/experiment.yaml calls the headline plot and what the scaling
	// class is read from. Depth is a second experiment, not a second dimension
	// of this one, so it gets its own figure rather than multiplying the curves
	// by five. Setup sweeps are held at their first configured value for the
	// same reason: an arity-2 tree and an arity-10 tree are two systems.
	headDepth := math.MaxInt32
	firstSetup := map[string]map[string]string{}
	for _, p := range r.Points {
		if p.HistoryDepth < headDepth {
			headDepth = p.HistoryDepth
		}
	}
	for _, p := range r.Points {
		d := dimsFromSetupParams(p.SetupParams)
		if _, seen := firstSetup[p.Scheme]; !seen && len(d) > 0 {
			firstSetup[p.Scheme] = d
		}
	}
	sameSetup := func(p exp3.Point) bool {
		want, ok := firstSetup[p.Scheme]
		if !ok {
			return true // this scheme has no setup sweep
		}
		got := dimsFromSetupParams(p.SetupParams)
		for k, v := range want {
			if got[k] != v {
				return false
			}
		}
		return true
	}

	for _, p := range r.Points {
		if sameSetup(p) {
			audit.Add(p.Scheme, map[string]string{"L": strconv.Itoa(p.LedgerSize)},
				float64(p.HistoryDepth), float64(p.VerificationTime)/1e6)
		}
		x := float64(p.LedgerSize)
		if p.HistoryDepth == headDepth && sameSetup(p) {
			cost.Add(p.Scheme, map[string]string{}, x, float64(p.TotalTime)/1e6)
			bytes.Add(p.Scheme, map[string]string{}, x, float64(p.EvidenceBytes))
		}
		if sameSetup(p) {
			depth.Add(p.Scheme, map[string]string{"depth": strconv.Itoa(p.HistoryDepth)},
				x, float64(p.TotalTime)/1e6)
		}
	}

	caveats := []string{
		fmt.Sprintf("One curve per system, at history depth %d and the first "+
			"configured setup sweep. Depth is swept in exp3-history-depth.", headDepth),
		"Auditor authorization is excluded from these totals and reported " +
			"separately: no baseline has that step, so folding it in would " +
			"penalise ZK-Redact for a capability the others lack.",
		"The schemes answer DIFFERENT questions — VRBC audits ledger integrity, " +
			"ZK-Redact retrieves a transaction's history. What is compared is how " +
			"cost SCALES, not feature equivalence.",
	}
	// The scaling classifier's own verdict belongs on the figure: a scheme that
	// declares ledger-independent audit and then scales linearly is
	// contradicting itself, and that must not be left for a reader to notice.
	for _, name := range sortedScaling(r.LedgerScaling) {
		sc := r.LedgerScaling[name]
		if !sc.ClaimHolds {
			caveats = append(caveats, fmt.Sprintf(
				"WARNING: %s declares a ledger-independent audit but scaled %s "+
					"(cost x%.2f over ledger x%.0f)", name, sc.Class, sc.CostRatio, sc.SizeRatio))
		}
	}

	return []chart{
		{
			Name:   "exp3-audit",
			Title:  "Exp 3 — Audit verification time vs redaction history depth",
			XLabel: "number of redactions in transaction history",
			YLabel: "audit verification time (ms)",
			XLog:   true, YLog: true,
			Series: audit.Series(),
			Caveats: append([]string{
				"Each scheme is drawn once per ledger size L. The SLOPE is its " +
					"dependence on history depth; the GAP between a scheme's " +
					"curves is its dependence on ledger size.",
				"Coincident curves mean a ledger-independent audit. ZK-Redact's " +
					"pair separating would mean the PAI is not delivering its " +
					"O(nu + log|I|) bound.",
				"Verification only. Retrieval latency and the auditor " +
					"authorization adder are reported separately.",
			}, caveats[1:]...),
		},
		{
			Name:   "exp3-audit-cost",
			Title:  "Exp 3 — Audit cost vs ledger size, at fixed history depth",
			XLabel: "ledger size (blocks)",
			YLabel: "retrieval + verification (ms)",
			XLog:   true, YLog: true,
			Series:  cost.Series(),
			Caveats: caveats,
		},
		{
			Name:   "exp3-evidence-bytes",
			Title:  "Exp 3 — Evidence transferred vs ledger size",
			XLabel: "ledger size (blocks)",
			YLabel: "bytes",
			XLog:   true, YLog: true,
			Series: bytes.Series(),
			Caveats: []string{
				"For full-scan schemes this is the traversed portion of the ledger, " +
					"which is the point of the comparison.",
			},
		},
		{
			Name:   "exp3-history-depth",
			Title:  "Exp 3 — Audit cost vs ledger size, by history depth",
			XLabel: "ledger size (blocks)",
			YLabel: "retrieval + verification (ms)",
			XLog:   true, YLog: true,
			Series: depth.Series(),
			Caveats: []string{
				"Depth is how many times the target transaction has already been " +
					"redacted. Held fixed on the headline figure so the ledger axis " +
					"means what it says; swept here.",
			},
		},
	}, nil
}

func sortedKeys(m map[string]document) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedScaling(m map[string]exp3.ScalingClass) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// csvName is the data file written beside every chart.
func csvName(chartName string) string { return strings.ReplaceAll(chartName, " ", "-") + ".csv" }
