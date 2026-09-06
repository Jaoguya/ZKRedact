package main

import (
	"bytes"
	"encoding/json"
	"fmt"
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
	for _, p := range r.Points {
		dims := map[string]string{}
		if p.ShardCount > 0 {
			dims["shards"] = strconv.Itoa(p.ShardCount)
		}
		if p.BatchSize > 0 {
			dims["batch"] = strconv.Itoa(p.BatchSize)
		}
		if p.Ablation != nil {
			dims["native_verify"] = strconv.FormatBool(p.NativeBatchVerify)
		}
		tp.Add(p.Scheme, dims, float64(p.Concurrency), p.Throughput)
		lat.Add(p.Scheme, dims, float64(p.Concurrency), float64(p.Latency.P50)/1e6)
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
			},
		},
		{
			Name:   "exp1-latency-p50",
			Title:  "Exp 1 — Median authorization latency vs concurrency",
			XLabel: "concurrency (closed loop)",
			YLabel: "p50 latency (ms)",
			XLog:   true, YLog: true,
			Series: lat.Series(),
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
	for _, p := range r.Points {
		dims := merge(
			dimsFromSetupParams(p.SetupParams),
			map[string]string{
				"wait_ms":  strconv.Itoa(p.WaitBoundMS),
				"conflict": strconv.FormatFloat(p.ConflictRatio, 'g', -1, 64),
			},
		)
		x := float64(p.BatchSize)
		cost.Add(p.Scheme, dims, x, float64(p.CostPerRequest)/1e6)
		share.Add(p.Scheme, dims, x, p.CryptoShare)
		stale.Add(p.Scheme, dims, x, p.StaleExclusionRate)
	}

	return []chart{
		{
			Name:   "exp2-cost-per-request",
			Title:  "Exp 2 — Cost per redaction vs batch size",
			XLabel: "B_R (redactions per batch)",
			YLabel: "cost per request (ms)",
			XLog:   true, YLog: true,
			Series: cost.Series(),
			Caveats: []string{
				"B_R=1 is the batching-disabled arm and the point every baseline sits at.",
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
	}, nil
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
	for _, p := range r.Points {
		dims := merge(
			dimsFromSetupParams(p.SetupParams),
			map[string]string{"depth": strconv.Itoa(p.HistoryDepth)},
		)
		x := float64(p.LedgerSize)
		cost.Add(p.Scheme, dims, x, float64(p.TotalTime)/1e6)
		bytes.Add(p.Scheme, dims, x, float64(p.EvidenceBytes))
	}

	caveats := []string{
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
