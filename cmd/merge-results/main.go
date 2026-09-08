// Command merge-results pools sharded result files into one document per
// experiment.
//
// WHY IT EXISTS. A run split across instances writes one file per shard —
// exp1_verification-<stamp>.json from each. cmd/plot keeps only the LATEST
// document per experiment name (cmd/plot/load.go: latest[doc.Metadata.Experiment]
// = doc), which is right for re-runs of the same config and silently wrong for
// shards: twelve files in, one shard plotted, exit code 0, no warning. Measured
// on a real 1,212-point file split into 1,176 + 36: the plot showed 3 series.
//
// WHAT IT REFUSES. Pooling is only meaningful when the shards describe the same
// run. Files that disagree on the seed, the dataset, the code version or the
// resolved config are not shards of one experiment — they are different
// experiments — and merging them would produce a table nobody could reproduce.
// Every such disagreement is an error, never a warning.
//
//	merge-results -in results -out results/merged
//	merge-results -in results -out results/merged -allow-dirty
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// document mirrors results.Document loosely: the parts merging needs typed, the
// rest kept as raw JSON so nothing is lost or reinterpreted on the way through.
type document struct {
	Metadata metadata        `json:"metadata"`
	Result   json.RawMessage `json:"result"`
}

type metadata struct {
	Experiment        string          `json:"experiment"`
	Timestamp         time.Time       `json:"timestamp"`
	Seed              int64           `json:"seed"`
	DatasetID         string          `json:"dataset_id"`
	GitCommit         string          `json:"git_commit"`
	GitDirty          bool            `json:"git_dirty"`
	ConfigPath        string          `json:"config_path"`
	Environment       envFinger       `json:"environment"`
	ResolvedConfig    json.RawMessage `json:"resolved_config,omitempty"`
	PartialComparison []string        `json:"partial_comparison,omitempty"`

	// MergedFrom records the shards a pooled document came from. Absent on a
	// document written by run-experiment, so a reader can always tell a merged
	// result from a single run.
	MergedFrom []string `json:"merged_from,omitempty"`

	// Hosts lists every machine that contributed, one entry per distinct
	// hostname. A single-host run has one, and its absence would hide that a
	// figure pools numbers taken on different machines.
	Hosts []string `json:"hosts,omitempty"`

	// CommitDrift and CommitDriftReason record a pool built from shards that
	// ran at different commits, and why that was judged sound. Absent on a
	// single-commit merge. Present, they are the reader's warning that this
	// figure needs the reason checked before it is believed.
	CommitDrift       []string `json:"commit_drift,omitempty"`
	CommitDriftReason string   `json:"commit_drift_reason,omitempty"`
}

type envFinger struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	NumCPU   int    `json:"num_cpu"`
	GoVer    string `json:"go_version"`
	Hostname string `json:"hostname"`
}

func main() {
	var (
		inDir      = flag.String("in", "results", "directory holding the shard result files")
		outDir     = flag.String("out", "", "directory for merged documents (default <in>/merged)")
		allowDirty = flag.Bool("allow-dirty", false,
			"pool shards recorded from a dirty git tree; the commit no longer identifies the code")
		allowCommits = flag.String("allow-commit-drift", "",
			"pool shards recorded at DIFFERENT commits, giving the reason. Only "+
				"sound when the commits differ in code that took no measurement — "+
				"verify with: git diff <a> <b> -- cmd internal pkg experiments config "+
				"network, and expect it empty. The reason is written into the merged "+
				"document beside the commit list")
	)
	flag.Parse()

	if *outDir == "" {
		*outDir = filepath.Join(*inDir, "merged")
	}

	if err := run(*inDir, *outDir, *allowDirty, *allowCommits); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(inDir, outDir string, allowDirty bool, allowCommits string) error {
	paths, err := filepath.Glob(filepath.Join(inDir, "*.json"))
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return fmt.Errorf("no result files in %s", inDir)
	}
	sort.Strings(paths)

	byExperiment := map[string][]shard{}
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("read %s: %w", p, err)
		}
		// A UTF-8 BOM is an encoding artefact, not corruption; cmd/plot strips
		// one for the same reason.
		raw = bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})

		var doc document
		if err := json.Unmarshal(raw, &doc); err != nil {
			return fmt.Errorf("parse %s: %w", p, err)
		}
		if doc.Metadata.Experiment == "" {
			return fmt.Errorf("%s has no metadata.experiment", p)
		}
		if doc.Metadata.MergedFrom != nil {
			// Merging a merged document would double-count every point it
			// already holds, and the second pass has no way to see that.
			return fmt.Errorf(
				"%s is itself a merged document (metadata.merged_from is set); "+
					"merge the shards, not the merge", p)
		}
		byExperiment[doc.Metadata.Experiment] = append(
			byExperiment[doc.Metadata.Experiment], shard{path: p, doc: doc})
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", outDir, err)
	}

	names := make([]string, 0, len(byExperiment))
	for k := range byExperiment {
		names = append(names, k)
	}
	sort.Strings(names)

	fmt.Printf("merge-results: %d file(s) in %s\n", len(paths), inDir)

	for _, name := range names {
		shards := byExperiment[name]
		merged, err := mergeOne(name, shards, allowDirty, allowCommits)
		if err != nil {
			return err
		}
		out := filepath.Join(outDir, fmt.Sprintf("%s-merged.json", name))
		if err := writeJSON(out, merged); err != nil {
			return err
		}
		points := countPoints(merged.Result)
		fmt.Printf("  %-20s %2d shard(s) -> %d point(s)  %s\n",
			name, len(shards), points, out)
		if len(merged.Metadata.Hosts) > 1 {
			fmt.Printf("      hosts: %s\n", strings.Join(merged.Metadata.Hosts, ", "))
		}
		if len(merged.Metadata.PartialComparison) > 0 {
			fmt.Printf("      systems: %s\n",
				strings.Join(merged.Metadata.PartialComparison, ", "))
		}
	}
	return nil
}

type shard struct {
	path string
	doc  document
}

// mergeOne pools one experiment's shards after checking they describe one run.
func mergeOne(name string, shards []shard, allowDirty bool, allowCommits string) (*document, error) {
	base := shards[0]

	out := base.doc
	out.Metadata.MergedFrom = nil
	hosts := map[string]bool{}
	systems := map[string]bool{}
	commits := map[string]bool{}
	var points []json.RawMessage
	var extras map[string]json.RawMessage

	for _, s := range shards {
		m := s.doc.Metadata

		if !allowDirty && m.GitDirty {
			return nil, fmt.Errorf(
				"%s was recorded from a dirty git tree, so commit %s does not identify "+
					"the code that produced it; pass -allow-dirty to pool it anyway",
				s.path, short(m.GitCommit))
		}

		// Everything below defines the run. A shard disagreeing on any of it is
		// a different experiment wearing the same filename.
		if err := sameString("seed", s.path, base.path,
			fmt.Sprint(base.doc.Metadata.Seed), fmt.Sprint(m.Seed)); err != nil {
			return nil, err
		}
		if err := sameString("dataset_id", s.path, base.path,
			base.doc.Metadata.DatasetID, m.DatasetID); err != nil {
			return nil, err
		}
		if allowCommits == "" {
			if err := sameString("git_commit", s.path, base.path,
				base.doc.Metadata.GitCommit, m.GitCommit); err != nil {
				return nil, err
			}
		} else {
			commits[m.GitCommit] = true
		}
		if !bytes.Equal(base.doc.Metadata.ResolvedConfig, m.ResolvedConfig) {
			return nil, fmt.Errorf(
				"%s and %s carry different resolved configs, so their numbers describe "+
					"different parameters; they cannot be pooled",
				base.path, s.path)
		}

		// The machine may differ — that is the point of sharding — but only in
		// its name. Different core counts or architectures make absolute
		// numbers incomparable, which pkg/results states outright.
		if err := sameEnv(base.path, s.path, base.doc.Metadata.Environment, m.Environment); err != nil {
			return nil, err
		}
		hosts[m.Environment.Hostname] = true
		for _, sys := range m.PartialComparison {
			systems[sys] = true
		}

		ps, rest, err := splitResult(s.doc.Result)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.path, err)
		}
		points = append(points, ps...)
		if extras, err = mergeExtras(extras, rest, s.path); err != nil {
			return nil, err
		}
	}

	if err := checkSweepIsComplete(name, points); err != nil {
		return nil, err
	}
	recomputeSaturation(name, points, extras)

	out.Metadata.Hosts = sortedKeys(hosts)
	out.Metadata.PartialComparison = sortedKeys(systems)
	out.Metadata.MergedFrom = shardPaths(shards)
	if allowCommits != "" && len(commits) > 1 {
		out.Metadata.CommitDrift = sortedKeys(commits)
		out.Metadata.CommitDriftReason = allowCommits
	}
	// The pooled document is as new as its newest shard: a reader sorting by
	// timestamp must not see a merge as older than a file it contains.
	out.Metadata.Timestamp = newest(shards)

	res, err := rebuildResult(points, extras)
	if err != nil {
		return nil, err
	}
	out.Result = res
	return &out, nil
}

// checkSweepIsComplete enforces, on the POOLED result, what a single run
// enforces on itself.
//
// experiments/exp1_verification/runner.go refuses a sweep that does not start
// at concurrency 1: that is where the trapdoor baselines legitimately win, and
// a plot without it is selection rather than measurement. Sharding by
// concurrency (-levels) suspends that check per process, so it has to land
// here — otherwise splitting the sweep across hosts would quietly buy an
// exemption from the rule the experiment depends on.
func checkSweepIsComplete(experiment string, points []json.RawMessage) error {
	if !strings.HasPrefix(experiment, "exp1") {
		return nil
	}
	seen := map[float64]bool{}
	for _, raw := range points {
		var p struct {
			Concurrency *float64 `json:"concurrency"`
		}
		if err := json.Unmarshal(raw, &p); err != nil || p.Concurrency == nil {
			continue
		}
		seen[*p.Concurrency] = true
	}
	if len(seen) == 0 {
		return nil // not a concurrency sweep; nothing to check
	}
	if !seen[1] {
		return fmt.Errorf(
			"the pooled %s sweep has no concurrency 1 point; that is where the "+
				"trapdoor baselines legitimately win, and reporting the sweep without "+
				"it makes the comparison selective. Merge the c=1 shard too",
			experiment)
	}
	return nil
}

// recomputeSaturation derives Exp 1's saturation point from the POOLED curve.
//
// Each level shard sees a slice of the sweep, so a per-shard verdict is read
// off points it does not have — the c=8+ shard said 32 while the c=1 shard said
// 0. Runners on a partial sweep now report none, and the answer is computed
// here where the whole curve exists. Mirrors findSaturation in
// experiments/exp1_verification: the lowest level after which no higher level
// improves throughput by more than 5%.
func recomputeSaturation(experiment string, points []json.RawMessage, extras map[string]json.RawMessage) {
	if !strings.HasPrefix(experiment, "exp1") {
		return
	}
	best := map[string]map[int]float64{}
	for _, raw := range points {
		var p struct {
			Scheme      string   `json:"scheme"`
			Concurrency *int     `json:"concurrency"`
			Throughput  *float64 `json:"authorized_requests_per_second"`
		}
		if err := json.Unmarshal(raw, &p); err != nil ||
			p.Concurrency == nil || p.Throughput == nil || p.Scheme == "" {
			continue
		}
		if best[p.Scheme] == nil {
			best[p.Scheme] = map[int]float64{}
		}
		if *p.Throughput > best[p.Scheme][*p.Concurrency] {
			best[p.Scheme][*p.Concurrency] = *p.Throughput
		}
	}
	if len(best) == 0 {
		return
	}

	const relGain = 0.05
	out := map[string]int{}
	for scheme, curve := range best {
		levels := make([]int, 0, len(curve))
		for c := range curve {
			levels = append(levels, c)
		}
		sort.Ints(levels)
		if len(levels) < 2 {
			out[scheme] = 0
			continue
		}
		sat := 0
		for i := 0; i < len(levels)-1; i++ {
			improved := false
			for j := i + 1; j < len(levels); j++ {
				if curve[levels[j]] > curve[levels[i]]*(1+relGain) {
					improved = true
					break
				}
			}
			if !improved {
				sat = levels[i]
				break
			}
		}
		out[scheme] = sat
	}
	if enc, err := json.Marshal(out); err == nil {
		extras["saturation_point"] = enc
	}
}

// splitResult separates the points array from whatever else the result carries
// (saturation_point, scaling classes) so the extras survive the merge.
func splitResult(raw json.RawMessage) ([]json.RawMessage, map[string]json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, nil, fmt.Errorf("result is not an object: %w", err)
	}
	rawPoints, ok := obj["points"]
	if !ok {
		return nil, nil, fmt.Errorf("result has no points array")
	}
	var points []json.RawMessage
	if err := json.Unmarshal(rawPoints, &points); err != nil {
		return nil, nil, fmt.Errorf("result.points is not an array: %w", err)
	}
	rest := map[string]json.RawMessage{}
	for k, v := range obj {
		if k != "points" {
			rest[k] = v
		}
	}
	return points, rest, nil
}

// mergeExtras pools the result fields that sit BESIDE the points array.
//
// Exp 1's saturation_point and Exp 3's scaling classes are keyed by scheme, and
// a per-scheme shard carries only its own key. Keeping the first shard's copy
// dropped every other scheme's entry — measured: merging zkredact, ref13 and
// ref10 shards produced saturation_point {"zkredact": 0} and lost the rest.
//
// Object-valued extras are merged key by key. A key appearing twice with
// different values means two shards measured the same thing and disagreed,
// which is a fault to report rather than a tie to break. Non-object extras must
// match outright.
func mergeExtras(into, next map[string]json.RawMessage, path string) (map[string]json.RawMessage, error) {
	if into == nil {
		into = map[string]json.RawMessage{}
	}
	for key, val := range next {
		// Recomputed from the pooled points below, so a per-shard verdict here
		// is noise that would only ever collide with another shard's.
		if key == "saturation_point" {
			continue
		}
		prev, seen := into[key]
		if !seen {
			into[key] = val
			continue
		}
		if bytes.Equal(prev, val) {
			continue
		}

		prevObj, prevOK := asObject(prev)
		valObj, valOK := asObject(val)
		if !prevOK || !valOK {
			return nil, fmt.Errorf(
				"%s carries a different result.%s than an earlier shard, and it is not "+
					"a keyed object that can be pooled", path, key)
		}
		for k, v := range valObj {
			old, dup := prevObj[k]
			if !dup || bytes.Equal(old, v) {
				prevObj[k] = v
				continue
			}
			// Exp 3 classifies scaling PER SETUP CONFIGURATION but keys the map
			// by scheme alone, so two sweeps of one scheme collide the moment
			// they are measured on different hosts. Both verdicts are real and
			// neither is the pooled answer, so keep the LEAST favourable: a
			// contradicted claim must survive being averaged with a satisfied
			// one, and this can only ever make a claim look worse.
			if key == "ledger_scaling" {
				prevObj[k] = worseScaling(old, v)
				continue
			}
			return nil, fmt.Errorf(
				"%s and an earlier shard both report result.%s[%q] and disagree "+
					"(%s vs %s)", path, key, k, old, v)
		}
		merged, err := json.Marshal(prevObj)
		if err != nil {
			return nil, err
		}
		into[key] = merged
	}
	return into, nil
}

// worseScaling picks the scaling verdict that reflects worse on the claim: a
// broken claim beats an intact one, and beyond that the larger cost ratio wins.
func worseScaling(a, b json.RawMessage) json.RawMessage {
	type verdict struct {
		CostRatio  float64 `json:"cost_ratio"`
		ClaimHolds *bool   `json:"claim_holds"`
	}
	var va, vb verdict
	if json.Unmarshal(a, &va) != nil || json.Unmarshal(b, &vb) != nil {
		return a
	}
	switch {
	case va.ClaimHolds != nil && !*va.ClaimHolds:
		return a
	case vb.ClaimHolds != nil && !*vb.ClaimHolds:
		return b
	case vb.CostRatio > va.CostRatio:
		return b
	default:
		return a
	}
}

func asObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, false
	}
	return m, true
}

func rebuildResult(points []json.RawMessage, extras map[string]json.RawMessage) (json.RawMessage, error) {
	obj := map[string]json.RawMessage{}
	for k, v := range extras {
		obj[k] = v
	}
	ps, err := json.Marshal(points)
	if err != nil {
		return nil, err
	}
	obj["points"] = ps
	return json.Marshal(obj)
}

func sameString(field, aPath, bPath, want, got string) error {
	if want == got {
		return nil
	}
	return fmt.Errorf(
		"%s and %s disagree on %s (%q vs %q); they are not shards of one run",
		bPath, aPath, field, got, want)
}

func sameEnv(aPath, bPath string, a, b envFinger) error {
	switch {
	case a.OS != b.OS, a.Arch != b.Arch:
		return fmt.Errorf(
			"%s ran on %s/%s and %s on %s/%s; absolute numbers are not comparable "+
				"across platforms", aPath, a.OS, a.Arch, bPath, b.OS, b.Arch)
	case a.NumCPU != b.NumCPU:
		return fmt.Errorf(
			"%s ran on %d CPUs and %s on %d; a throughput curve pooled across "+
				"different core counts measures the hosts, not the schemes",
			aPath, a.NumCPU, bPath, b.NumCPU)
	case a.GoVer != b.GoVer:
		return fmt.Errorf(
			"%s was built with %s and %s with %s; the runtime is part of what was "+
				"measured", aPath, a.GoVer, bPath, b.GoVer)
	}
	return nil
}

func countPoints(raw json.RawMessage) int {
	points, _, err := splitResult(raw)
	if err != nil {
		return 0
	}
	return len(points)
}

func shardPaths(shards []shard) []string {
	out := make([]string, 0, len(shards))
	for _, s := range shards {
		out = append(out, filepath.Base(s.path))
	}
	sort.Strings(out)
	return out
}

func newest(shards []shard) time.Time {
	t := shards[0].doc.Metadata.Timestamp
	for _, s := range shards[1:] {
		if s.doc.Metadata.Timestamp.After(t) {
			t = s.doc.Metadata.Timestamp
		}
	}
	return t
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func short(commit string) string {
	if len(commit) > 8 {
		return commit[:8]
	}
	return commit
}

func writeJSON(path string, doc *document) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
