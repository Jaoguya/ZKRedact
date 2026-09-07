// Package results writes experiment output with the metadata that makes it
// reproducible.
//
// SKILL.md requires that identical configs produce identical results. That is
// only checkable if every result file carries what produced it: the resolved
// config, the seed, the dataset identity, the code version, and the machine. A
// result missing any of those cannot be regenerated, and under the project's own
// rules is not publishable.
package results

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Metadata accompanies every result file.
type Metadata struct {
	Experiment  string    `json:"experiment"`
	Timestamp   time.Time `json:"timestamp"`
	Seed        int64     `json:"seed"`
	DatasetID   string    `json:"dataset_id"`
	GitCommit   string    `json:"git_commit"`
	GitDirty    bool      `json:"git_dirty"`
	ConfigPath  string    `json:"config_path"`
	Environment EnvFinger `json:"environment"`

	// ResolvedConfig is the full config after defaults, so a reader never has to
	// guess which file version produced these numbers.
	ResolvedConfig any `json:"resolved_config,omitempty"`

	// PartialComparison names the systems a run was restricted to, and is empty
	// for a full run.
	//
	// A results file covering fewer than all enabled systems is not a
	// comparison, and the difference is invisible once the numbers are in a
	// plot. Recording it here means a partial run cannot be mistaken for a
	// complete one later, when nobody remembers which flags were passed.
	PartialComparison []string `json:"partial_comparison,omitempty"`

	// PartialLevels and PartialTransports record an Exp 1 sweep narrowed by
	// -levels or -transports, for the same reason PartialComparison exists.
	//
	// THEY ARE RECORDED BESIDE THE RESOLVED CONFIG, NOT INSIDE IT. Narrowing
	// the config itself would make every shard carry a different
	// resolved_config, and merge-results rightly refuses to pool documents
	// whose parameters disagree — so the split would have made its own output
	// unmergeable. The resolved config stays the run's full parameters; these
	// say which slice of them this process measured.
	PartialLevels     []int    `json:"partial_levels,omitempty"`
	PartialTransports []string `json:"partial_transports,omitempty"`

	// PartialArms records an Exp 2 / Exp 3 sweep split across hosts, in the
	// i/N form -arms takes. Empty for a whole-sweep run.
	PartialArms string `json:"partial_arms,omitempty"`
}

// EnvFinger identifies the machine a run happened on.
//
// Absolute numbers are not comparable across machines, so results carrying
// different fingerprints must never be merged into one table.
type EnvFinger struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	NumCPU   int    `json:"num_cpu"`
	GoVer    string `json:"go_version"`
	Hostname string `json:"hostname"`
}

// Fingerprint captures the current machine.
func Fingerprint() EnvFinger {
	host, err := os.Hostname()
	if err != nil {
		host = "unknown"
	}
	return EnvFinger{
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		NumCPU:   runtime.NumCPU(),
		GoVer:    runtime.Version(),
		Hostname: host,
	}
}

// GitInfo returns the current commit and whether the tree has uncommitted
// changes.
//
// A dirty tree is recorded rather than rejected, but it means the commit hash
// does not fully identify the code that ran — which the reader needs to know.
func GitInfo() (commit string, dirty bool) {
	commit = "unknown"
	if out, err := exec.Command("git", "rev-parse", "HEAD").Output(); err == nil {
		commit = strings.TrimSpace(string(out))
	}
	if out, err := exec.Command("git", "status", "--porcelain").Output(); err == nil {
		dirty = len(strings.TrimSpace(string(out))) > 0
	}
	return commit, dirty
}

// Document is one experiment's complete output.
type Document struct {
	Metadata Metadata `json:"metadata"`
	Result   any      `json:"result"`
}

// Writer emits result documents into a directory.
type Writer struct {
	dir     string
	formats []string
}

// NewWriter creates the output directory if needed.
func NewWriter(dir string, formats []string) (*Writer, error) {
	if dir == "" {
		return nil, fmt.Errorf("results directory not configured")
	}
	if len(formats) == 0 {
		return nil, fmt.Errorf("no output formats configured")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create results dir %s: %w", dir, err)
	}
	return &Writer{dir: dir, formats: formats}, nil
}

// disambiguate appends a counter when a name is already taken.
//
// Suffixes are -2, -3 and so on, so the first writer in a second keeps the
// plain name and nothing that already exists is renamed. Checked across EVERY
// configured format: a run that writes .json and .csv must not take the .json
// name from one earlier run and the .csv from another.
func (w *Writer) disambiguate(base string) string {
	taken := func(b string) bool {
		for _, f := range w.formats {
			ext := strings.ToLower(strings.TrimSpace(f))
			if ext == "" {
				continue
			}
			if _, err := os.Stat(filepath.Join(w.dir, b+"."+ext)); err == nil {
				return true
			}
		}
		return false
	}
	if !taken(base) {
		return base
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s-%d", base, i)
		if !taken(candidate) {
			return candidate
		}
	}
}

// Write emits one document under a timestamped name.
//
// Timestamps are part of the filename so a re-run never silently overwrites an
// earlier result. Losing a measurement to an accidental overwrite is expensive:
// these runs take hours.
func (w *Writer) Write(doc Document) ([]string, error) {
	stamp := doc.Metadata.Timestamp.UTC().Format("20060102-150405")
	base := fmt.Sprintf("%s-%s", doc.Metadata.Experiment, stamp)

	// The stamp resolves to ONE SECOND, which is not fine enough to keep two
	// shards apart. Sharding by scheme runs several short commands in a row —
	// Ref[10]'s Exp 1 takes well under a second — and two finishing in the same
	// second produced the same filename, so os.Create truncated the first.
	// Measured: four shards run in sequence, all exiting 0, left three files;
	// Ref[22]'s results were gone with nothing reporting it.
	base = w.disambiguate(base)

	var written []string
	for _, f := range w.formats {
		switch strings.ToLower(f) {
		case "json":
			path := filepath.Join(w.dir, base+".json")
			if err := writeJSON(path, doc); err != nil {
				return written, err
			}
			written = append(written, path)
		case "csv":
			path := filepath.Join(w.dir, base+".csv")
			if err := writeCSV(path, doc); err != nil {
				return written, err
			}
			written = append(written, path)
		default:
			return written, fmt.Errorf("unsupported output format %q", f)
		}
	}
	return written, nil
}

func writeJSON(path string, doc Document) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	return nil
}

// writeCSV flattens the result's point list into rows.
//
// Structures are converted via JSON so the CSV columns follow the same field
// names as the JSON document. Hand-maintained column lists drift from the
// structs they mirror, and a drifted column header silently mislabels data.
func writeCSV(path string, doc Document) error {
	raw, err := json.Marshal(doc.Result)
	if err != nil {
		return fmt.Errorf("marshal result: %w", err)
	}

	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return fmt.Errorf("unmarshal result: %w", err)
	}

	pointsRaw, ok := generic["points"]
	if !ok {
		return fmt.Errorf("result has no \"points\" field to flatten into CSV")
	}
	points, ok := pointsRaw.([]any)
	if !ok {
		return fmt.Errorf("result \"points\" is not a list")
	}
	if len(points) == 0 {
		return fmt.Errorf("result has no points to write")
	}

	first, ok := points[0].(map[string]any)
	if !ok {
		return fmt.Errorf("result points are not objects")
	}
	cols := make([]string, 0, len(first))
	for k := range first {
		cols = append(cols, k)
	}
	sortStrings(cols)

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()

	// Metadata rides along as comment lines so a CSV opened on its own still
	// says which run produced it.
	fmt.Fprintf(f, "# experiment: %s\n", doc.Metadata.Experiment)
	fmt.Fprintf(f, "# timestamp: %s\n", doc.Metadata.Timestamp.UTC().Format(time.RFC3339))
	fmt.Fprintf(f, "# seed: %d\n", doc.Metadata.Seed)
	fmt.Fprintf(f, "# dataset_id: %s\n", doc.Metadata.DatasetID)
	fmt.Fprintf(f, "# git_commit: %s (dirty=%t)\n", doc.Metadata.GitCommit, doc.Metadata.GitDirty)
	fmt.Fprintf(f, "# host: %s %s/%s %d cpu %s\n",
		doc.Metadata.Environment.Hostname,
		doc.Metadata.Environment.OS,
		doc.Metadata.Environment.Arch,
		doc.Metadata.Environment.NumCPU,
		doc.Metadata.Environment.GoVer)

	fmt.Fprintln(f, strings.Join(cols, ","))
	for _, p := range points {
		row, ok := p.(map[string]any)
		if !ok {
			continue
		}
		cells := make([]string, len(cols))
		for i, c := range cols {
			cells[i] = csvCell(row[c])
		}
		fmt.Fprintln(f, strings.Join(cells, ","))
	}
	return nil
}

func csvCell(v any) string {
	if v == nil {
		return ""
	}
	s := fmt.Sprint(v)
	// json.Unmarshal renders all numbers as float64, so integral values would
	// otherwise print in scientific notation and become unreadable in a
	// spreadsheet.
	if f, ok := v.(float64); ok {
		if f == float64(int64(f)) {
			s = fmt.Sprintf("%d", int64(f))
		} else {
			s = fmt.Sprintf("%g", f)
		}
	}
	if strings.ContainsAny(s, ",\"\n") {
		s = `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

func sortStrings(xs []string) {
	for i := 1; i < len(xs); i++ {
		for j := i; j > 0 && xs[j] < xs[j-1]; j-- {
			xs[j], xs[j-1] = xs[j-1], xs[j]
		}
	}
}
