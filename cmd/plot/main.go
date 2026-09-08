// Command plot renders figures from the results this project writes.
//
//	plot -results results -out results/plots
//
// It reads every results file, aggregates repetitions, and writes one SVG plus
// one CSV per figure.
//
// THE CSV IS NOT AN AFTERTHOUGHT. It carries the aggregated numbers behind each
// line — mean, min, max, and how many repetitions were pooled — so a figure can
// be checked without rerunning anything, and so whoever writes the paper can
// re-plot in whatever they use. A chart nobody can audit is a chart nobody
// should trust.
//
// WHAT THIS COMMAND WILL NOT DO. It will not average across configurations that
// were measured separately. Every dimension that is not the x-axis is part of a
// series key, so an arity-2 run and an arity-10 run are two lines, never one
// smoothed curve at a value neither produced. See aggregate.go.
package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
)

func main() {
	var (
		resultsDir = flag.String("results", "results", "directory holding results/*.json")
		outDir     = flag.String("out", "", "output directory (default <results>/plots)")
	)
	flag.Parse()

	if *outDir == "" {
		*outDir = filepath.Join(*resultsDir, "plots")
	}

	if err := run(*resultsDir, *outDir); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(resultsDir, outDir string) error {
	charts, err := loadAll(resultsDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", outDir, err)
	}

	fmt.Printf("plot: %d figure(s) from %s\n", len(charts), resultsDir)

	for _, c := range charts {
		svgPath := filepath.Join(outDir, c.Name+".svg")
		if err := os.WriteFile(svgPath, []byte(renderSVG(c)), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", svgPath, err)
		}
		csvPath := filepath.Join(outDir, csvName(c.Name))
		if err := writeSeriesCSV(csvPath, c); err != nil {
			return err
		}

		single := totalSingle(c.Series)
		note := ""
		if single > 0 {
			note = fmt.Sprintf("  [%d single-repetition point(s)]", single)
		}
		fmt.Printf("  %-24s %d series%s\n", c.Name, len(c.Series), note)
		for _, w := range c.Caveats {
			if len(w) > 8 && w[:8] == "WARNING:" {
				fmt.Printf("      %s\n", w)
			}
		}
	}
	fmt.Printf("  wrote %s\n", outDir)
	return nil
}

// writeSeriesCSV emits the aggregated numbers behind one figure.
//
// One row per (series, x). The dimensions that define the series get their own
// columns, so the file says exactly which configuration each row came from —
// a reader must never have to infer that from a legend string.
func writeSeriesCSV(path string, c chart) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()

	// Union of dimension names across the series, so every row has the same
	// shape even when one series carries a knob another does not.
	dimSet := map[string]bool{}
	for _, s := range c.Series {
		for k := range s.Dims {
			dimSet[k] = true
		}
	}
	dims := make([]string, 0, len(dimSet))
	for k := range dimSet {
		dims = append(dims, k)
	}
	sort.Strings(dims)

	w := csv.NewWriter(f)
	defer w.Flush()

	header := append([]string{"scheme"}, dims...)
	// median first: it is what the figure draws. mean stays beside it so a
	// reader can see when the two disagree, which is the signal that one
	// repetition ran on a machine that was busy.
	header = append(header, "x", "median", "mean", "min", "max", "repetitions", "spread_over_mean")
	if err := w.Write(header); err != nil {
		return err
	}

	for _, s := range c.Series {
		for _, p := range s.Points {
			row := []string{s.Scheme}
			for _, d := range dims {
				row = append(row, s.Dims[d])
			}
			row = append(row,
				strconv.FormatFloat(p.X, 'g', -1, 64),
				strconv.FormatFloat(p.Median, 'g', -1, 64),
				strconv.FormatFloat(p.Mean, 'g', -1, 64),
				strconv.FormatFloat(p.Min, 'g', -1, 64),
				strconv.FormatFloat(p.Max, 'g', -1, 64),
				strconv.Itoa(p.N),
				strconv.FormatFloat(p.CV(), 'g', -1, 64),
			)
			if err := w.Write(row); err != nil {
				return err
			}
		}
	}
	return w.Error()
}
