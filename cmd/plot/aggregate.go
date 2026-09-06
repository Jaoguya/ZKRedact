package main

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// Aggregation across repetitions, and the rule that decides what may be pooled.
//
// UNTIL NOW NOTHING CONSUMED REPETITIONS. All three runners append each
// repetition as its own Point and never combine them (TASK.md §9). So extra
// repetitions were rows nobody read, and `meta.repetitions` could be set from
// measured variance only once something computed variance. This is that
// something.
//
// THE POOLING RULE, WHICH IS THE PART THAT CAN GO WRONG SILENTLY.
// Two points may be averaged together only if they differ in NOTHING except
// the repetition index. Every other dimension — shard count, batch size,
// verification mode, arity, challenged blocks, wait bound, conflict ratio,
// history depth — is part of the series key.
//
// Get that wrong and the failure is invisible: averaging arity 2 with arity 10
// produces a smooth curve at a value neither configuration ever measured, and
// nothing in the output says so. This project has already shipped four sweeps
// that were declared and never executed; pooling them after the fact would be
// the same class of error at the other end of the pipeline.
//
// So Key is built from every dimension the caller does not name as the x-axis,
// and a series records how many repetitions it actually pooled.

// Sample is one (x, y) observation from a single repetition.
type Sample struct {
	X float64
	Y float64
}

// Point is an aggregated measurement at one x value.
type Point struct {
	X float64

	// Mean of the repetitions at this x.
	Mean float64

	// Min and Max bound the observed spread. Reported rather than a standard
	// deviation because a sweep is commonly run at 3 repetitions, where a
	// standard deviation is a number with more precision than meaning.
	Min float64
	Max float64

	// N is how many repetitions were pooled. A plot must be able to say when
	// a point is a single observation.
	N int
}

// CV is the coefficient of variation, as a fraction of the mean. Zero when the
// mean is zero or there is only one sample.
func (p Point) CV() float64 {
	if p.N < 2 || p.Mean == 0 {
		return 0
	}
	return (p.Max - p.Min) / p.Mean
}

// Series is one line on a chart: a scheme under one configuration.
type Series struct {
	// Scheme is the system under test.
	Scheme string

	// Dims are the non-x dimensions this series holds fixed, e.g.
	// {"shard_count": "16", "native_batch_verify": "true"}. Sorted by key when
	// rendered, so a legend is stable across runs.
	Dims map[string]string

	Points []Point
}

// Label renders the series for a legend: the scheme, then its dimensions in a
// stable order.
func (s Series) Label() string {
	if len(s.Dims) == 0 {
		return s.Scheme
	}
	keys := make([]string, 0, len(s.Dims))
	for k := range s.Dims {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, s.Dims[k]))
	}
	return s.Scheme + " (" + strings.Join(parts, ", ") + ")"
}

// SingleObservationPoints counts points backed by one repetition. A chart drawn
// from these is showing one run, not a measurement, and says so.
func (s Series) SingleObservationPoints() int {
	n := 0
	for _, p := range s.Points {
		if p.N < 2 {
			n++
		}
	}
	return n
}

// rawSeries accumulates samples before aggregation.
type rawSeries struct {
	scheme  string
	dims    map[string]string
	samples map[float64][]float64
}

// Collector groups observations into series and aggregates them.
type Collector struct {
	series map[string]*rawSeries
}

func NewCollector() *Collector {
	return &Collector{series: make(map[string]*rawSeries)}
}

// Add records one observation.
//
// dims must contain EVERY dimension that is not the x-axis and not the
// repetition index. Omitting one silently pools configurations that were
// measured separately — see the package comment.
func (c *Collector) Add(scheme string, dims map[string]string, x, y float64) {
	key := seriesKey(scheme, dims)
	rs, ok := c.series[key]
	if !ok {
		copied := make(map[string]string, len(dims))
		for k, v := range dims {
			copied[k] = v
		}
		rs = &rawSeries{scheme: scheme, dims: copied, samples: make(map[float64][]float64)}
		c.series[key] = rs
	}
	rs.samples[x] = append(rs.samples[x], y)
}

// Series aggregates and returns the collected series, ordered for stable
// output: by scheme, then by label.
func (c *Collector) Series() []Series {
	out := make([]Series, 0, len(c.series))
	for _, rs := range c.series {
		s := Series{Scheme: rs.scheme, Dims: rs.dims}
		for x, ys := range rs.samples {
			s.Points = append(s.Points, aggregate(x, ys))
		}
		sort.Slice(s.Points, func(i, j int) bool { return s.Points[i].X < s.Points[j].X })
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Scheme != out[j].Scheme {
			return out[i].Scheme < out[j].Scheme
		}
		return out[i].Label() < out[j].Label()
	})
	return out
}

func aggregate(x float64, ys []float64) Point {
	p := Point{X: x, N: len(ys)}
	if len(ys) == 0 {
		return p
	}
	p.Min, p.Max = ys[0], ys[0]
	sum := 0.0
	for _, y := range ys {
		sum += y
		p.Min = math.Min(p.Min, y)
		p.Max = math.Max(p.Max, y)
	}
	p.Mean = sum / float64(len(ys))
	return p
}

// seriesKey is the identity of a series: the scheme plus every fixed dimension.
func seriesKey(scheme string, dims map[string]string) string {
	keys := make([]string, 0, len(dims))
	for k := range dims {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteString(scheme)
	for _, k := range keys {
		b.WriteString("\x00")
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(dims[k])
	}
	return b.String()
}

// dimsFromSetupParams renders a Point's swept setup parameters as series
// dimensions. Ref[13] carries arity_q and challenged_blocks here; other schemes
// carry nothing.
func dimsFromSetupParams(sp map[string]any) map[string]string {
	out := make(map[string]string, len(sp))
	for k, v := range sp {
		out[k] = fmt.Sprint(v)
	}
	return out
}

// merge combines dimension maps, later entries winning. Used to build a series
// key from several sources without mutating any of them.
func merge(maps ...map[string]string) map[string]string {
	out := make(map[string]string)
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}
