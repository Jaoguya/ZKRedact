// Package metrics collects timing and throughput measurements.
//
// Percentiles are computed from retained samples rather than from a streaming
// approximation. At the configured workload size (10,000 requests) the memory
// cost is trivial, and exact percentiles remove a whole class of doubt: an
// approximate p99 that differs between schemes by a few percent is
// indistinguishable from a real difference of a few percent.
package metrics

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// Latency accumulates duration samples and reports exact percentiles.
// Safe for concurrent use — Exp 1 records from up to 1024 goroutines.
type Latency struct {
	mu      sync.Mutex
	samples []time.Duration
	sorted  bool
}

// NewLatency returns a collector preallocated for n samples.
func NewLatency(n int) *Latency {
	if n < 0 {
		n = 0
	}
	return &Latency{samples: make([]time.Duration, 0, n)}
}

// Record adds one sample.
func (l *Latency) Record(d time.Duration) {
	l.mu.Lock()
	l.samples = append(l.samples, d)
	l.sorted = false
	l.mu.Unlock()
}

// Count returns the number of samples recorded.
func (l *Latency) Count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.samples)
}

// ensureSorted must be called with l.mu held.
func (l *Latency) ensureSorted() {
	if !l.sorted {
		sort.Slice(l.samples, func(i, j int) bool { return l.samples[i] < l.samples[j] })
		l.sorted = true
	}
}

// Percentile returns the p-th percentile, p in [0,100], using linear
// interpolation between adjacent ranks. Returns 0 when no samples exist.
func (l *Latency) Percentile(p float64) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.percentileLocked(p)
}

func (l *Latency) percentileLocked(p float64) time.Duration {
	n := len(l.samples)
	if n == 0 {
		return 0
	}
	l.ensureSorted()
	if p <= 0 {
		return l.samples[0]
	}
	if p >= 100 {
		return l.samples[n-1]
	}

	rank := (p / 100) * float64(n-1)
	lo := int(math.Floor(rank))
	hi := int(math.Ceil(rank))
	if lo == hi {
		return l.samples[lo]
	}
	frac := rank - float64(lo)
	delta := float64(l.samples[hi] - l.samples[lo])
	return l.samples[lo] + time.Duration(frac*delta)
}

// Mean returns the arithmetic mean.
func (l *Latency) Mean() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.samples) == 0 {
		return 0
	}
	var sum time.Duration
	for _, s := range l.samples {
		sum += s
	}
	return sum / time.Duration(len(l.samples))
}

// StdDev returns the sample standard deviation. The pilot run uses this to fix
// meta.repetitions: repeat until the confidence interval is narrower than the
// smallest difference the paper intends to claim.
func (l *Latency) StdDev() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := len(l.samples)
	if n < 2 {
		return 0
	}
	var sum float64
	for _, s := range l.samples {
		sum += float64(s)
	}
	mean := sum / float64(n)

	var ss float64
	for _, s := range l.samples {
		d := float64(s) - mean
		ss += d * d
	}
	return time.Duration(math.Sqrt(ss / float64(n-1)))
}

// Summary is a snapshot of a Latency collector, suitable for serialisation.
type Summary struct {
	Count  int           `json:"count"`
	Mean   time.Duration `json:"mean_ns"`
	StdDev time.Duration `json:"stddev_ns"`
	Min    time.Duration `json:"min_ns"`
	P50    time.Duration `json:"p50_ns"`
	P95    time.Duration `json:"p95_ns"`
	P99    time.Duration `json:"p99_ns"`
	Max    time.Duration `json:"max_ns"`

	// P99Reliable is false when fewer than 100 samples landed in the top
	// percentile, which makes the reported p99 noise rather than measurement.
	// Serialised so a reader of the results can see it without recomputing.
	P99Reliable bool `json:"p99_reliable"`
}

// Summarize computes all statistics in a single pass under one lock.
func (l *Latency) Summarize() Summary {
	l.mu.Lock()
	defer l.mu.Unlock()

	n := len(l.samples)
	if n == 0 {
		return Summary{}
	}
	l.ensureSorted()

	var sum float64
	for _, s := range l.samples {
		sum += float64(s)
	}
	mean := sum / float64(n)

	var sd float64
	if n > 1 {
		var ss float64
		for _, s := range l.samples {
			d := float64(s) - mean
			ss += d * d
		}
		sd = math.Sqrt(ss / float64(n-1))
	}

	return Summary{
		Count:       n,
		Mean:        time.Duration(mean),
		StdDev:      time.Duration(sd),
		Min:         l.samples[0],
		P50:         l.percentileLocked(50),
		P95:         l.percentileLocked(95),
		P99:         l.percentileLocked(99),
		Max:         l.samples[n-1],
		P99Reliable: n >= 10000,
	}
}

// String renders a summary for terminal output.
func (s Summary) String() string {
	if s.Count == 0 {
		return "no samples"
	}
	warn := ""
	if !s.P99Reliable {
		warn = fmt.Sprintf("  (p99 unreliable: %d samples)", s.Count)
	}
	return fmt.Sprintf("n=%d  mean=%s  p50=%s  p95=%s  p99=%s  max=%s%s",
		s.Count,
		roundDur(s.Mean), roundDur(s.P50), roundDur(s.P95),
		roundDur(s.P99), roundDur(s.Max), warn)
}

func roundDur(d time.Duration) time.Duration {
	switch {
	case d >= time.Second:
		return d.Round(time.Millisecond)
	case d >= time.Millisecond:
		return d.Round(10 * time.Microsecond)
	default:
		return d.Round(time.Nanosecond)
	}
}

// -----------------------------------------------------------------------------
// Throughput
// -----------------------------------------------------------------------------

// Throughput measures completed operations per second over a wall-clock window.
type Throughput struct {
	mu        sync.Mutex
	start     time.Time
	completed int64
	stopped   time.Time
}

// NewThroughput starts the measurement window.
func NewThroughput() *Throughput {
	return &Throughput{start: time.Now()}
}

// Add records n completed operations.
func (t *Throughput) Add(n int) {
	t.mu.Lock()
	t.completed += int64(n)
	t.mu.Unlock()
}

// Stop closes the measurement window.
func (t *Throughput) Stop() {
	t.mu.Lock()
	if t.stopped.IsZero() {
		t.stopped = time.Now()
	}
	t.mu.Unlock()
}

// PerSecond returns completed operations per second. If Stop has not been
// called, the window runs to now.
func (t *Throughput) PerSecond() float64 {
	t.mu.Lock()
	defer t.mu.Unlock()

	end := t.stopped
	if end.IsZero() {
		end = time.Now()
	}
	elapsed := end.Sub(t.start).Seconds()
	if elapsed <= 0 {
		return 0
	}
	return float64(t.completed) / elapsed
}

// Completed returns the operation count.
func (t *Throughput) Completed() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.completed
}

// Elapsed returns the measurement window duration.
func (t *Throughput) Elapsed() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	end := t.stopped
	if end.IsZero() {
		end = time.Now()
	}
	return end.Sub(t.start)
}
