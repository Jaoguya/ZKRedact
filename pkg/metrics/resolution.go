package metrics

import (
	"fmt"
	"time"
)

// Clock resolution checking.
//
// WHY THIS EXISTS. Every number this project produces comes from time.Since.
// On a host whose monotonic clock is coarse, an operation shorter than one tick
// measures as exactly zero, and a sequence of them measures as a staircase of
// multiples of the tick. Neither outcome errors. Both look like data.
//
// This was found the hard way: on a Windows host, 200,000 consecutive
// time.Since(time.Now()) calls all returned zero. Linux hosts back the
// monotonic clock with clock_gettime(CLOCK_MONOTONIC) at nanosecond
// granularity, which is why the same code measures correctly on the EC2 target
// and silently does not on a developer laptop.
//
// The consequences are specific and severe:
//
//   - Exp 1's latency percentiles quantise to multiples of the tick, so p50,
//     p95 and p99 collapse onto the same few values.
//   - Exp 2's cost decomposition is the comparison between CryptoTime and
//     LedgerTime. If both round to zero, the ratio is undefined; if both round
//     to one tick, they look equal.
//   - Exp 3's flat-versus-linear distinction disappears below one tick.
//
// So the harness refuses to record results on a host it cannot measure on,
// rather than producing plausible numbers nobody can trust.

// RequiredResolution is the coarsest clock this evaluation can be run on.
//
// Derived from the smallest quantity that must be distinguishable. Exp 2
// separates per-request CH adaptation from per-batch ledger work; a single
// elliptic-curve adaptation on the target hardware is on the order of tens of
// microseconds. Resolving that to roughly two significant figures needs a tick
// well under a microsecond, so 1µs is the outer bound at which any of these
// measurements remain meaningful.
const RequiredResolution = time.Microsecond

// ClockResolution estimates the smallest interval time.Since can distinguish.
//
// Measured by sampling consecutive calls until the clock advances, repeated so
// one lucky scheduling boundary cannot pass a coarse clock. Returns the
// smallest non-zero delta observed, or 0 if the clock never advanced within the
// sample budget — which itself means the host is unusable.
func ClockResolution() time.Duration {
	const (
		rounds     = 16
		maxSamples = 200000
	)

	best := time.Duration(0)
	for r := 0; r < rounds; r++ {
		start := time.Now()
		for i := 0; i < maxSamples; i++ {
			if d := time.Since(start); d > 0 {
				if best == 0 || d < best {
					best = d
				}
				break
			}
		}
	}
	return best
}

// ErrCoarseClock reports a host whose clock cannot resolve the measurements.
type ErrCoarseClock struct {
	Observed time.Duration
	Required time.Duration
}

func (e ErrCoarseClock) Error() string {
	if e.Observed == 0 {
		return fmt.Sprintf(
			"clock never advanced across the sample budget: this host cannot time "+
				"anything shorter than a scheduler tick, so every measurement would be "+
				"zero or a multiple of it (need resolution finer than %v)", e.Required)
	}
	return fmt.Sprintf(
		"clock resolution is %v, coarser than the %v required: measurements would "+
			"quantise to multiples of the tick, so latency percentiles would collapse "+
			"and the Exp 2 cost decomposition would be undefined",
		e.Observed, e.Required)
}

// RequireUsableClock reports an error unless this host can resolve the
// measurements the experiments depend on.
//
// Called at harness startup. Failing here costs seconds; discovering it after a
// multi-hour sweep costs the sweep, and discovering it after publication costs
// more than that.
func RequireUsableClock() error {
	got := ClockResolution()
	if got == 0 || got > RequiredResolution {
		return ErrCoarseClock{Observed: got, Required: RequiredResolution}
	}
	return nil
}

// ClockIsUsable reports whether this host can resolve the measurements.
//
// For tests that would otherwise assert a non-zero duration and fail for
// reasons that have nothing to do with the code under test.
func ClockIsUsable() bool { return RequireUsableClock() == nil }
