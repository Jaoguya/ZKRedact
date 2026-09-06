// Package exp3_audit runs Experiment 3: Provenance Retrieval and Audit Cost.
//
// Question: does audit cost scale with the target transaction's redaction
// history rather than with total ledger size?
//
// The headline plot holds history depth fixed and grows the ledger. ZK-Redact
// should stay flat while Ref[10] and Ref[22] climb, since both must traverse the
// chain. Ref[13] should be sublinear.
//
// Two honesty constraints are built into the measurement:
//
//   - Auditor authorization is timed separately. No baseline authenticates the
//     auditor, so folding that cost into the total would penalise ZK-Redact for
//     providing a capability the others simply lack.
//
//   - The schemes do not answer the same question. VRBC audits ledger integrity;
//     ZK-Redact retrieves a transaction's history. Both scale with ledger size,
//     which is what this experiment compares — but every result carries its
//     semantics so the comparison is never read as feature equivalence.
package exp3_audit

import (
	"context"
	"fmt"
	"time"

	"zkredact/pkg/scheme"
)

// Config parameterises one Exp 3 run.
type Config struct {
	// LedgerSizes must span at least one order of magnitude: flat cannot be
	// distinguished from linear over a narrow range.
	LedgerSizes []int

	// HistoryDepths is the number of prior redactions on the target transaction.
	HistoryDepths []int

	Repetitions int

	// AuditorID identifies the querying auditor. Schemes without auditor
	// authentication ignore it.
	AuditorID string

	// Prepare puts a scheme into the state one measurement point needs: a
	// ledger of exactly ledgerSize blocks, with target transactions carrying
	// each configured history depth. It returns those targets by depth.
	//
	// WHY A HOOK RATHER THAN A PRE-BUILT MAP. Ledger size is the swept axis of
	// the headline plot, so the ledger has to be REBUILT at each size. An
	// earlier signature took one targetsByDepth map for the whole run, which
	// silently measured every ledger size against whatever ledger the scheme
	// happened to hold — the sweep would have produced a flat line for every
	// scheme, including the ones that must climb, and nothing would have
	// indicated why.
	//
	// Construction is NOT timed: only retrieval and verification are.
	//
	// overrides carries SETUP-time swept parameters for this point — Ref[13]'s
	// arity_q and challenged_blocks. They cannot be reconfigured in place the
	// way Exp 1 reshards, because the tree shape depends on them, so Setup is
	// re-run per value. That is free: Setup is untimed for every scheme.
	Prepare func(ctx context.Context, s scheme.Scheme, ledgerSize int, overrides map[string]any) (map[int][]string, error)

	// SetupSweeps reports the swept setup-parameter combinations that apply to
	// one scheme, each as an override map. A scheme without any of these knobs
	// must get exactly one entry, or it would be measured repeatedly under
	// labels that mean nothing for it and the extra points would look like
	// variance.
	//
	// WHY A HOOK. Whether a parameter applies to a scheme is decided by whether
	// config.SchemeParams produces it, which keeps the parameter map the single
	// contract — the same contract internal/schemes/contract_test.go checks.
	// The runner has no business duplicating that knowledge.
	SetupSweeps func(s scheme.Scheme) ([]map[string]any, error)
}

// Point is one measured configuration.
type Point struct {
	Scheme       string `json:"scheme"`
	LedgerSize   int    `json:"ledger_size"`
	HistoryDepth int    `json:"history_depth"`
	Repetition   int    `json:"repetition"`

	// SetupParams records the swept setup-time parameters this point was
	// measured under — Ref[13]'s arity_q and challenged_blocks. Empty for a
	// scheme with no such knob. Without it the arity sweep would produce
	// several curves a plot could not tell apart.
	SetupParams map[string]any `json:"setup_params,omitempty"`

	// Semantics records which question this scheme actually answered. Carried
	// into results so no table can silently imply equivalence.
	Semantics string `json:"semantics"`

	Verified bool `json:"verified"`

	RetrievalTime    time.Duration `json:"retrieval_time_ns"`
	VerificationTime time.Duration `json:"verification_time_ns"`
	TotalTime        time.Duration `json:"total_time_ns"`

	// AuthorizationTime is reported separately, never folded into TotalTime.
	AuthorizationTime time.Duration `json:"auditor_authorization_time_ns"`

	EvidenceBytes   int `json:"proof_size_bytes"`
	BlocksTraversed int `json:"blocks_traversed"`
	RecordsReturned int `json:"records_returned"`
}

// Result is the full Exp 3 output.
type Result struct {
	Points []Point `json:"points"`

	// LedgerScaling maps each scheme to how its cost responds to ledger growth,
	// at fixed history depth. See ScalingClass.
	LedgerScaling map[string]ScalingClass `json:"ledger_scaling"`
}

// ScalingClass summarises how cost responded to a tenfold ledger increase.
type ScalingClass struct {
	// CostRatio is cost at the largest ledger divided by cost at the smallest.
	CostRatio float64 `json:"cost_ratio"`

	// SizeRatio is the corresponding ledger-size ratio.
	SizeRatio float64 `json:"size_ratio"`

	// Class is "flat", "sublinear", or "linear", derived from the two ratios.
	// A label, not a proof: the underlying points are retained so a reader can
	// fit whatever model they prefer.
	Class string `json:"class"`

	// ClaimHolds reports whether a scheme advertising LedgerIndependentAudit
	// actually behaved that way. A false value here contradicts the scheme's own
	// capability declaration and must be reported, not smoothed over.
	ClaimHolds bool `json:"claim_holds"`
}

// Run executes Experiment 3.
//
// Ledgers at each configured size must already be built and the target
// transactions already carry the requested history depth. Construction is not
// timed — only retrieval and verification are.
func Run(
	ctx context.Context,
	cfg Config,
	schemesUnderTest []scheme.Scheme,
) (*Result, error) {
	if cfg.Prepare == nil {
		return nil, fmt.Errorf("exp3: Prepare is required — the ledger must be rebuilt at each swept size")
	}
	if len(cfg.LedgerSizes) < 2 {
		return nil, fmt.Errorf("exp3: need at least two ledger sizes to distinguish flat from linear")
	}
	if ratio := float64(maxInt(cfg.LedgerSizes)) / float64(minInt(cfg.LedgerSizes)); ratio < 10 {
		return nil, fmt.Errorf(
			"exp3: ledger sizes span only %.1fx; separating O(1) from O(n) needs "+
				"at least one order of magnitude", ratio)
	}
	if cfg.Repetitions < 1 {
		return nil, fmt.Errorf("exp3: repetitions must be >= 1, got %d", cfg.Repetitions)
	}
	if len(cfg.HistoryDepths) == 0 {
		return nil, fmt.Errorf("exp3: no history depths configured")
	}

	res := &Result{LedgerScaling: make(map[string]ScalingClass)}

	for _, s := range schemesUnderTest {
		// The setup-parameter combinations this scheme is measured under. One
		// empty entry for a scheme with no swept setup knobs.
		sweeps := []map[string]any{nil}
		if cfg.SetupSweeps != nil {
			got, err := cfg.SetupSweeps(s)
			if err != nil {
				return nil, fmt.Errorf("exp3: setup sweeps for %s: %w", s.Name(), err)
			}
			if len(got) > 0 {
				sweeps = got
			}
		}

		schemeStart := len(res.Points)

		for _, overrides := range sweeps {
			for _, ledger := range cfg.LedgerSizes {
				// Rebuild at this ledger size and setup configuration before
				// measuring anything at it.
				targetsByDepth, err := cfg.Prepare(ctx, s, ledger, overrides)
				if err != nil {
					return nil, fmt.Errorf("exp3: preparing %s at ledger %d: %w", s.Name(), ledger, err)
				}
				for _, depth := range cfg.HistoryDepths {
					targets := targetsByDepth[depth]
					if len(targets) == 0 {
						return nil, fmt.Errorf("exp3: no target transaction at history depth %d", depth)
					}
					for rep := 0; rep < cfg.Repetitions; rep++ {
						// Rotate targets across repetitions so results are not an
						// artefact of one transaction's position in the ledger.
						target := targets[rep%len(targets)]

						p, err := runOne(ctx, s, cfg.AuditorID, target, ledger, depth)
						if err != nil {
							return nil, fmt.Errorf("exp3: %s at ledger %d depth %d: %w",
								s.Name(), ledger, depth, err)
						}
						p.Repetition = rep
						p.SetupParams = overrides
						res.Points = append(res.Points, p)
					}
				}
			}
		}

		// Scaling is classified per setup configuration: pooling an arity-2 run
		// with an arity-10 run would compare two different trees and report the
		// difference as ledger scaling.
		res.LedgerScaling[s.Name()] = classifyScaling(res.Points[schemeStart:], s)
	}
	return res, nil
}

func runOne(
	ctx context.Context,
	s scheme.Scheme,
	auditorID, targetTx string,
	ledgerSize, depth int,
) (Point, error) {
	q := &scheme.AuditQuery{
		AuditorID:  auditorID,
		TargetTxID: targetTx,
	}

	start := time.Now()
	r, err := s.Audit(ctx, q)
	total := time.Since(start)
	if err != nil {
		return Point{}, err
	}

	// A scheme claiming ledger independence that traversed the whole ledger is
	// contradicting its own capability declaration. Surfacing it here beats
	// discovering it when the headline plot fails to be flat.
	if s.Capabilities().LedgerIndependentAudit && r.BlocksTraversed >= ledgerSize {
		return Point{}, fmt.Errorf(
			"%s declares LedgerIndependentAudit but traversed %d of %d blocks",
			s.Name(), r.BlocksTraversed, ledgerSize)
	}

	return Point{
		Scheme:            s.Name(),
		LedgerSize:        ledgerSize,
		HistoryDepth:      depth,
		Semantics:         string(r.Semantics),
		Verified:          r.Verified,
		RetrievalTime:     r.RetrievalTime,
		VerificationTime:  r.VerificationTime,
		TotalTime:         total,
		AuthorizationTime: r.AuthorizationTime,
		EvidenceBytes:     r.EvidenceBytes,
		BlocksTraversed:   r.BlocksTraversed,
		RecordsReturned:   len(r.History),
	}, nil
}

// classifyScaling compares cost at the largest and smallest ledger sizes, at the
// shallowest history depth so that history is held constant.
func classifyScaling(points []Point, s scheme.Scheme) ScalingClass {
	name := s.Name()

	// Hold history depth fixed at its minimum: the headline plot varies only
	// ledger size.
	minDepth := -1
	for _, p := range points {
		if p.Scheme != name {
			continue
		}
		if minDepth < 0 || p.HistoryDepth < minDepth {
			minDepth = p.HistoryDepth
		}
	}
	if minDepth < 0 {
		return ScalingClass{}
	}

	type agg struct {
		total time.Duration
		n     int
	}
	by := make(map[int]*agg)
	for _, p := range points {
		if p.Scheme != name || p.HistoryDepth != minDepth {
			continue
		}
		a, ok := by[p.LedgerSize]
		if !ok {
			a = &agg{}
			by[p.LedgerSize] = a
		}
		a.total += p.TotalTime
		a.n++
	}
	if len(by) < 2 {
		return ScalingClass{}
	}

	sizes := make([]int, 0, len(by))
	for sz := range by {
		sizes = append(sizes, sz)
	}
	small, large := minInt(sizes), maxInt(sizes)

	meanAt := func(sz int) float64 {
		a := by[sz]
		if a == nil || a.n == 0 {
			return 0
		}
		return float64(a.total) / float64(a.n)
	}
	cs, cl := meanAt(small), meanAt(large)
	if cs <= 0 {
		return ScalingClass{}
	}

	costRatio := cl / cs
	sizeRatio := float64(large) / float64(small)

	// Thresholds are reporting conventions, not claims. All underlying points
	// are retained so a reader can apply a different model.
	var class string
	switch {
	case costRatio < 1.2:
		class = "flat"
	case costRatio < sizeRatio*0.5:
		class = "sublinear"
	default:
		class = "linear"
	}

	return ScalingClass{
		CostRatio:  costRatio,
		SizeRatio:  sizeRatio,
		Class:      class,
		ClaimHolds: !s.Capabilities().LedgerIndependentAudit || class != "linear",
	}
}

func maxInt(xs []int) int {
	m := xs[0]
	for _, x := range xs {
		if x > m {
			m = x
		}
	}
	return m
}

func minInt(xs []int) int {
	m := xs[0]
	for _, x := range xs {
		if x < m {
			m = x
		}
	}
	return m
}
