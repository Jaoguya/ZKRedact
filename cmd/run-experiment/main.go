// Command run-experiment executes one experiment end to end.
//
//	run-experiment -exp verification   # Exp 1
//	run-experiment -exp redaction      # Exp 2
//	run-experiment -exp audit          # Exp 3
//	run-experiment -exp all
//
// Flags:
//
//	-config   path to experiment.yaml (default config/experiment.yaml)
//	-dry-run  build the dataset and trace, report what would run, execute nothing
//
// The order of operations is deliberate. The shared dataset and request trace
// are generated ONCE and handed to every scheme, so no system can be measured
// against a workload the others did not receive. Setup is excluded from timing:
// the four schemes cannot share a ledger format, so each materialises the same
// source data into its own representation first.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	exp1 "zkredact/experiments/exp1_verification"
	exp2 "zkredact/experiments/exp2_redaction"
	exp3 "zkredact/experiments/exp3_audit"
	"zkredact/internal/schemes"
	"zkredact/pkg/config"
	"zkredact/pkg/metrics"
	"zkredact/pkg/results"
	"zkredact/pkg/scheme"
	"zkredact/pkg/workload"
)

func main() {
	var (
		configPath = flag.String("config", config.DefaultPath, "path to experiment.yaml")
		expName    = flag.String("exp", "", "experiment: verification | redaction | audit | all")
		dryRun     = flag.Bool("dry-run", false, "prepare and report, but execute nothing")
		only       = flag.String("schemes", "", "comma-separated subset of enabled systems to run; "+
			"produces a PARTIAL comparison, recorded as such in results")
	)
	flag.Parse()

	if *expName == "" {
		fmt.Fprintln(os.Stderr, "error: -exp is required (verification | redaction | audit | all)")
		flag.Usage()
		os.Exit(2)
	}

	if err := run(*configPath, *expName, *dryRun, *only); err != nil {
		fmt.Fprintf(os.Stderr, "\nerror: %v\n", err)
		os.Exit(1)
	}
}

func run(configPath, expName string, dryRun bool, only string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	seed, err := cfg.Seed()
	if err != nil {
		return err
	}
	reps, err := cfg.Repetitions()
	if err != nil {
		return err
	}
	targetBits, err := cfg.TargetBits()
	if err != nil {
		return err
	}

	// Ctrl-C cancels cleanly so a long sweep can be stopped without leaving
	// containers running.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("config      %s (version %s)\n", configPath, cfg.Meta.ConfigVersion)
	fmt.Printf("seed        %d\n", seed)
	fmt.Printf("security    %d-bit\n", targetBits)
	fmt.Printf("repetitions %d\n", reps)

	// Refuse to measure on a host whose clock cannot resolve what is being
	// measured. A coarse clock does not error — it quantises every duration to
	// multiples of its tick, which collapses the latency percentiles and makes
	// the Exp 2 cost decomposition meaningless while still producing a full,
	// plausible-looking results file.
	//
	// Checked before the dataset is built so the failure costs seconds rather
	// than a sweep.
	// A dry run measures nothing: it builds the dataset and trace and reports
	// what would execute. Blocking it would make the dataset unbuildable on
	// every development machine, for a property none of its output depends on.
	// The warning still prints, so the limitation is visible before anyone
	// attempts a real run here.
	if err := metrics.RequireUsableClock(); err != nil {
		if !dryRun {
			return fmt.Errorf("this host cannot be measured on: %w", err)
		}
		fmt.Printf("clock       %v resolution — TOO COARSE TO MEASURE\n", metrics.ClockResolution())
		fmt.Println("            dry run permitted; a real run on this host is refused")
		fmt.Println()
	} else {
		fmt.Printf("clock       %v resolution\n\n", metrics.ClockResolution())
	}

	// -------------------------------------------------------------------------
	// Shared workload — generated once, used by every scheme
	// -------------------------------------------------------------------------
	//
	// The zero-conflict ratio is used for dataset and trace construction here.
	// Exp 2 sweeps conflict ratio and regenerates its own traces per ratio.
	wp, err := cfg.WorkloadParams(0.0)
	if err != nil {
		return err
	}
	wcfg := workload.Config{
		Seed:                   wp.Seed,
		BaseTransactions:       wp.BaseTransactions,
		CorePayloadBytes:       wp.CorePayloadBytes,
		RedactablePayloadBytes: wp.RedactablePayloadBytes,
		IdentityCount:          wp.IdentityCount,
		IdentityAttributes:     wp.IdentityAttributes,
		PolicyCount:            wp.PolicyCount,
		PredicateDepth:         wp.PredicateDepth,
		TotalRequests:          wp.TotalRequests,
		TargetDistribution:     wp.TargetDistribution,
		ZipfS:                  wp.ZipfS,
		ConflictRatio:          wp.ConflictRatio,
	}

	fmt.Println("generating shared dataset...")
	genStart := time.Now()
	ds, err := workload.GenerateDataset(wcfg)
	if err != nil {
		return fmt.Errorf("generate dataset: %w", err)
	}
	trace, err := workload.GenerateTrace(wcfg, ds)
	if err != nil {
		return fmt.Errorf("generate trace: %w", err)
	}
	fmt.Printf("  dataset %s: %d transactions, %d identities, %d policies (%s)\n",
		ds.ID, len(ds.Transactions), len(ds.Identities), len(ds.Policies),
		time.Since(genStart).Round(time.Millisecond))
	fmt.Printf("  trace: %d requests, observed conflict rate %.3f\n\n",
		len(trace), workload.ConflictRate(trace))

	// -------------------------------------------------------------------------
	// Schemes
	// -------------------------------------------------------------------------
	names := cfg.EnabledSchemes()

	// Restricting the system set is for developing and smoke-testing a single
	// scheme. It yields a PARTIAL comparison, so it announces itself here and is
	// recorded in every results file the run writes — a reader months later has
	// no other way to know which flags were passed.
	var partial []string
	if only != "" {
		names, err = restrictSchemes(names, only)
		if err != nil {
			return err
		}
		partial = names
		fmt.Println()
		fmt.Println("  ############################################################")
		fmt.Printf("  # PARTIAL COMPARISON — restricted to %v\n", names)
		fmt.Println("  # Results are NOT a comparison and must not be plotted as one.")
		fmt.Println("  ############################################################")
	}
	fmt.Printf("schemes     %v\n", names)

	matrix, err := schemes.CapabilityMatrix(names)
	if err != nil {
		return err
	}
	printCapabilities(names, matrix)

	systems, err := schemes.NewAll(names)
	if err != nil {
		return err
	}

	if dryRun {
		fmt.Println("dry run: dataset and trace built, nothing executed.")
		return nil
	}

	// Setup is NOT timed — see the package comment.
	fmt.Println("setting up schemes (not timed)...")
	for _, s := range systems {
		params, err := cfg.SchemeParams(s.Name())
		if err != nil {
			return fmt.Errorf("params for %s: %w", s.Name(), err)
		}
		start := time.Now()
		err = s.Setup(ctx, scheme.SetupParams{
			Dataset:      ds,
			Seed:         seed,
			SecurityBits: targetBits,
			Params:       params,
		})
		if err != nil {
			// Setup failure is fatal for the whole run. Continuing with the
			// remaining schemes would produce a comparison silently missing one
			// system, which is worse than no comparison at all.
			return fmt.Errorf("setup %s: %w", s.Name(), err)
		}
		fmt.Printf("  %-12s ready (%s)\n", s.Name(), time.Since(start).Round(time.Millisecond))
	}
	defer func() {
		for _, s := range systems {
			_ = s.Teardown(context.Background())
		}
	}()

	writer, err := results.NewWriter(cfg.Output.ResultsDir, cfg.Output.Formats)
	if err != nil {
		return err
	}
	commit, dirty := results.GitInfo()

	meta := func(name string) results.Metadata {
		return results.Metadata{
			Experiment:        name,
			Timestamp:         time.Now(),
			Seed:              seed,
			DatasetID:         ds.ID,
			GitCommit:         commit,
			GitDirty:          dirty,
			ConfigPath:        configPath,
			Environment:       results.Fingerprint(),
			ResolvedConfig:    cfg,
			PartialComparison: partial,
		}
	}

	// -------------------------------------------------------------------------
	// Experiments
	// -------------------------------------------------------------------------
	switch expName {
	case "verification":
		return runExp1(ctx, cfg, reps, systems, trace, writer, meta)
	case "redaction":
		return runExp2(ctx, cfg, reps, systems, trace, writer, meta)
	case "audit":
		return runExp3(ctx, cfg, reps, systems, writer, meta, ds, seed, targetBits)
	case "all":
		if err := runExp1(ctx, cfg, reps, systems, trace, writer, meta); err != nil {
			return err
		}
		if err := runExp2(ctx, cfg, reps, systems, trace, writer, meta); err != nil {
			return err
		}
		return runExp3(ctx, cfg, reps, systems, writer, meta, ds, seed, targetBits)
	default:
		return fmt.Errorf("unknown experiment %q (want verification | redaction | audit | all)", expName)
	}
}

type metaFn func(string) results.Metadata

func runExp1(
	ctx context.Context,
	cfg *config.Config,
	reps int,
	systems []scheme.Scheme,
	trace []*scheme.Request,
	w *results.Writer,
	meta metaFn,
) error {
	e := cfg.Experiments.VerificationThroughput
	if !e.Enabled {
		fmt.Println("\nExp 1 disabled in config, skipping.")
		return nil
	}
	fmt.Println("\n=== Exp 1: Verification Throughput ===")

	ablations := make([]exp1.Ablation, len(e.Ablations))
	for i, a := range e.Ablations {
		ablations[i] = exp1.Ablation{Sharding: a.Sharding, Batching: a.Batching}
	}

	res, err := exp1.Run(ctx, exp1.Config{
		ConcurrencyLevels: e.ConcurrencyLevels,
		Repetitions:       reps,
		ShardCounts:       cfg.ZKRedact.Sharding.Counts,
		NativeBatchVerify: cfg.ZKRedact.ProofBatch.NativeBatchVerify,
		BatchSizes:        cfg.ZKRedact.ProofBatch.Sizes,
		Ablations:         ablations,
	}, systems, trace)
	if err != nil {
		return err
	}

	for name, sat := range res.SaturationPoint {
		if sat == 0 {
			fmt.Printf("  %-12s no saturation inside the sweep — extend concurrency_levels\n", name)
		} else {
			fmt.Printf("  %-12s saturates at concurrency %d\n", name, sat)
		}
	}
	return emit(w, results.Document{Metadata: meta("exp1_verification"), Result: res})
}

func runExp2(
	ctx context.Context,
	cfg *config.Config,
	reps int,
	systems []scheme.Scheme,
	trace []*scheme.Request,
	w *results.Writer,
	meta metaFn,
) error {
	e := cfg.Experiments.RedactionThroughput
	if !e.Enabled {
		fmt.Println("\nExp 2 disabled in config, skipping.")
		return nil
	}
	fmt.Println("\n=== Exp 2: Redaction Throughput ===")

	// Each scheme authorizes the shared trace with its own mechanism inside
	// exp2.Run, untimed. Authorizations carry scheme-specific evidence, so they
	// are not interchangeable between systems.
	res, err := exp2.Run(ctx, exp2.Config{
		BatchSizes:     cfg.ZKRedact.RedactionBatch.Sizes,
		WaitBoundsMS:   cfg.ZKRedact.RedactionBatch.WaitBoundsMS,
		ConflictRatios: cfg.Workload.ConflictRatios,
		Repetitions:    reps,
	}, systems, trace)
	if err != nil {
		return err
	}

	for name, opt := range res.OptimalBatchSize {
		if opt == 0 {
			fmt.Printf("  %-12s still improving at the top of the sweep — extend batch sizes\n", name)
		} else {
			fmt.Printf("  %-12s optimal batch size %d\n", name, opt)
		}
	}
	return emit(w, results.Document{Metadata: meta("exp2_redaction"), Result: res})
}

func runExp3(
	ctx context.Context,
	cfg *config.Config,
	reps int,
	systems []scheme.Scheme,
	w *results.Writer,
	meta metaFn,
	ds *scheme.Dataset,
	seed int64,
	targetBits int,
) error {
	e := cfg.Experiments.ProvenanceAudit
	if !e.Enabled {
		fmt.Println("\nExp 3 disabled in config, skipping.")
		return nil
	}
	fmt.Println("\n=== Exp 3: Provenance Retrieval and Audit Cost ===")

	blockTx := cfg.Environment.Network.BlockMaxTransactions
	if blockTx == nil {
		return fmt.Errorf("exp3: environment.network.block_max_transactions is not set")
	}

	res, err := exp3.Run(ctx, exp3.Config{
		LedgerSizes:   e.LedgerSizes,
		HistoryDepths: e.HistoryDepths,
		Repetitions:   reps,
		AuditorID:     "auditor-0",
		Prepare: func(ctx context.Context, s scheme.Scheme, ledgerSize int) (map[int][]string, error) {
			return prepareLedger(ctx, cfg, ds, seed, targetBits, s, ledgerSize, *blockTx, e.HistoryDepths)
		},
	}, systems)
	if err != nil {
		return err
	}

	for name, sc := range res.LedgerScaling {
		fmt.Printf("  %-12s %s (cost x%.2f over ledger x%.0f)\n",
			name, sc.Class, sc.CostRatio, sc.SizeRatio)
		if !sc.ClaimHolds {
			fmt.Printf("  %-12s WARNING: declares ledger-independent audit but scaled linearly\n", name)
		}
	}
	return emit(w, results.Document{Metadata: meta("exp3_audit"), Result: res})
}

func emit(w *results.Writer, doc results.Document) error {
	paths, err := w.Write(doc)
	if err != nil {
		return fmt.Errorf("write results: %w", err)
	}
	for _, p := range paths {
		fmt.Printf("  wrote %s\n", p)
	}
	return nil
}

// printCapabilities renders the matrix that carries the interpretation of Exp 1,
// where two baselines lead precisely because they do less work.
func printCapabilities(names []string, m map[string]scheme.Capabilities) {
	rows := []struct {
		label string
		get   func(scheme.Capabilities) bool
	}{
		{"privacy-preserving auth", func(c scheme.Capabilities) bool { return c.PrivacyPreservingAuth }},
		{"policy-bound", func(c scheme.Capabilities) bool { return c.PolicyBound }},
		{"decentralized auth", func(c scheme.Capabilities) bool { return c.DecentralizedAuth }},
		{"parallel verification", func(c scheme.Capabilities) bool { return c.ParallelVerification }},
		{"batch redaction", func(c scheme.Capabilities) bool { return c.BatchRedaction }},
		{"per-tx provenance", func(c scheme.Capabilities) bool { return c.PerTxProvenance }},
		{"ledger-independent audit", func(c scheme.Capabilities) bool { return c.LedgerIndependentAudit }},
		{"state freshness check", func(c scheme.Capabilities) bool { return c.StateFreshnessCheck }},
	}

	fmt.Printf("\n%-26s", "capability")
	for _, n := range names {
		fmt.Printf(" %-12s", n)
	}
	fmt.Println()

	for _, r := range rows {
		fmt.Printf("%-26s", r.label)
		for _, n := range names {
			mark := "-"
			if r.get(m[n]) {
				mark = "yes"
			}
			fmt.Printf(" %-12s", mark)
		}
		fmt.Println()
	}
	fmt.Println()
}

// restrictSchemes narrows the enabled set to the named subset.
//
// A name that is not enabled is an error rather than a silent omission: asking
// for a system and receiving results without it is exactly the kind of quiet
// gap that survives into a plot.
func restrictSchemes(enabled []string, csv string) ([]string, error) {
	want := strings.Split(csv, ",")
	out := make([]string, 0, len(want))
	for _, w := range want {
		w = strings.TrimSpace(w)
		if w == "" {
			continue
		}
		found := false
		for _, e := range enabled {
			if e == w {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf(
				"-schemes names %q, which is not among the enabled systems %v", w, enabled)
		}
		out = append(out, w)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("-schemes is empty")
	}
	return out, nil
}

// prepareLedger puts one scheme into the state a single Exp 3 ledger size needs.
//
// Two things happen here, and NEITHER is timed — Exp 3 measures retrieval and
// verification only:
//
//  1. The scheme is re-Setup over a dataset truncated to exactly ledgerSize
//     blocks. Ledger size is the swept axis of the headline plot, so it has to
//     be a real difference in the scheme's state rather than a label on the
//     x-axis. Setup is the interface's own "materialise the corpus" step, so
//     re-running it is how a scheme is legitimately resized.
//
//  2. Target transactions are driven to each configured history depth using the
//     scheme's OWN Authorize and Redact. Fabricating provenance records
//     directly would let a scheme be measured on history it never actually
//     produced, and would skip whatever indexing its design does or does not
//     build along the way — which is the whole subject of this experiment.
//
// One target per depth is enough for the sweep; exp3 rotates across
// repetitions, so more targets only spread the same measurement over more
// transactions.
func prepareLedger(
	ctx context.Context,
	cfg *config.Config,
	full *scheme.Dataset,
	seed int64,
	targetBits int,
	s scheme.Scheme,
	ledgerSize, blockTx int,
	depths []int,
) (map[int][]string, error) {
	need := ledgerSize * blockTx
	if need > len(full.Transactions) {
		return nil, fmt.Errorf(
			"ledger of %d blocks needs %d transactions, dataset holds %d",
			ledgerSize, need, len(full.Transactions))
	}

	sized := &scheme.Dataset{
		ID:           fmt.Sprintf("%s-ledger%d", full.ID, ledgerSize),
		Transactions: full.Transactions[:need],
		Identities:   full.Identities,
		Policies:     full.Policies,
	}

	params, err := cfg.SchemeParams(s.Name())
	if err != nil {
		return nil, err
	}
	if err := s.Setup(ctx, scheme.SetupParams{
		Dataset:      sized,
		Seed:         seed,
		SecurityBits: targetBits,
		Params:       params,
	}); err != nil {
		return nil, fmt.Errorf("re-setup at ledger %d: %w", ledgerSize, err)
	}

	// A requester that satisfies the policy, found by asking the scheme rather
	// than by assuming which identities qualify.
	requester, err := findGrantedRequester(ctx, s, sized)
	if err != nil {
		return nil, err
	}

	out := make(map[int][]string, len(depths))
	next := 0
	for _, depth := range depths {
		if next >= len(sized.Transactions) {
			return nil, fmt.Errorf("dataset exhausted while building history depth %d", depth)
		}
		target := sized.Transactions[next].ID
		next++

		for i := 0; i < depth; i++ {
			req := &scheme.Request{
				ID:          fmt.Sprintf("hist-%d-%s-%d", ledgerSize, target, i),
				RequesterID: requester,
				TargetTxID:  target,
				NewContent:  []byte(fmt.Sprintf("redacted revision %d", i+1)),
				PolicyID:    sized.Policies[0].ID,
				Timestamp:   time.Now(),
			}
			auth, err := s.Authorize(ctx, req)
			if err != nil {
				return nil, fmt.Errorf("building history for %s: %w", target, err)
			}
			if !auth.Granted {
				return nil, fmt.Errorf(
					"building history for %s: authorization denied at revision %d (%s); "+
						"history depth cannot be reached, so the depth axis would be a fiction",
					target, i+1, auth.Reason)
			}
			r, err := s.Redact(ctx, []*scheme.Authorization{auth})
			if err != nil {
				return nil, fmt.Errorf("building history for %s: %w", target, err)
			}
			if r.Succeeded != 1 {
				return nil, fmt.Errorf(
					"building history for %s: revision %d did not commit (%d succeeded, %d stale, %d failed)",
					target, i+1, r.Succeeded, r.StaleExcluded, r.Failed)
			}
		}
		out[depth] = []string{target}
	}
	return out, nil
}

// findGrantedRequester returns an identity the scheme actually authorizes.
//
// Asking rather than assuming: each scheme decides eligibility its own way, and
// hardcoding an identity here would silently break whichever scheme disagrees.
func findGrantedRequester(ctx context.Context, s scheme.Scheme, ds *scheme.Dataset) (string, error) {
	probeTx := ds.Transactions[len(ds.Transactions)-1].ID
	for i, id := range ds.Identities {
		auth, err := s.Authorize(ctx, &scheme.Request{
			ID:          fmt.Sprintf("probe-%d", i),
			RequesterID: id.ID,
			TargetTxID:  probeTx,
			NewContent:  []byte("probe"),
			PolicyID:    ds.Policies[0].ID,
			Timestamp:   time.Now(),
		})
		if err != nil {
			return "", err
		}
		if auth.Granted {
			return id.ID, nil
		}
	}
	return "", fmt.Errorf("%s authorized none of the %d identities; history cannot be built",
		s.Name(), len(ds.Identities))
}
