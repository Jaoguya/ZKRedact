// Command build-zk compiles the ZK-Redact authorization circuit and reports its
// size.
//
// The two numbers it prints are MEASUREMENTS, not choices:
// zkredact.circuit.constraint_count and public_input_count in
// config/experiment.yaml are filled from this output and then held fixed and
// reported. They set the Exp 1 verification floor, so recording them is what
// makes that floor reproducible.
//
//	go run ./cmd/build-zk -config config/experiment.yaml
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"zkredact/pkg/config"
	"zkredact/pkg/zk"
)

func main() {
	configPath := flag.String("config", config.DefaultPath, "path to experiment.yaml")
	flag.Parse()

	if err := run(*configPath); err != nil {
		fmt.Fprintf(os.Stderr, "build-zk: %v\n", err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	// Circuit shape comes from the dataset the proofs will be about. A shape
	// chosen here instead would compile cleanly and then fail to prove anything
	// about the corpus actually being measured.
	depth := cfg.Dataset.Policies.PredicateDepth
	if depth == nil || *depth < 1 {
		return fmt.Errorf("dataset.policies.predicate_depth is not set")
	}
	identities := cfg.Dataset.Identities.Count
	if identities == nil || *identities < 1 {
		return fmt.Errorf("dataset.identities.count is not set")
	}
	targetBits, err := cfg.TargetBits()
	if err != nil {
		return err
	}

	treeDepth := zk.TreeDepthFor(*identities)

	fmt.Printf("build-zk: %s (version %s)\n\n", configPath, cfg.Meta.ConfigVersion)
	fmt.Printf("  proof system     %s over %s\n", zk.System, zk.Curve)
	fmt.Printf("  security target  %d-bit\n", targetBits)
	fmt.Printf("  predicate depth  %d   (dataset.policies.predicate_depth)\n", *depth)
	fmt.Printf("  registry depth   %d   (%d identities)\n", treeDepth, *identities)
	fmt.Printf("\ncompiling and running trusted setup...\n")

	start := time.Now()
	params, err := zk.Setup(*depth, treeDepth, targetBits)
	if err != nil {
		return err
	}
	elapsed := time.Since(start)

	fmt.Printf("\n  compiled in      %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf("  constraints      %d\n", params.Constraints)
	fmt.Printf("  public inputs    %d\n\n", params.PublicInputs)

	// Compare against what the config records. A recorded measurement that has
	// drifted from the circuit is worse than an absent one: it is reported as
	// the Exp 1 verification floor while describing a circuit nobody is running.
	rec := cfg.ZKRedact.Circuit
	if rec.ConstraintCount == nil || rec.PublicInputCount == nil {
		fmt.Printf("Record these in %s under zkredact.circuit:\n\n", configPath)
		fmt.Printf("    constraint_count:   %d\n", params.Constraints)
		fmt.Printf("    public_input_count: %d\n", params.PublicInputs)
		return nil
	}

	var drift []string
	if *rec.ConstraintCount != params.Constraints {
		drift = append(drift, fmt.Sprintf(
			"constraint_count: config records %d, circuit compiles to %d",
			*rec.ConstraintCount, params.Constraints))
	}
	if *rec.PublicInputCount != params.PublicInputs {
		drift = append(drift, fmt.Sprintf(
			"public_input_count: config records %d, circuit compiles to %d",
			*rec.PublicInputCount, params.PublicInputs))
	}
	if len(drift) > 0 {
		for _, d := range drift {
			fmt.Fprintf(os.Stderr, "  MISMATCH  %s\n", d)
		}
		return fmt.Errorf(
			"recorded circuit size does not match the compiled circuit.\n" +
				"       These are measurements: the circuit changed and the config did not\n" +
				"       follow. Update zkredact.circuit, because the recorded values are\n" +
				"       reported as the Exp 1 verification floor.\n" +
				"       A rise in public_input_count especially: verification costs one\n" +
				"       scalar multiplication each, and it may mean part of the witness\n" +
				"       became public.")
	}

	fmt.Printf("  config agrees with the compiled circuit.\n")
	return nil
}
