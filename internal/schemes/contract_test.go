package schemes

import (
	"context"
	"testing"

	"zkredact/pkg/config"
	"zkredact/pkg/scheme"
	"zkredact/pkg/workload"
)

// The contract this file guards is the one that has broken twice.
//
// config.SchemeParams produces the parameter map, and each scheme's Setup
// consumes it. Nothing checked that the two agreed. ref13's arity_q was omitted
// from the map behind a comment claiming a runner injected it — no runner did,
// so Setup failed on a missing parameter and the scheme could not run at all.
// It was invisible because ref13 was the only scheme not yet wired, so nothing
// ever called its Setup.
//
// Package-level tests do not catch this: they build their own parameter maps
// and therefore agree with themselves. This one uses the REAL config file.

func loadConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Load("../../config/experiment.yaml")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	return cfg
}

// contractDataset uses the REAL generator, not a hand-rolled fixture.
//
// Each scheme validates the dataset in its own terms — ref10 needs enough
// eligible identities to form its committee, zkredact needs policy predicates
// its compiler recognises — and hand-writing a dataset that satisfies all four
// means reimplementing pkg/workload's semantics, badly. Using the generator the
// runner uses is both less work and a stronger check.
//
// BaseTransactions is overridden down: the configured 20,000 would make this a
// slow test, and the contract being checked does not depend on ledger size. It
// stays above ref13's challenged_blocks, which is the binding constraint.
func contractDataset(t *testing.T, cfg *config.Config) *scheme.Dataset {
	t.Helper()

	wp, err := cfg.WorkloadParams(0.0)
	if err != nil {
		t.Fatalf("workload params: %v", err)
	}
	wcfg := workload.Config{
		Seed:                   wp.Seed,
		BaseTransactions:       600,
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
	ds, err := workload.GenerateDataset(wcfg)
	if err != nil {
		t.Fatalf("generate dataset: %v", err)
	}
	return ds
}

// TestSchemeParamsSatisfiesEverySetup runs each registered scheme's Setup
// against the parameters the real config produces for it.
//
// It asserts only that Setup does not fail for a MISSING or ill-typed
// parameter. A scheme that needs a live network is allowed to fail for that
// reason — the contract being checked is config-to-scheme, not connectivity.
func TestSchemeParamsSatisfiesEverySetup(t *testing.T) {
	cfg := loadConfig(t)

	for name := range registry {
		t.Run(name, func(t *testing.T) {
			params, err := cfg.SchemeParams(name)
			if err != nil {
				t.Fatalf("SchemeParams(%s): %v", name, err)
			}

			// Every scheme's Setup reads what it needs from this map. A key the
			// scheme requires and the config does not produce is the defect
			// this test exists for.
			s := registry[name]()
			err = s.Setup(context.Background(), scheme.SetupParams{
				Dataset:      contractDataset(t, cfg),
				Seed:         1,
				SecurityBits: *cfg.Security.TargetBits,
				Params:       params,
			})
			if err == nil {
				return
			}
			if isMissingParameter(err) {
				t.Errorf("Setup(%s) failed on a parameter the config does not "+
					"produce: %v", name, err)
			} else {
				t.Logf("Setup(%s) failed for a non-parameter reason, which this "+
					"test does not judge: %v", name, err)
			}
		})
	}
}

// isMissingParameter reports whether the error is about the config-to-scheme
// contract rather than about the environment.
func isMissingParameter(err error) bool {
	msg := err.Error()
	for _, marker := range []string{"missing parameter", "has type", "want a number"} {
		if contains(msg, marker) {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
