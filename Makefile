# =============================================================================
# ZK-Redact / VeRedact — build and evaluation
#
# Build order matters: components have inter-dependencies, and experiments run
# against stale builds produce invalid results (SKILL.md).
#
# Every experiment target depends on validate-config. Validation you have to
# remember is validation that gets skipped.
# =============================================================================

SHELL := /bin/bash
.DEFAULT_GOAL := help

CONFIG      ?= config/experiment.yaml
RESULTS_DIR ?= results
BUILD_DIR   ?= build
GO          ?= go

# -----------------------------------------------------------------------------
# Help
# -----------------------------------------------------------------------------
.PHONY: help
help:
	@echo "Build:"
	@echo "  make all                  build every component in dependency order"
	@echo "  make proto                shared protobuf definitions"
	@echo "  make build-ch             chameleon hash library"
	@echo "  make build-zk             ZK circuits and proof verification layer"
	@echo "  make build-gateway        redaction gateway"
	@echo "  make build-pai            provenance audit index"
	@echo "  make build-network        permissioned network"
	@echo "  make deploy-chaincode     deploy chaincode to the network"
	@echo "  make build-baselines      all three baseline implementations"
	@echo ""
	@echo "Verify:"
	@echo "  make validate-config      check $(CONFIG) before running anything"
	@echo "  make test                 full test suite"
	@echo "  make fidelity-check       baseline fidelity tests (negative tests)"
	@echo "  make test-live            live Fabric integration (needs a running network)"
	@echo ""
	@echo "Experiments:"
	@echo "  make pilot                short run to resolve sweep bounds"
	@echo "  make experiments          all three experiments"
	@echo "  make experiment-verification-throughput"
	@echo "  make experiment-redaction-throughput"
	@echo "  make experiment-provenance-audit"
	@echo "  make experiment-e2e       full pipeline under concurrent load"
	@echo ""
	@echo "Results:"
	@echo "  make plots                regenerate plots from $(RESULTS_DIR)"
	@echo "  make clean                remove build artifacts"
	@echo "  make clean-results        remove results (asks first)"

# -----------------------------------------------------------------------------
# Config validation — gate for everything below
# -----------------------------------------------------------------------------
.PHONY: validate-config
validate-config:
	@$(GO) run ./cmd/validate-config $(CONFIG)

# -----------------------------------------------------------------------------
# Build — dependency order per SKILL.md
# -----------------------------------------------------------------------------
.PHONY: all
all: proto build-ch build-zk build-gateway build-pai build-network

.PHONY: proto
proto:
	@echo "==> proto"
	@mkdir -p $(BUILD_DIR)
	@echo "TODO: protoc invocation for pkg/proto"
	@false

.PHONY: build-ch
build-ch: proto
	@echo "==> chameleon hash library"
	@echo "TODO: build pkg/ch"
	@false

.PHONY: build-zk
build-zk: proto
	@echo "==> ZK circuits and PVL (circuit compilation may take several minutes)"
	@echo "TODO: build pkg/zk and internal/pvl"
	@echo "REMINDER: record constraint_count and public_input_count into $(CONFIG)"
	@false

.PHONY: build-gateway
build-gateway: proto build-ch build-zk
	@echo "==> redaction gateway"
	@echo "TODO: build internal/gateway"
	@false

.PHONY: build-pai
build-pai: proto build-ch
	@echo "==> provenance audit index"
	@echo "TODO: build internal/pai"
	@false

.PHONY: build-network
build-network:
	@echo "==> permissioned network"
	@echo "TODO: docker compose up for network/"
	@false

.PHONY: deploy-chaincode
deploy-chaincode: build-network
	@echo "==> deploy chaincode"
	@echo "TODO: deploy network/chaincode"
	@false

# -----------------------------------------------------------------------------
# Baselines
#
# Specs: docs/baselines/*.md — implementation scope, measurement boundaries,
# and deviations are recorded there, not decided here.
# -----------------------------------------------------------------------------
.PHONY: build-baselines
build-baselines: build-baseline-ref10 build-baseline-ref13 build-baseline-ref22

.PHONY: build-baseline-ref10
build-baseline-ref10: proto
	@echo "==> baseline Ref[10] EMT — docs/baselines/ref10-emt.md"
	@false

.PHONY: build-baseline-ref13
build-baseline-ref13: proto
	@echo "==> baseline Ref[13] VRBC — docs/baselines/ref13-vrbc.md"
	@false

.PHONY: build-baseline-ref22
build-baseline-ref22: proto
	@echo "==> baseline Ref[22] Shen — docs/baselines/ref22-shen.md"
	@false

# -----------------------------------------------------------------------------
# Test
# -----------------------------------------------------------------------------
.PHONY: test
test:
	@$(GO) vet ./...
	@$(GO) test ./...

# Compiles every package without running anything - the fastest way to find out
# whether the tree is consistent after an edit.
.PHONY: build
build:
	@$(GO) build ./...

# Baseline fidelity: every verification path must actually REJECT invalid input.
# A commitment scheme that never rejects anything benchmarks beautifully and is
# worthless. See the fidelity checklists in docs/baselines/*.md.
# Live integration against a running network. Build-tagged so a normal
# `make test` does not depend on Docker, and so this cannot silently pass when
# the network is down.
#
# Three defects lived where the fake-based tests could not reach - RegisterNodes
# never called, committee_size absent from the wire, member ids used as identity
# directory names - and a fourth, the client and contract ranking committees
# differently, surfaced only here.
.PHONY: test-live
test-live:
	@echo "==> live integration (requires network.sh up + deploy)"
	@$(GO) test -tags live ./internal/schemes/ref10/ -run TestLive -v -count=1

.PHONY: fidelity-check
fidelity-check:
	@echo "==> baseline fidelity (negative tests)"
	@echo "TODO: Ref[13] must detect a tampered block"
	@echo "TODO: Ref[22] must catch a reversion attack"
	@echo "TODO: Ref[10] must reject a redaction altering core data"
	@echo "TODO: Ref[10] must reject below-threshold votes"
	@false

# -----------------------------------------------------------------------------
# Experiments — all gated behind validate-config
# -----------------------------------------------------------------------------

# Resolves the sweep bounds that cannot be known in advance: repetition count
# from measured variance, and saturation points for the concurrency and batch
# ranges. Run this before the real experiments.
.PHONY: pilot
pilot: validate-config
	@echo "==> pilot: builds dataset and trace, executes nothing"
	$(GO) run ./cmd/run-experiment -config $(CONFIG) -exp verification -dry-run

.PHONY: experiments
experiments: validate-config
	@mkdir -p $(RESULTS_DIR)
	$(GO) run ./cmd/run-experiment -config $(CONFIG) -exp all

.PHONY: experiment-verification-throughput
experiment-verification-throughput: validate-config
	@mkdir -p $(RESULTS_DIR)
	$(GO) run ./cmd/run-experiment -config $(CONFIG) -exp verification

.PHONY: experiment-redaction-throughput
experiment-redaction-throughput: validate-config
	@mkdir -p $(RESULTS_DIR)
	$(GO) run ./cmd/run-experiment -config $(CONFIG) -exp redaction

.PHONY: experiment-provenance-audit
experiment-provenance-audit: validate-config
	@mkdir -p $(RESULTS_DIR)
	$(GO) run ./cmd/run-experiment -config $(CONFIG) -exp audit

.PHONY: experiment-e2e
experiment-e2e: validate-config
	@echo "==> E2E: full pipeline under concurrent load"
	@mkdir -p $(RESULTS_DIR)
	@false

# -----------------------------------------------------------------------------
# Results
# -----------------------------------------------------------------------------
.PHONY: plots
plots:
	@echo "==> plots from $(RESULTS_DIR)"
	@false

.PHONY: clean
clean:
	@rm -rf $(BUILD_DIR)
	@echo "removed $(BUILD_DIR)"

# Results are expensive to regenerate, so this asks first.
.PHONY: clean-results
clean-results:
	@read -p "Delete everything in $(RESULTS_DIR)? [y/N] " ans; \
	if [ "$$ans" = "y" ] || [ "$$ans" = "Y" ]; then \
		rm -rf $(RESULTS_DIR); echo "removed $(RESULTS_DIR)"; \
	else \
		echo "cancelled"; \
	fi
