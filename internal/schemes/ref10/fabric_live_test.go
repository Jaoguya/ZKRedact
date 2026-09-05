//go:build live

package ref10

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"zkredact/pkg/config"
	"zkredact/pkg/scheme"
)

// Live integration test for the Fabric vote transport.
//
//	go test -tags live ./internal/schemes/ref10/ -run TestLive -v
//
// Requires a running network with the chaincode deployed:
//
//	network/scripts/network.sh up minimal
//	network/scripts/network.sh deploy
//
// WHY IT IS SEPARATE. Everything else in this package runs against a fake
// session, which verifies the protocol's shape but not that it works against a
// real peer. Three defects lived in exactly that gap — RegisterNodes never
// called, committee_size absent from the wire, and member ids used directly as
// Fabric identity directory names — and all three passed the fake-based tests.
//
// Build-tagged rather than skipped so a normal `go test ./...` does not depend
// on Docker, while `-tags live` cannot silently pass when the network is down.

const liveNetworkRoot = "../../../network"

// liveRunID makes request ids unique per run.
//
// The contract address derives from the request id, and a round cannot be
// reopened — so fixed ids pass on a fresh ledger and fail on every rerun with
// "round already exists". That reads as a contract defect rather than as test
// state, and it means the suite could only ever be run once per network.
var liveRunID = time.Now().UTC().Format("150405.000")

func liveReq(name string) string { return fmt.Sprintf("live-%s-%s", liveRunID, name) }

func liveGatewayParams(t *testing.T) map[string]any {
	t.Helper()

	cryptoPath, err := filepath.Abs(filepath.Join(
		liveNetworkRoot, "organizations", "peerOrganizations", "org1.example.com"))
	if err != nil {
		t.Fatalf("resolve crypto path: %v", err)
	}
	if _, err := os.Stat(cryptoPath); err != nil {
		t.Fatalf("no crypto material at %s: bring the network up first "+
			"(network/scripts/network.sh up minimal)", cryptoPath)
	}
	tlsCert := filepath.Join(cryptoPath, "peers", "peer0.org1.example.com", "tls", "ca.crt")

	// peer0.org1 is exposed at 7051 on the minimal topology and 11051 on the
	// full one; the marker says which is running.
	endpoint := "localhost:7051"
	if b, err := os.ReadFile(filepath.Join(liveNetworkRoot, ".topology")); err == nil &&
		strings.TrimSpace(string(b)) == "full" {
		endpoint = "localhost:11051"
	}

	return map[string]any{
		"committee_size":         3,
		"vote_threshold":         2,
		"vote_window_ms":         30000,
		"attribute_policy":       "S OR R OR V",
		"vote_transport":         transportFabric,
		"signature_curve":        "P-256",
		"hash":                   "SHA-256",
		"block_max_transactions": 100,
		"gateway": map[string]any{
			"peer_endpoint":      endpoint,
			"peer_server_name":   "peer0.org1.example.com",
			"tls_cert_path":      tlsCert,
			"msp_id":             "Org1MSP",
			"crypto_path":        cryptoPath,
			"channel":            "redaction",
			"chaincode":          "redaction",
			"endorse_timeout_ms": 30000,
			"commit_timeout_ms":  60000,
		},
	}
}

// liveDataset builds a corpus whose identity count fits the Fabric identities
// cryptogen produced. buildIdentityMap refuses a partial mapping, so this is
// the constraint a real run has to satisfy too.
func liveDataset(t *testing.T, identities int) *scheme.Dataset {
	t.Helper()
	ds := testDataset(20, 30)
	if len(ds.Identities) > identities {
		ds.Identities = ds.Identities[:identities]
	}
	return ds
}

// TestLiveSetupRegistersNodesAndMapsIdentities covers defects 1 and 3 against a
// real peer: Setup must publish the node set and resolve every member onto
// crypto material that actually exists on disk.
func TestLiveSetupRegistersNodesAndMapsIdentities(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	s := New()
	err := s.Setup(ctx, scheme.SetupParams{
		Dataset:      liveDataset(t, 6),
		Seed:         42,
		SecurityBits: 128,
		Params:       liveGatewayParams(t),
	})
	if err != nil {
		t.Fatalf("Setup against the live network failed: %v", err)
	}
	t.Cleanup(func() { _ = s.Teardown(context.Background()) })

	if s.transport.Name() != transportFabric {
		t.Fatalf("transport is %q, want %q — the run would report networked "+
			"voting while using function calls", s.transport.Name(), transportFabric)
	}
}

// TestLiveAuthorizeRunsVotesThroughTheLedger is the end-to-end check the
// fake-based tests cannot make: ballots are endorsed, ordered and tallied by the
// deployed contract.
func TestLiveAuthorizeRunsVotesThroughTheLedger(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	ds := liveDataset(t, 6)
	s := New()
	if err := s.Setup(ctx, scheme.SetupParams{
		Dataset:      ds,
		Seed:         42,
		SecurityBits: 128,
		Params:       liveGatewayParams(t),
	}); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	t.Cleanup(func() { _ = s.Teardown(context.Background()) })

	// Pick a requester the policy actually admits, so a denial here means the
	// protocol rejected it rather than the fixture being wrong.
	requester := eligibleRequester(t, s)

	auth, err := s.Authorize(ctx, request(liveReq("single"), requester, "tx-00000003"))
	if err != nil {
		t.Fatalf("Authorize over the fabric transport: %v", err)
	}
	if !auth.Granted {
		t.Fatalf("the committee did not approve an eligible request: %s", auth.Reason)
	}
	if auth.Evidence == nil {
		t.Error("authorization carries no evidence; Sigma was not retained")
	}
}

// TestLiveRefusesWhenIdentitiesAreShort pins defect 3's guard against real
// crypto material: asking for more members than there are Fabric identities
// must stop at Setup, not at vote time.
func TestLiveRefusesWhenIdentitiesAreShort(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// The minimal topology generates 8 users; 500 identities cannot be mapped.
	err := New().Setup(ctx, scheme.SetupParams{
		Dataset:      testDataset(20, 500),
		Seed:         42,
		SecurityBits: 128,
		Params:       liveGatewayParams(t),
	})
	if err == nil {
		t.Fatal("Setup accepted more members than there are Fabric identities")
	}
	t.Logf("refused as expected: %v", err)
}

// liveConcurrencyLevels returns the levels to drive the transport at.
//
// They are read from experiments.verification_throughput.concurrency_levels in
// config/experiment.yaml — the levels Exp 1 actually sweeps — rather than
// written here as a literal. A constant in this file drifts below what the
// experiment does, and then the transport is only ever checked at a level no
// measured run uses.
//
// LIVE_CONCURRENCY_LEVELS scopes a run down for a host that cannot carry the
// full sweep (a laptop peer runs out of connections long before a c6i.8xlarge
// does). It overrides this check, never the experiment.
func liveConcurrencyLevels(t *testing.T) []int {
	t.Helper()

	if raw := os.Getenv("LIVE_CONCURRENCY_LEVELS"); raw != "" {
		var levels []int
		for _, f := range strings.Split(raw, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(f))
			if err != nil || n < 1 {
				t.Fatalf("LIVE_CONCURRENCY_LEVELS=%q: %q is not a positive integer", raw, f)
			}
			levels = append(levels, n)
		}
		t.Logf("levels overridden by LIVE_CONCURRENCY_LEVELS: %v", levels)
		return levels
	}

	cfgPath, err := filepath.Abs(filepath.Join(liveNetworkRoot, "..", "config", "experiment.yaml"))
	if err != nil {
		t.Fatalf("resolve config path: %v", err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load %s: %v", cfgPath, err)
	}
	levels := cfg.Experiments.VerificationThroughput.ConcurrencyLevels
	if len(levels) == 0 {
		t.Fatal("config has no experiments.verification_throughput.concurrency_levels")
	}
	return levels
}

// TestLiveConcurrentAuthorize drives the fabric transport the way Exp 1 does.
//
// Everything before this exercised one request at a time. Exp 1 runs up to 1024
// concurrent authorizations, and the transport caches a gateway per member
// behind a mutex while the contract enforces one ballot per member per round —
// neither of which a single-request test can exercise.
//
// Three failures would be invisible in aggregate numbers rather than loud:
//
//   - A data race in the session cache. Under -race it is a test failure; in a
//     measured run it is a crash partway through a sweep, or worse, silent
//     corruption of the ballots.
//   - Rounds interfering with each other. Each request has its own contract
//     address, so concurrent rounds must not see each other's ballots. If they
//     did, approvals would leak across requests and the approval rate would
//     rise with concurrency — which reads as a throughput result.
//   - Endorsement timeouts and exhausted gateway connections. Both surface as
//     an error here; in a measured run they surface as latency, which reads as
//     the protocol being slow rather than as the harness failing.
//
// The approval rate is the invariant: every request is the same eligible
// requester, so it must be 100% at every level. A rate that moves with
// concurrency is the signal, whichever direction it moves in.
func TestLiveConcurrentAuthorize(t *testing.T) {
	levels := liveConcurrencyLevels(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
	defer cancel()

	s := New()
	if err := s.Setup(ctx, scheme.SetupParams{
		Dataset:      liveDataset(t, 6),
		Seed:         42,
		SecurityBits: 128,
		Params:       liveGatewayParams(t),
	}); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	t.Cleanup(func() { _ = s.Teardown(context.Background()) })

	requester := eligibleRequester(t, s)

	for _, concurrency := range levels {
		t.Run(fmt.Sprintf("concurrency=%d", concurrency), func(t *testing.T) {
			type outcome struct {
				granted bool
				err     error
			}
			results := make(chan outcome, concurrency)

			started := time.Now()
			for i := 0; i < concurrency; i++ {
				go func(n int) {
					auth, err := s.Authorize(ctx, request(
						liveReq(fmt.Sprintf("conc-%d-%d", concurrency, n)),
						requester, "tx-00000003"))
					if err != nil {
						results <- outcome{err: err}
						return
					}
					results <- outcome{granted: auth.Granted}
				}(i)
			}

			granted, denied, failed := 0, 0, 0
			var firstErr error
			for i := 0; i < concurrency; i++ {
				r := <-results
				switch {
				case r.err != nil:
					failed++
					if firstErr == nil {
						firstErr = r.err
					}
				case r.granted:
					granted++
				default:
					denied++
				}
			}
			elapsed := time.Since(started)

			// Wall time per level, so an endorsement timeout is legible as a
			// stall rather than as the protocol's cost.
			t.Logf("concurrency=%d granted=%d denied=%d failed=%d elapsed=%s",
				concurrency, granted, denied, failed, elapsed.Round(time.Millisecond))

			if failed > 0 {
				t.Errorf("%d of %d authorizations returned an error; in a measured "+
					"run this reads as latency, not as failure. First: %v",
					failed, concurrency, firstErr)
			}
			// Every request is the same eligible requester on the same
			// transaction, so all should be granted. A denial under concurrency
			// that does not occur serially means rounds are interfering.
			if granted != concurrency {
				t.Errorf("%d of %d concurrent authorizations granted; the same request "+
					"succeeds on its own, so rounds are interfering", granted, concurrency)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Where the authorization latency actually goes
// -----------------------------------------------------------------------------

// liveBlockTimeout reads the channel's batch timeout from the config.
//
// It is the unit the whole cost model is expressed in, so reading it beats
// restating it: if the channel is reconfigured, this test re-derives rather
// than silently comparing against a stale constant.
func liveBlockTimeout(t *testing.T) time.Duration {
	t.Helper()

	cfgPath, err := filepath.Abs(filepath.Join(liveNetworkRoot, "..", "config", "experiment.yaml"))
	if err != nil {
		t.Fatalf("resolve config path: %v", err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load %s: %v", cfgPath, err)
	}
	ms := cfg.Environment.Network.BlockTimeoutMS
	if ms == nil || *ms <= 0 {
		t.Fatal("config has no environment.network.block_timeout_ms")
	}
	return time.Duration(*ms) * time.Millisecond
}

// TestLiveAuthorizationCostIsBlockTime pins WHY one authorization costs what it
// does over the fabric transport, and that the cost does not grow with the
// committee.
//
// A round issues three ordered transactions, whatever the committee size:
//
//	Init    open the round
//	Vote    every member's ballot, submitted concurrently, sharing one block
//	Close   tally the ballots and emit tx_rdt
//
// So the cost is 3 x block_timeout and the slope in committee_size is ZERO.
// That flatness is the property under test. It held only after the tally was
// split out of Vote: while Vote tallied, it read every member's ballot key,
// two ballots could not share a block, and a round cost
// (1 + committee_size) blocks — 16.3 s at size 7 instead of 6.1 s, an inflation
// of Ref[10]'s latency that biased Exp 1 in ZK-Redact's favour.
//
// A non-zero slope here means ballots have stopped sharing a block. The likely
// cause is a read of another member's ballot creeping back into Vote, which
// would reintroduce the MVCC conflict that forced serialization.
func TestLiveAuthorizationCostIsBlockTime(t *testing.T) {
	block := liveBlockTimeout(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// Committee sizes to sweep. Each needs a real majority threshold, which
	// ref10.Setup enforces independently.
	sizes := []int{3, 5, 7}

	// Init + one shared ballot block + Close.
	const blocksPerRound = 3

	type sample struct {
		size    int
		elapsed time.Duration
	}
	var samples []sample

	for _, size := range sizes {
		params := liveGatewayParams(t)
		params["committee_size"] = size
		params["vote_threshold"] = size/2 + 1

		s := New()
		if err := s.Setup(ctx, scheme.SetupParams{
			Dataset:      liveDataset(t, 12),
			Seed:         42,
			SecurityBits: 128,
			Params:       params,
		}); err != nil {
			t.Fatalf("Setup at committee_size=%d: %v", size, err)
		}

		requester := eligibleRequester(t, s)

		started := time.Now()
		auth, err := s.Authorize(ctx,
			request(liveReq(fmt.Sprintf("cost-%d", size)), requester, "tx-00000003"))
		elapsed := time.Since(started)
		_ = s.Teardown(context.Background())

		if err != nil {
			t.Fatalf("Authorize at committee_size=%d: %v", size, err)
		}
		if !auth.Granted {
			t.Fatalf("committee_size=%d: eligible request denied: %s", size, auth.Reason)
		}

		predicted := time.Duration(blocksPerRound) * block
		t.Logf("committee_size=%-2d elapsed=%-8s predicted=%dx%s=%-8s ratio=%.2f",
			size, elapsed.Round(time.Millisecond), blocksPerRound, block,
			predicted.Round(time.Millisecond),
			float64(elapsed)/float64(predicted))

		samples = append(samples, sample{size: size, elapsed: elapsed})
	}

	// 35% covers endorsement, the commit-status round trip and scheduling
	// jitter on top of the block waits; the measured overshoot is ~2%. Wide
	// enough not to flake, far too tight to admit an extra block.
	const tolerance = 1.35
	predicted := time.Duration(blocksPerRound) * block

	for _, s := range samples {
		if s.elapsed > time.Duration(float64(predicted)*tolerance) {
			t.Errorf("committee_size=%d took %s against a predicted %s (%d blocks): "+
				"a round is paying for more than Init, one ballot block and Close",
				s.size, s.elapsed.Round(time.Millisecond),
				predicted.Round(time.Millisecond), blocksPerRound)
		}
		if s.elapsed < time.Duration(float64(predicted)*0.5) {
			t.Errorf("committee_size=%d took only %s against a predicted %s: "+
				"transactions are not waiting for ordering, so this is not "+
				"measuring the networked protocol",
				s.size, s.elapsed.Round(time.Millisecond),
				predicted.Round(time.Millisecond))
		}
	}

	// The headline invariant: cost must not grow with committee size.
	first, last := samples[0], samples[len(samples)-1]
	slope := (last.elapsed - first.elapsed) / time.Duration(last.size-first.size)
	t.Logf("per-member slope=%s across committee_size %d..%d (must be ~0; "+
		"one block=%s means ballots stopped sharing a block)",
		slope.Round(time.Millisecond), first.size, last.size, block)

	// Half a block per member is far below the one-block-per-member that
	// serialization costs, and far above measurement noise.
	if slope > block/2 {
		t.Errorf("each extra committee member adds %s: ballots are no longer "+
			"sharing a block. Check whether Vote reads another member's ballot "+
			"key again — that is what forces one ballot per block.",
			slope.Round(time.Millisecond))
	}
}
