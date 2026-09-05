//go:build live

package ref10

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

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
			"peer_endpoint":      "localhost:7051",
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

	auth, err := s.Authorize(ctx, request("live-req-1", requester, "tx-00000003"))
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
