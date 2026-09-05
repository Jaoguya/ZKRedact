package ref10

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests cover the three defects a review found on the fabric path, all of
// which were unreachable from the in-process transport and so had passed every
// existing test:
//
//   1. RegisterNodes was never called, so the contract held no node set.
//   2. Init selected every eligible node instead of committee_size.
//   3. Member ids were used directly as Fabric identity directory names.
//
// None would have crashed at build time. Each would have failed at run time
// pointing somewhere other than its cause.

// fakeCryptoDir builds a cryptogen-shaped users/ tree.
func fakeCryptoDir(t *testing.T, users []string) string {
	t.Helper()
	root := t.TempDir()
	for _, u := range users {
		msp := filepath.Join(root, "users", u, "msp")
		for _, sub := range []string{"signcerts", "keystore"} {
			if err := os.MkdirAll(filepath.Join(msp, sub), 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
		}
	}
	return root
}

func TestIdentityMapPairsMembersWithFabricUsers(t *testing.T) {
	root := fakeCryptoDir(t, []string{
		"Admin@org1.example.com",
		"User1@org1.example.com",
		"User2@org1.example.com",
		"User3@org1.example.com",
	})
	members := []string{"id-000000", "id-000001", "id-000002"}

	m, err := buildIdentityMap(root, members)
	if err != nil {
		t.Fatalf("buildIdentityMap: %v", err)
	}

	for _, id := range members {
		dir, err := m.resolve(id)
		if err != nil {
			t.Fatalf("resolve(%s): %v", id, err)
		}
		if !strings.HasPrefix(dir, "User") {
			t.Errorf("member %s resolved to %q, which is not a voting identity", id, dir)
		}
	}
}

// TestIdentityMapExcludesAdmin: the org administrator is not a committee
// member. Mapping a member onto it would let an identity outside the node set
// cast a ballot.
func TestIdentityMapExcludesAdmin(t *testing.T) {
	root := fakeCryptoDir(t, []string{
		"Admin@org1.example.com",
		"User1@org1.example.com",
	})
	m, err := buildIdentityMap(root, []string{"id-000000"})
	if err != nil {
		t.Fatalf("buildIdentityMap: %v", err)
	}
	dir, _ := m.resolve("id-000000")
	if strings.HasPrefix(dir, "Admin@") {
		t.Errorf("a member was mapped onto the org administrator")
	}
}

// TestIdentityMapRefusesPartialCoverage is the guard for defect 3's worst form.
//
// Mapping only what fits would produce a run where some committees can vote and
// others cannot, and the difference would surface as a varying approval rate
// that looks like a property of the protocol.
func TestIdentityMapRefusesPartialCoverage(t *testing.T) {
	root := fakeCryptoDir(t, []string{
		"Admin@org1.example.com",
		"User1@org1.example.com",
		"User2@org1.example.com",
	})
	members := []string{"id-000000", "id-000001", "id-000002", "id-000003"}

	_, err := buildIdentityMap(root, members)
	if err == nil {
		t.Fatal("a partial identity map was accepted")
	}
	// The message must name both counts, or the reader cannot tell which side
	// to change.
	if !strings.Contains(err.Error(), "2 Fabric identities") ||
		!strings.Contains(err.Error(), "4 members") {
		t.Errorf("error does not name both counts: %v", err)
	}
}

func TestIdentityMapIsDeterministic(t *testing.T) {
	root := fakeCryptoDir(t, []string{
		"User3@org1.example.com", "User1@org1.example.com", "User2@org1.example.com",
	})
	members := []string{"id-000002", "id-000000", "id-000001"}

	first, err := buildIdentityMap(root, members)
	if err != nil {
		t.Fatalf("buildIdentityMap: %v", err)
	}
	for i := 0; i < 5; i++ {
		again, err := buildIdentityMap(root, members)
		if err != nil {
			t.Fatalf("buildIdentityMap: %v", err)
		}
		for _, id := range members {
			a, _ := first.resolve(id)
			b, _ := again.resolve(id)
			if a != b {
				t.Fatalf("mapping for %s varied between builds: %q then %q; "+
					"reproducibility requires a stable pairing", id, a, b)
			}
		}
	}
}

func TestIdentityMapReportsMissingCryptoMaterial(t *testing.T) {
	_, err := buildIdentityMap(filepath.Join(t.TempDir(), "absent"), []string{"id-000000"})
	if err == nil {
		t.Fatal("a missing crypto directory was accepted")
	}
	// The message should point at the fix, not just the symptom.
	if !strings.Contains(err.Error(), "network.sh up") {
		t.Errorf("error does not say how to produce the material: %v", err)
	}
}

func TestResolveRejectsUnmappedMember(t *testing.T) {
	root := fakeCryptoDir(t, []string{"User1@org1.example.com"})
	m, _ := buildIdentityMap(root, []string{"id-000000"})

	if _, err := m.resolve("id-999999"); err == nil {
		t.Error("an unmapped member resolved to an identity")
	}
}

// -----------------------------------------------------------------------------
// Node registration
// -----------------------------------------------------------------------------

// TestRegisterNodesPublishesTheSet covers defect 1. Without this call the
// contract holds no node set and every round fails at Init with "no nodes
// registered", which reads as a chaincode fault rather than a missing step.
func TestRegisterNodesPublishesTheSet(t *testing.T) {
	r := testVoteRound(t, 5, true)
	f := newFakeFactory("{}")
	tr := newFabricTransport(f)

	if err := registerNodes(context.Background(), tr, r.Members); err != nil {
		t.Fatalf("registerNodes: %v", err)
	}

	var found bool
	for _, c := range f.log.snapshot() {
		if c.Fn != "RegisterNodes" {
			continue
		}
		found = true
		if c.Kind != "submit" {
			t.Errorf("RegisterNodes must be submitted; it writes the node set")
		}
		for _, m := range r.Members {
			if !strings.Contains(c.Args[0], m.Identity.ID) {
				t.Errorf("member %s is missing from the registered set", m.Identity.ID)
			}
		}
	}
	if !found {
		t.Error("registerNodes made no RegisterNodes call")
	}
}

// TestRegisterNodesIsNoOpInProcess: the in-process transport keeps the node set
// in memory, so demanding a network call there would break the fast path.
func TestRegisterNodesIsNoOpInProcess(t *testing.T) {
	r := testVoteRound(t, 3, true)
	if err := registerNodes(context.Background(), localTransport{}, r.Members); err != nil {
		t.Errorf("registerNodes failed for the in-process transport: %v", err)
	}
}

func TestRegisterNodesRefusesEmptySet(t *testing.T) {
	tr := newFabricTransport(newFakeFactory("{}"))
	if err := registerNodes(context.Background(), tr, nil); err == nil {
		t.Error("an empty node set was registered")
	}
}

// -----------------------------------------------------------------------------
// Committee size on the wire
// -----------------------------------------------------------------------------

// TestEncodeRoundCarriesCommitteeSize covers defect 2.
//
// The contract selected every eligible node when this field was absent, so a
// registered node that was NOT selected could still have its vote counted —
// the membership guard failing open. The eligible pool is usually far larger
// than the committee, so the gap is not marginal.
func TestEncodeRoundCarriesCommitteeSize(t *testing.T) {
	r := testVoteRound(t, 7, true)

	roundJSON, err := encodeRound(r)
	if err != nil {
		t.Fatalf("encodeRound: %v", err)
	}
	if !strings.Contains(roundJSON, `"committee_size"`) {
		t.Fatalf("round JSON omits committee_size; the contract would select the "+
			"entire eligible pool\n  %s", roundJSON)
	}

	var decoded chainRound
	if err := json.Unmarshal([]byte(roundJSON), &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.CommitteeSize != len(r.Members) {
		t.Errorf("committee_size = %d, want %d", decoded.CommitteeSize, len(r.Members))
	}
	if decoded.Threshold > decoded.CommitteeSize {
		t.Errorf("threshold %d exceeds committee size %d; no redaction could be approved",
			decoded.Threshold, decoded.CommitteeSize)
	}
}

func TestFabricTransportRoundJSONIsWellFormed(t *testing.T) {
	r := testVoteRound(t, 3, true)
	roundJSON, err := encodeRound(r)
	if err != nil {
		t.Fatalf("encodeRound: %v", err)
	}
	var decoded chainRound
	if err := json.Unmarshal([]byte(roundJSON), &decoded); err != nil {
		t.Fatalf("round JSON does not decode: %v\n  %s", err, roundJSON)
	}
	if decoded.ContractAddr != r.ContractAddr {
		t.Errorf("contract address did not survive: %q", decoded.ContractAddr)
	}
}
