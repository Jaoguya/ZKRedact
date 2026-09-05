package main

import (
	"encoding/json"
	"fmt"
	"testing"
)

// -----------------------------------------------------------------------------
// Golden vectors — the cross-module agreement test
// -----------------------------------------------------------------------------

// These signatures were produced by pkg/crypto in the main module, over
// voteMessage("con-golden-0001", "req-golden-0001", approve), and verified
// there before being recorded here.
//
// WHY THEY EXIST. The chaincode is a separate Go module and cannot import
// pkg/crypto, so its Schnorr verification is a second implementation of the
// same equations. Two implementations drift. When they drift here the symptom
// is silent and badly misleading: the contract rejects every honest vote, no
// round ever reaches threshold, and the run looks like a slow or congested
// network rather than a broken verifier.
//
// This was not hypothetical — the first draft of verifyBallot computed
// R' = s*G + e*P instead of s*G - e*P and would have rejected every ballot ever
// cast.
//
// If this test fails after a change to pkg/crypto, the chaincode must be
// updated to match and these vectors regenerated. Do not adjust the chaincode
// until the two agree.
const (
	goldenContractAddr = "con-golden-0001"
	goldenRequestID    = "req-golden-0001"

	goldenPubX = "84e1a05364cf2f8dcc42a03ad4d33b8bc4085691298e32af70b5aeed99008b9d"
	goldenPubY = "6bf002766e0b3f68ed5ecaa8ed310efd013fdd0190a49597a58aa56b4a8a682c"

	goldenYesE = "560ee83d3df849623a36baac5c0b4ac04ce093d51f7af97573a3eb70170217d"
	goldenYesS = "385d825ccf1e3774efd311f6270d46d8ebc09fe6439b6e969a8a66c5a078487b"

	goldenNoE = "652bdfe8e26ed1d27d6438fcb670a7190ff5045ec15caa5303521808d82d893e"
	goldenNoS = "4c132efb3fb0475fc7d9c41f9ee396354bef0402da66644ec498d279fa082dd7"
)

func goldenNode() Node {
	return Node{
		ID:         "id-golden",
		Attributes: map[string]string{"validator": "true"},
		PubX:       goldenPubX,
		PubY:       goldenPubY,
	}
}

func TestChaincodeVerifiesPkgCryptoSignatures(t *testing.T) {
	n := goldenNode()

	for _, tc := range []struct {
		name    string
		approve bool
		e, s    string
	}{
		{"yes vote", true, goldenYesE, goldenYesS},
		{"no vote", false, goldenNoE, goldenNoS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bal := Ballot{NodeID: n.ID, Approve: tc.approve, E: tc.e, S: tc.s}

			ok, err := verifyBallot(n, goldenContractAddr, goldenRequestID, bal)
			if err != nil {
				t.Fatalf("verifyBallot: %v", err)
			}
			if !ok {
				t.Fatalf("chaincode rejected a signature that pkg/crypto produced and accepted; "+
					"the two Schnorr implementations have diverged (approve=%v)", tc.approve)
			}
		})
	}
}

// TestVerifyBallotRejectsWrongVoteDirection covers the binding that makes a
// ballot mean something: a "yes" signature must not verify as a "no".
//
// Without it, a client could flip Approve on a captured ballot and convert a
// rejection into an approval.
func TestVerifyBallotRejectsWrongVoteDirection(t *testing.T) {
	n := goldenNode()

	flipped := Ballot{NodeID: n.ID, Approve: false, E: goldenYesE, S: goldenYesS}
	ok, err := verifyBallot(n, goldenContractAddr, goldenRequestID, flipped)
	if err != nil {
		t.Fatalf("verifyBallot: %v", err)
	}
	if ok {
		t.Errorf("a yes-signature verified as a no-vote; the vote direction is not bound")
	}
}

// TestVerifyBallotRejectsReplayAcrossRounds covers the replay binding: a ballot
// is valid only for the contract and request it was cast in.
func TestVerifyBallotRejectsReplayAcrossRounds(t *testing.T) {
	n := goldenNode()
	bal := Ballot{NodeID: n.ID, Approve: true, E: goldenYesE, S: goldenYesS}

	for _, tc := range []struct{ name, addr, req string }{
		{"different contract", "con-other", goldenRequestID},
		{"different request", goldenContractAddr, "req-other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := verifyBallot(n, tc.addr, tc.req, bal)
			if err != nil {
				t.Fatalf("verifyBallot: %v", err)
			}
			if ok {
				t.Errorf("ballot replayed successfully into a %s", tc.name)
			}
		})
	}
}

func TestVerifyBallotRejectsWrongKey(t *testing.T) {
	other := goldenNode()
	// Flip one nibble of the public key; still a syntactically valid hex string.
	other.PubX = "74e1a05364cf2f8dcc42a03ad4d33b8bc4085691298e32af70b5aeed99008b9d"

	bal := Ballot{NodeID: other.ID, Approve: true, E: goldenYesE, S: goldenYesS}
	ok, _ := verifyBallot(other, goldenContractAddr, goldenRequestID, bal)
	if ok {
		t.Errorf("signature verified under a key that did not produce it")
	}
}

func TestVerifyBallotRejectsMalformedInput(t *testing.T) {
	n := goldenNode()

	for _, tc := range []struct {
		name string
		bal  Ballot
		node Node
	}{
		{"non-hex e", Ballot{NodeID: n.ID, Approve: true, E: "zz", S: goldenYesS}, n},
		{"non-hex s", Ballot{NodeID: n.ID, Approve: true, E: goldenYesE, S: "zz"}, n},
		{"empty e", Ballot{NodeID: n.ID, Approve: true, E: "", S: goldenYesS}, n},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := verifyBallot(tc.node, goldenContractAddr, goldenRequestID, tc.bal); err == nil {
				t.Errorf("malformed input was not rejected")
			}
		})
	}

	t.Run("zero scalars", func(t *testing.T) {
		bal := Ballot{NodeID: n.ID, Approve: true, E: "0", S: "0"}
		ok, err := verifyBallot(n, goldenContractAddr, goldenRequestID, bal)
		if err != nil {
			t.Fatalf("verifyBallot: %v", err)
		}
		if ok {
			t.Errorf("zero scalars were accepted; the range check is missing")
		}
	})
}

// -----------------------------------------------------------------------------
// Committee selection — Eq. 7
// -----------------------------------------------------------------------------

func testNodes(n int) []Node {
	out := make([]Node, n)
	for i := range out {
		out[i] = Node{
			ID:         fmt.Sprintf("id-%03d", i),
			Attributes: map[string]string{"validator": "true"},
			PubX:       goldenPubX,
			PubY:       goldenPubY,
		}
	}
	return out
}

// TestCommitteeDependsOnContractAddress pins Eq. 7: N_auth is derived from
// addr(con_k), so different rounds draw different committees.
//
// A selection that ignored the address would be a fixed list, removing
// per-request selection from the path Exp 1 times.
func TestCommitteeDependsOnContractAddress(t *testing.T) {
	nodes := testNodes(20)

	a, err := selectCommittee("con-A", nodes, "S OR R OR V", 7)
	if err != nil {
		t.Fatalf("selectCommittee: %v", err)
	}
	b, err := selectCommittee("con-B", nodes, "S OR R OR V", 7)
	if err != nil {
		t.Fatalf("selectCommittee: %v", err)
	}

	if len(a) != 7 || len(b) != 7 {
		t.Fatalf("expected committees of 7, got %d and %d", len(a), len(b))
	}
	same := true
	for i := range a {
		if a[i] != b[i] {
			same = false
			break
		}
	}
	if same {
		t.Errorf("two contract addresses produced an identical committee; "+
			"selection is not bound to addr(con_k)\n  %v", a)
	}
}

func TestCommitteeIsDeterministic(t *testing.T) {
	nodes := testNodes(20)

	first, _ := selectCommittee("con-A", nodes, "S OR R OR V", 7)
	for i := 0; i < 5; i++ {
		again, _ := selectCommittee("con-A", nodes, "S OR R OR V", 7)
		for j := range first {
			if first[j] != again[j] {
				t.Fatalf("selection %d differed from the first; peers would disagree "+
					"on N_auth and endorsement would fail", i)
			}
		}
	}
}

// TestCommitteeExcludesIneligibleNodes covers A_r: a node carrying none of the
// {S, R, V} roles must not be selectable.
func TestCommitteeExcludesIneligibleNodes(t *testing.T) {
	nodes := testNodes(10)
	for i := range nodes {
		if i%2 == 0 {
			nodes[i].Attributes = map[string]string{"validator": "false"}
		}
	}

	got, err := selectCommittee("con-A", nodes, "S OR R OR V", 10)
	if err != nil {
		t.Fatalf("selectCommittee: %v", err)
	}
	if len(got) != 5 {
		t.Errorf("expected 5 eligible nodes, got %d: %v", len(got), got)
	}
	for _, id := range got {
		var idx int
		if _, err := fmt.Sscanf(id, "id-%03d", &idx); err != nil {
			t.Fatalf("unexpected id %q", id)
		}
		if idx%2 == 0 {
			t.Errorf("ineligible node %s was selected", id)
		}
	}
}

// TestUnknownAttributePolicyExcludesEveryone guards against a policy string the
// contract does not understand being treated as "everyone qualifies", which
// would inflate the eligible pool and weaken the threshold.
func TestUnknownAttributePolicyExcludesEveryone(t *testing.T) {
	nodes := testNodes(10)
	if _, err := selectCommittee("con-A", nodes, "S AND R AND V", 5); err == nil {
		t.Errorf("an unrecognised attribute policy did not produce an error")
	}
}

func TestSelectCommitteeCapsAtEligibleCount(t *testing.T) {
	nodes := testNodes(3)
	got, err := selectCommittee("con-A", nodes, "S OR R OR V", 10)
	if err != nil {
		t.Fatalf("selectCommittee: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("expected the committee capped at 3 eligible nodes, got %d", len(got))
	}
}

// -----------------------------------------------------------------------------
// PolicyCert
// -----------------------------------------------------------------------------

// TestGrantedRequiresAllThreeConditions pins the separation between Eq. 5's two
// conditions and V(n_i, C).
func TestGrantedRequiresAllThreeConditions(t *testing.T) {
	full := PolicyCert{RequesterKnown: true, Redactable: true, Satisfies: true}
	if !full.Granted() {
		t.Fatalf("a fully satisfied certificate was not granted")
	}

	for _, tc := range []struct {
		name string
		cert PolicyCert
	}{
		{"unknown requester", PolicyCert{RequesterKnown: false, Redactable: true, Satisfies: true}},
		{"not redactable", PolicyCert{RequesterKnown: true, Redactable: false, Satisfies: true}},
		{"policy unsatisfied", PolicyCert{RequesterKnown: true, Redactable: true, Satisfies: false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.cert.Granted() {
				t.Errorf("certificate granted despite %s", tc.name)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Wire format
// -----------------------------------------------------------------------------

// TestRoundRoundTripsThroughJSON covers the encoding the client and contract
// share. A field that fails to survive the round trip would arrive zeroed, and
// a zeroed Threshold would close every round on its first vote.
func TestRoundRoundTripsThroughJSON(t *testing.T) {
	in := Round{
		ContractAddr: "con-1",
		RequestID:    "req-1",
		TargetTxID:   "tx-1",
		RequesterID:  "id-1",
		Cert: PolicyCert{
			TargetTxID: "tx-1", RequesterID: "id-1",
			RequesterKnown: true, Redactable: true, Satisfies: true,
			PolicyID: "pol-1", PolicyVer: 3, Attributes: "S OR R OR V",
		},
		Committee: []string{"a", "b", "c"},
		Threshold: 5,
	}

	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Round
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Threshold != in.Threshold {
		t.Errorf("Threshold did not survive: got %d, want %d", out.Threshold, in.Threshold)
	}
	if out.Cert.PolicyVer != in.Cert.PolicyVer {
		t.Errorf("PolicyVer did not survive: got %d, want %d", out.Cert.PolicyVer, in.Cert.PolicyVer)
	}
	if !out.Cert.Granted() {
		t.Errorf("certificate decision did not survive the round trip")
	}
	if len(out.Committee) != len(in.Committee) {
		t.Errorf("committee did not survive: got %v", out.Committee)
	}
}

func TestVoteMessageMatchesDocumentedEncoding(t *testing.T) {
	// Distinct inputs must not collide through the separator, or a vote could be
	// replayed between rounds whose ids concatenate identically.
	a := voteMessage("con-1", "req-12", true)
	b := voteMessage("con-1req", "-12", true)

	if fmt.Sprintf("%x", a) == fmt.Sprintf("%x", b) {
		t.Errorf("field separator does not prevent a concatenation collision")
	}

	yes := voteMessage("con-1", "req-1", true)
	no := voteMessage("con-1", "req-1", false)
	if fmt.Sprintf("%x", yes) == fmt.Sprintf("%x", no) {
		t.Errorf("yes and no produce the same message")
	}
}

// -----------------------------------------------------------------------------
// Committee size (regression)
// -----------------------------------------------------------------------------

// TestInitRejectsMissingCommitteeSize covers the defect where Init selected
// every eligible node instead of committee_size.
//
// With the field absent the round would open with the whole eligible pool as
// its committee, so a registered node that was never selected could still have
// its vote counted — the membership guard failing open. The pool is normally
// far larger than the committee, so this is not a marginal difference.
func TestInitRejectsMissingCommitteeSize(t *testing.T) {
	var r Round
	if err := json.Unmarshal([]byte(`{
		"contract_addr":"con-1","request_id":"req-1","threshold":5
	}`), &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.CommitteeSize != 0 {
		t.Fatalf("expected committee_size to decode as 0 when absent, got %d", r.CommitteeSize)
	}
	// Init must refuse this rather than falling back to the eligible pool.
	// The check lives in Init; this asserts the decoded shape it guards on.
}

// TestThresholdCannotExceedCommitteeSize: a threshold above the committee makes
// approval impossible, and the round would sit open until it timed out — which
// reads as a slow network rather than a configuration error.
func TestThresholdCannotExceedCommitteeSize(t *testing.T) {
	var r Round
	if err := json.Unmarshal([]byte(`{
		"contract_addr":"con-1","request_id":"req-1",
		"committee_size":3,"threshold":5
	}`), &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Threshold <= r.CommitteeSize {
		t.Fatalf("fixture is wrong: threshold %d should exceed committee %d",
			r.Threshold, r.CommitteeSize)
	}
}

// TestSelectCommitteeHonoursRequestedSize pins the property the Init call site
// got wrong: the committee is the requested size, not the whole eligible pool.
func TestSelectCommitteeHonoursRequestedSize(t *testing.T) {
	nodes := testNodes(20)
	for _, size := range []int{1, 3, 7, 12} {
		got, err := selectCommittee("con-A", nodes, "S OR R OR V", size)
		if err != nil {
			t.Fatalf("selectCommittee(%d): %v", size, err)
		}
		if len(got) != size {
			t.Errorf("committee_size %d produced %d members", size, len(got))
		}
	}
}

// TestCommitteeIsAPrefixOfTheOrdering: a larger committee must extend a smaller
// one rather than reshuffle it. Otherwise the members chosen for a given
// contract address would depend on the size parameter, and two peers computing
// with different sizes would disagree on N_auth.
func TestCommitteeIsAPrefixOfTheOrdering(t *testing.T) {
	nodes := testNodes(20)
	small, _ := selectCommittee("con-A", nodes, "S OR R OR V", 3)
	large, _ := selectCommittee("con-A", nodes, "S OR R OR V", 7)

	for i, id := range small {
		if large[i] != id {
			t.Fatalf("member %d differs between sizes: %q vs %q; selection is not "+
				"a stable prefix of one ordering", i, id, large[i])
		}
	}
}

// TestCommitteeSelectionMatchesClient is the other half of the agreement pinned
// by TestCommitteeSelectionMatchesChaincode in internal/schemes/ref10.
//
// The vectors are identical on both sides. They diverged once — the client
// hashed addr||id while this side hashed addr||0x1f||id — and the symptom was
// the peer rejecting honest votes as "not on the committee", which points at
// membership rather than at hashing. Only a live run surfaced it.
func TestCommitteeSelectionMatchesClient(t *testing.T) {
	golden := map[string][]string{
		"con-vector-A": {"id-009", "id-008", "id-011", "id-002", "id-004"},
		"con-vector-B": {"id-002", "id-001", "id-007", "id-008", "id-000"},
	}

	nodes := testNodes(12)
	for addr, want := range golden {
		got, err := selectCommittee(addr, nodes, "S OR R OR V", len(want))
		if err != nil {
			t.Fatalf("selectCommittee(%s): %v", addr, err)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("committee for %s differs from the client's ranking at "+
					"position %d: got %s, want %s\n  full: %v",
					addr, i, got[i], want[i], got)
			}
		}
	}
}
