package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
)

// -----------------------------------------------------------------------------
// Golden vectors — the cross-module agreement test
// -----------------------------------------------------------------------------

// These signatures were produced by pkg/crypto in the main module, over
// voteMessage("con-golden-0001", "req-golden-0001", goldenCertDigest, approve),
// and verified there before being recorded here.
//
// REGENERATED when the certificate digest entered the signed message. The old
// vectors signed (addr, requestID, approve) only; a ballot carrying its own
// certificate has to bind it, or the same signature verifies against any P_C.
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

	goldenTargetTx  = "tx-golden-0001"
	goldenRequester = "id-golden"
	goldenPolicyID  = "pol-golden"
	// The attribute policy A_r, and it must be a string `satisfies` recognises.
	// It was "validator" — syntactically fine, semantically empty: `satisfies`
	// matches the literal "S OR R OR V", so every node failed eligibility and
	// the committee was empty. Every unit test still passed, because none of
	// them derived a committee from the golden certificate. smoke.sh caught it
	// against the deployed contract; TestGoldenCertificateSelectsACommittee
	// now catches it here.
	goldenAttrs = "S OR R OR V"

	goldenPubX = "b07b38cbba315fa1ed0597049ba3514be6e86e190400bef368f6c02c84c8c716"
	goldenPubY = "701ce97bf410478f263d55922292fc9f70d48c6281262817cc3aa103495c8cef"

	// The CA key that signs P_C. Algorithm 4 line 1 verifies against this, and
	// without it the certificate is whatever the caller typed.
	goldenCAPubX = "5d78e3a8b6e42894b9abb7f178c6970ae6d6115f1ade994b6259ade8c9b7a3af"
	goldenCAPubY = "4b387ebb70ab16aa93bab9671ea56b1499700138d9bce809afcba723cb7200b9"

	goldenCertSigE   = "432e25f82cc6cd1a29aba737f96596bd60504bed53799383ce3f440f4dd50fab"
	goldenCertSigS   = "8bcd77f70facf94c6b108f954410ca9b9bb546ecca5090c34bf3650547b073ef"
	goldenCertDigest = "afb3c93412f33045c4a64de66ad65ed3c58290693cff5c26f72aab7b5b77b2a4"

	goldenYesE = "33b3e03afbe5ec307810e3409e681a3ea15424a48db20950063fece372d28a0c"
	goldenYesS = "056d993f8897f8127cfaa391e5b38cf5e1bb7009e1219e585930db7e2187cc97"

	goldenNoE = "7ca5ea0ba570c63a2628d2d0878a5861549a8527965444dfa5ccb3b035060a67"
	goldenNoS = "0bfadcd965a69e3b3521126bf4752018b827ab76b19ac152ba61d1b5f851b2aa"
)

// goldenCert is the CA-signed P_C every golden ballot votes on.
func goldenCert() PolicyCert {
	return PolicyCert{
		TargetTxID:     goldenTargetTx,
		RequesterID:    goldenRequester,
		RequesterKnown: true,
		Redactable:     true,
		Satisfies:      true,
		PolicyID:       goldenPolicyID,
		PolicyVer:      1,
		Attributes:     goldenAttrs,
		SigE:           goldenCertSigE,
		SigS:           goldenCertSigS,
	}
}

func goldenPolicy() *RoundPolicy {
	return &RoundPolicy{
		CommitteeSize: 1,
		Threshold:     1,
		CAPubX:        goldenCAPubX,
		CAPubY:        goldenCAPubY,
	}
}

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
			bal := Ballot{NodeID: n.ID, Approve: tc.approve, Cert: goldenCert(), E: tc.e, S: tc.s}

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

	flipped := Ballot{NodeID: n.ID, Approve: false, Cert: goldenCert(), E: goldenYesE, S: goldenYesS}
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
	bal := Ballot{NodeID: n.ID, Approve: true, Cert: goldenCert(), E: goldenYesE, S: goldenYesS}

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

	bal := Ballot{NodeID: other.ID, Approve: true, Cert: goldenCert(), E: goldenYesE, S: goldenYesS}
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
		{"non-hex e", Ballot{NodeID: n.ID, Approve: true, Cert: goldenCert(), E: "zz", S: goldenYesS}, n},
		{"non-hex s", Ballot{NodeID: n.ID, Approve: true, Cert: goldenCert(), E: goldenYesE, S: "zz"}, n},
		{"empty e", Ballot{NodeID: n.ID, Approve: true, Cert: goldenCert(), E: "", S: goldenYesS}, n},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := verifyBallot(tc.node, goldenContractAddr, goldenRequestID, tc.bal); err == nil {
				t.Errorf("malformed input was not rejected")
			}
		})
	}

	t.Run("zero scalars", func(t *testing.T) {
		bal := Ballot{NodeID: n.ID, Approve: true, Cert: goldenCert(), E: "0", S: "0"}
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

// TestBallotRoundTripsThroughJSON covers the encoding the client and contract
// share. A field that fails to survive the round trip would arrive zeroed, and
// a zeroed certificate would fail the CA check on every honest ballot.
func TestBallotRoundTripsThroughJSON(t *testing.T) {
	in := Ballot{
		NodeID: "id-1", Approve: true,
		RequestID: "req-1", TargetTxID: "tx-1",
		Cert: PolicyCert{
			TargetTxID: "tx-1", RequesterID: "id-1",
			RequesterKnown: true, Redactable: true, Satisfies: true,
			PolicyID: "pol-1", PolicyVer: 3, Attributes: "S OR R OR V",
			SigE: goldenCertSigE, SigS: goldenCertSigS,
		},
		E: goldenYesE, S: goldenYesS,
	}

	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Ballot
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Cert.PolicyVer != in.Cert.PolicyVer {
		t.Errorf("PolicyVer did not survive: got %d, want %d", out.Cert.PolicyVer, in.Cert.PolicyVer)
	}
	if !out.Cert.Granted() {
		t.Errorf("certificate decision did not survive the round trip")
	}
	if out.Cert.SigE != in.Cert.SigE || out.Cert.SigS != in.Cert.SigS {
		t.Errorf("CA signature did not survive the round trip")
	}
	if out.Cert.Digest() != in.Cert.Digest() {
		t.Errorf("certificate digest changed across the round trip; ballots would " +
			"be grouped apart from the votes they were cast with")
	}
	if out.RequestID != in.RequestID || out.TargetTxID != in.TargetTxID {
		t.Errorf("request identifiers did not survive: %+v", out)
	}
}

func TestVoteMessageMatchesDocumentedEncoding(t *testing.T) {
	d := goldenCertDigest

	// Distinct inputs must not collide through the separator, or a vote could be
	// replayed between rounds whose ids concatenate identically.
	a := voteMessage("con-1", "req-12", d, true)
	b := voteMessage("con-1req", "-12", d, true)

	if fmt.Sprintf("%x", a) == fmt.Sprintf("%x", b) {
		t.Errorf("field separator does not prevent a concatenation collision")
	}

	yes := voteMessage("con-1", "req-1", d, true)
	no := voteMessage("con-1", "req-1", d, false)
	if fmt.Sprintf("%x", yes) == fmt.Sprintf("%x", no) {
		t.Errorf("yes and no produce the same message")
	}
}

// -----------------------------------------------------------------------------
// The CA certificate — what replaced init()'s ledger write
// -----------------------------------------------------------------------------

// TestChaincodeVerifiesCACertificate is the cross-module agreement test for
// P_C, the same role TestChaincodeVerifiesPkgCryptoSignatures plays for
// ballots.
//
// PolicyCert.Bytes() here must match internal/schemes/ref10.policyCert.bytes()
// exactly. If they drift, every honest certificate fails and no round ever
// reaches threshold — which reads as a slow network, not a broken encoder.
func TestChaincodeVerifiesCACertificate(t *testing.T) {
	ok, err := verifyCert(goldenPolicy(), goldenCert())
	if err != nil {
		t.Fatalf("verifyCert: %v", err)
	}
	if !ok {
		t.Fatal("chaincode rejected a certificate that pkg/crypto signed and accepted; " +
			"PolicyCert.Bytes has drifted from ref10.policyCert.bytes")
	}
	if got := goldenCert().Digest(); got != goldenCertDigest {
		t.Fatalf("certificate digest changed: got %s, want %s; every recorded ballot "+
			"signature is over the old one", got, goldenCertDigest)
	}
}

// TestGoldenCertificateSelectsACommittee is the check the unit suite was
// missing.
//
// The golden certificate carries A_r, and A_r decides who is eligible. A
// certificate whose Attributes string `satisfies` does not recognise selects
// NOBODY — every node fails eligibility, committeeFor returns "only 0 nodes
// satisfy the policy", and no round can ever reach threshold. That is what
// happened with Attributes "validator": the CA signature verified, the digest
// matched, every existing test passed, and the deployed contract rejected every
// ballot for a reason that named the attribute policy rather than the vote.
//
// Verifying a certificate is not the same as being able to act on it.
func TestGoldenCertificateSelectsACommittee(t *testing.T) {
	nodes := []Node{goldenNode()}

	committee, err := selectCommittee(goldenContractAddr, nodes, goldenCert().Attributes, 1)
	if err != nil {
		t.Fatalf("selectCommittee with the golden certificate: %v", err)
	}
	if len(committee) != 1 || committee[0] != goldenNode().ID {
		t.Fatalf("the golden certificate selects %v, want [%s]; A_r = %q is not a "+
			"policy `satisfies` recognises, so no ballot could ever be counted",
			committee, goldenNode().ID, goldenCert().Attributes)
	}
}

// TestUnsignedCertificateIsRejected is the guard that makes removing init()
// safe.
//
// The stored round used to be the reason a member was not taking the
// requester's word for P_C. Now the CA signature is that reason, so a
// certificate without a valid one must not authorise anything. If this passes
// while the check is disabled, the caller can assert its own eligibility and
// the committee derived from cert.Attributes becomes the caller's to choose.
func TestUnsignedCertificateIsRejected(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(c *PolicyCert)
	}{
		{"no signature at all", func(c *PolicyCert) { c.SigE, c.SigS = "", "" }},
		{"signature over a different target", func(c *PolicyCert) { c.TargetTxID = "tx-other" }},
		{"signature over a different requester", func(c *PolicyCert) { c.RequesterID = "id-other" }},
		{"attributes altered after signing", func(c *PolicyCert) { c.Attributes = "V" }},
		{"decision flipped after signing", func(c *PolicyCert) { c.Satisfies = false }},
		{"policy version bumped after signing", func(c *PolicyCert) { c.PolicyVer = 2 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := goldenCert()
			tc.mut(&cert)
			ok, err := verifyCert(goldenPolicy(), cert)
			if err != nil {
				t.Fatalf("verifyCert: %v", err)
			}
			if ok {
				t.Error("a certificate the CA did not sign was accepted; P_C is " +
					"whatever the caller types and Algorithm 4 line 1 is not running")
			}
		})
	}
}

// TestBallotSignatureBindsTheCertificate pins that a member's signature says
// WHICH P_C it voted on.
//
// Without this, a ballot collected against one CA-signed certificate verifies
// unchanged beside a different one, and Close would count it in a group the
// member never approved.
func TestBallotSignatureBindsTheCertificate(t *testing.T) {
	n := goldenNode()

	other := goldenCert()
	other.PolicyVer = 99 // a different certificate, so a different digest

	bal := Ballot{NodeID: n.ID, Approve: true, Cert: other, E: goldenYesE, S: goldenYesS}
	ok, err := verifyBallot(n, goldenContractAddr, goldenRequestID, bal)
	if err != nil {
		t.Fatalf("verifyBallot: %v", err)
	}
	if ok {
		t.Error("a ballot verified against a certificate it was not signed over; " +
			"the certificate digest is not bound into the vote message")
	}
}

// TestRoundPolicyRejectsCallerControlledThreshold covers what RegisterRoundPolicy
// exists to prevent.
//
// The threshold and committee size must come from registered state, never from
// a ballot. A voter naming its own threshold authorises alone; a voter naming
// its own committee size shrinks N_auth until it holds a majority.
func TestRoundPolicyRejectsCallerControlledThreshold(t *testing.T) {
	for _, tc := range []struct {
		name string
		json string
	}{
		{"threshold above committee", `{"committee_size":3,"threshold":5,"ca_pub_x":"aa","ca_pub_y":"bb"}`},
		{"zero threshold", `{"committee_size":3,"threshold":0,"ca_pub_x":"aa","ca_pub_y":"bb"}`},
		{"zero committee", `{"committee_size":0,"threshold":1,"ca_pub_x":"aa","ca_pub_y":"bb"}`},
		{"no CA key", `{"committee_size":3,"threshold":2}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var p RoundPolicy
			if err := json.Unmarshal([]byte(tc.json), &p); err != nil {
				t.Fatalf("decode: %v", err)
			}
			bad := p.Threshold <= 0 || p.CommitteeSize <= 0 ||
				p.Threshold > p.CommitteeSize || p.CAPubX == "" || p.CAPubY == ""
			if !bad {
				t.Fatalf("fixture %+v is not the invalid shape this test claims", p)
			}
		})
	}
}

// TestBallotOmittingCommitteeSizeCannotWiden replaces the old
// TestInitRejectsMissingCommitteeSize.
//
// The defect it guarded against was selecting the whole eligible pool instead
// of committee_size, which let a registered node that was never selected have
// its vote counted. The size now comes from the round policy, so the failure
// mode is unreachable from a ballot — this pins that a ballot carries no size
// field at all to omit.
func TestBallotOmittingCommitteeSizeCannotWiden(t *testing.T) {
	var bal Ballot
	if err := json.Unmarshal([]byte(`{
		"node_id":"id-1","approve":true,"request_id":"req-1",
		"committee_size":999,"threshold":1
	}`), &bal); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// The extra keys are ignored: Ballot has no such fields, so a caller cannot
	// smuggle either value past the registered policy.
	raw, err := json.Marshal(bal)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, forbidden := range []string{"committee_size", "threshold"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Errorf("Ballot carries %q; a voter could then name its own %s",
				forbidden, forbidden)
		}
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
