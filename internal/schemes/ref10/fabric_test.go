package ref10

import (
	"context"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"strings"
	"sync"
	"testing"

	"zkredact/pkg/crypto"
	"zkredact/pkg/scheme"
)

// -----------------------------------------------------------------------------
// Fake chaincode session
//
// The transport is tested against a fake rather than a live network so its
// protocol logic — who is asked, in what order, and what is submitted — is
// verifiable without Docker. The live path is covered separately by
// network/scripts/smoke.sh, which needs a running Fabric.
// -----------------------------------------------------------------------------

type call struct {
	Member string
	Kind   string // "evaluate" | "submit"
	Fn     string
	Args   []string
}

type fakeSession struct {
	member string
	log    *callLog
	round  string // JSON returned by Query
	failOn string // function name that should error
	closed bool
}

type callLog struct {
	mu    sync.Mutex
	calls []call
}

func (l *callLog) add(c call) {
	l.mu.Lock()
	l.calls = append(l.calls, c)
	l.mu.Unlock()
}

func (l *callLog) snapshot() []call {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]call(nil), l.calls...)
}

func (s *fakeSession) Evaluate(ctx context.Context, fn string, args ...string) ([]byte, error) {
	s.log.add(call{Member: s.member, Kind: "evaluate", Fn: fn, Args: args})
	if s.failOn == fn {
		return nil, fmt.Errorf("fake: %s failed", fn)
	}
	if fn == "Query" {
		return []byte(s.round), nil
	}
	return nil, nil
}

func (s *fakeSession) Submit(ctx context.Context, fn string, args ...string) ([]byte, error) {
	s.log.add(call{Member: s.member, Kind: "submit", Fn: fn, Args: args})
	if s.failOn == fn {
		return nil, fmt.Errorf("fake: %s failed", fn)
	}
	return nil, nil
}

func (s *fakeSession) Close() error {
	s.closed = true
	return nil
}

type fakeFactory struct {
	log      *callLog
	round    string
	failOn   string
	created  map[string]*fakeSession
	failNext string // member id whose session creation should fail
	mu       sync.Mutex
}

func newFakeFactory(round string) *fakeFactory {
	return &fakeFactory{
		log:     &callLog{},
		round:   round,
		created: make(map[string]*fakeSession),
	}
}

func (f *fakeFactory) Session(memberID string) (chaincodeSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.failNext == memberID {
		return nil, errors.New("fake: session creation refused")
	}
	if s, ok := f.created[memberID]; ok {
		return s, nil
	}
	s := &fakeSession{member: memberID, log: f.log, round: f.round, failOn: f.failOn}
	f.created[memberID] = s
	return s, nil
}

func (f *fakeFactory) Close() error { return nil }

// -----------------------------------------------------------------------------
// Fixtures
// -----------------------------------------------------------------------------

func testVoteRound(t *testing.T, memberCount int, granted bool) *voteRound {
	t.Helper()

	curve := elliptic.P256()
	rnd := rand.New(rand.NewSource(42))

	identities := make([]scheme.Identity, memberCount)
	members := make([]*member, memberCount)
	for i := range members {
		key, err := crypto.SchnorrKeyGen(curve, rnd)
		if err != nil {
			t.Fatalf("SchnorrKeyGen: %v", err)
		}
		identities[i] = scheme.Identity{
			ID:         fmt.Sprintf("id-%03d", i),
			Attributes: map[string]string{"validator": "true"},
		}
		members[i] = &member{Identity: identities[i], Key: key}
	}

	ca, err := newCertAuthority(identities, curve, 42)
	if err != nil {
		t.Fatalf("newCertAuthority: %v", err)
	}

	cert := &policyCert{
		TargetTxID:     "tx-0001",
		RequesterID:    "id-000",
		RequesterKnown: true,
		Redactable:     granted,
		Satisfies:      granted,
		PolicyID:       "pol-0001",
		PolicyVer:      1,
		Attributes:     "S OR R OR V",
	}
	sig, err := ca.key.Sign(cert.bytes(), nil)
	if err != nil {
		t.Fatalf("sign cert: %v", err)
	}
	cert.Sig = sig

	return &voteRound{
		ContractAddr: "con-0001",
		RequestID:    "req-0001",
		Cert:         cert,
		CA:           ca,
		Members:      members,
		Threshold:    (memberCount / 2) + 1,
	}
}

func fakeRoundJSON(r *voteRound) string {
	cr := chainRound{
		ContractAddr: r.ContractAddr,
		RequestID:    r.RequestID,
		TargetTxID:   r.Cert.TargetTxID,
		RequesterID:  r.Cert.RequesterID,
		Threshold:    r.Threshold,
	}
	b, _ := json.Marshal(cr)
	return string(b)
}

// -----------------------------------------------------------------------------
// Protocol shape
// -----------------------------------------------------------------------------

// TestFabricTransportSubmitsOneVotePerMember pins the shape Ref[10] specifies:
// the round is opened once, then every member reads and writes under its own
// identity.
func TestFabricTransportSubmitsOneVotePerMember(t *testing.T) {
	r := testVoteRound(t, 5, true)
	f := newFakeFactory(fakeRoundJSON(r))
	tr := newFabricTransport(f)

	ballots, err := tr.Collect(context.Background(), r)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(ballots) != 5 {
		t.Fatalf("expected 5 ballots, got %d", len(ballots))
	}

	calls := f.log.snapshot()

	inits, queries, votes := 0, 0, 0
	votesBy := make(map[string]int)
	for _, c := range calls {
		switch c.Fn {
		case "Init":
			inits++
			if c.Kind != "submit" {
				t.Errorf("Init must be submitted, not evaluated: it writes the round")
			}
		case "Query":
			queries++
			if c.Kind != "evaluate" {
				t.Errorf("Query must be evaluated, not submitted: it is read-only")
			}
		case "Vote":
			votes++
			votesBy[c.Member]++
			if c.Kind != "submit" {
				t.Errorf("Vote must be submitted: routing it through Evaluate would skip " +
					"endorsement and ordering, restoring the in-process lower bound")
			}
		}
	}

	if inits != 1 {
		t.Errorf("expected the round to be opened once, got %d Init calls", inits)
	}
	if queries != 5 {
		t.Errorf("expected each of 5 members to read the round, got %d Query calls", queries)
	}
	if votes != 5 {
		t.Errorf("expected 5 votes, got %d", votes)
	}
	for _, m := range r.Members {
		if votesBy[m.Identity.ID] != 1 {
			t.Errorf("member %s submitted %d votes, want exactly 1",
				m.Identity.ID, votesBy[m.Identity.ID])
		}
	}
}

// TestFabricTransportVotesUnderEachMemberIdentity guards the property that
// makes the contract's membership check meaningful: a ballot must be submitted
// by the member it belongs to, not by one shared client.
func TestFabricTransportVotesUnderEachMemberIdentity(t *testing.T) {
	r := testVoteRound(t, 4, true)
	f := newFakeFactory(fakeRoundJSON(r))
	tr := newFabricTransport(f)

	if _, err := tr.Collect(context.Background(), r); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	for _, c := range f.log.snapshot() {
		if c.Fn != "Vote" {
			continue
		}
		var bal chainBallot
		if err := json.Unmarshal([]byte(c.Args[1]), &bal); err != nil {
			t.Fatalf("decode submitted ballot: %v", err)
		}
		if bal.NodeID != c.Member {
			t.Errorf("ballot for %s was submitted by %s; the contract's membership "+
				"check would be validating the wrong identity", bal.NodeID, c.Member)
		}
	}
}

// TestFabricTransportSignaturesVerify closes the loop: what the transport puts
// on the wire must verify under the member's key.
func TestFabricTransportSignaturesVerify(t *testing.T) {
	r := testVoteRound(t, 3, true)
	f := newFakeFactory(fakeRoundJSON(r))
	tr := newFabricTransport(f)

	if _, err := tr.Collect(context.Background(), r); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	byID := make(map[string]*member, len(r.Members))
	for _, m := range r.Members {
		byID[m.Identity.ID] = m
	}

	checked := 0
	for _, c := range f.log.snapshot() {
		if c.Fn != "Vote" {
			continue
		}
		var bal chainBallot
		if err := json.Unmarshal([]byte(c.Args[1]), &bal); err != nil {
			t.Fatalf("decode ballot: %v", err)
		}

		e, ok := decodeScalar(bal.E)
		if !ok {
			t.Fatalf("ballot e is not hex: %q", bal.E)
		}
		s, ok := decodeScalar(bal.S)
		if !ok {
			t.Fatalf("ballot s is not hex: %q", bal.S)
		}

		m := byID[bal.NodeID]
		msg := voteMessage(r.ContractAddr, r.RequestID, bal.Approve)
		if !m.Key.SchnorrPublicKey.Verify(msg, &crypto.SchnorrSignature{E: e, S: s}) {
			t.Errorf("signature submitted for %s does not verify under its key", bal.NodeID)
		}
		checked++
	}
	if checked != 3 {
		t.Errorf("verified %d ballots, expected 3", checked)
	}
}

// TestFabricTransportVotesNoOnUngrantedCert covers the decision path: members
// derive their vote from P_C, so an ungranted certificate must produce no
// votes, not silent approvals.
func TestFabricTransportVotesNoOnUngrantedCert(t *testing.T) {
	r := testVoteRound(t, 4, false) // policy not satisfied
	f := newFakeFactory(fakeRoundJSON(r))
	tr := newFabricTransport(f)

	ballots, err := tr.Collect(context.Background(), r)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, b := range ballots {
		if b.Approve {
			t.Errorf("member %s approved a redaction the policy does not permit", b.NodeID)
		}
	}
}

// TestFabricTransportRejectsForgedCert: a certificate the CA did not sign must
// not draw votes, even if the ledger returns a round for it.
func TestFabricTransportRejectsForgedCert(t *testing.T) {
	r := testVoteRound(t, 4, true)
	r.Cert.Redactable = true
	r.Cert.Satisfies = true
	r.Cert.PolicyVer = 99 // mutate after signing; the signature no longer covers this

	f := newFakeFactory(fakeRoundJSON(r))
	tr := newFabricTransport(f)

	ballots, err := tr.Collect(context.Background(), r)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(ballots) != 0 {
		t.Errorf("members voted on a certificate the CA did not sign; got %d ballots", len(ballots))
	}
}

func TestFabricTransportReusesSessions(t *testing.T) {
	r := testVoteRound(t, 3, true)
	f := newFakeFactory(fakeRoundJSON(r))
	tr := newFabricTransport(f)

	for i := 0; i < 3; i++ {
		if _, err := tr.Collect(context.Background(), r); err != nil {
			t.Fatalf("Collect %d: %v", i, err)
		}
	}

	// Three rounds over three members must not open more than three sessions;
	// reconnecting per ballot would measure gRPC setup rather than voting.
	if len(f.created) != 3 {
		t.Errorf("expected 3 cached sessions, got %d", len(f.created))
	}
}

func TestFabricTransportPropagatesSubmitFailure(t *testing.T) {
	r := testVoteRound(t, 3, true)
	f := newFakeFactory(fakeRoundJSON(r))
	f.failOn = "Vote"
	tr := newFabricTransport(f)

	if _, err := tr.Collect(context.Background(), r); err == nil {
		t.Errorf("a failed vote submission was swallowed; the round would look " +
			"under-subscribed rather than broken")
	}
}

func TestFabricTransportHonoursContextCancellation(t *testing.T) {
	r := testVoteRound(t, 5, true)
	f := newFakeFactory(fakeRoundJSON(r))
	tr := newFabricTransport(f)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := tr.Collect(ctx, r); err == nil {
		t.Errorf("Collect ignored a cancelled context")
	}
}

func TestFabricTransportName(t *testing.T) {
	tr := newFabricTransport(newFakeFactory("{}"))
	if tr.Name() != transportFabric {
		t.Errorf("Name = %q, want %q", tr.Name(), transportFabric)
	}
	// The name is recorded into results, so a run can never be read as
	// networked when it was not.
	if tr.Name() == transportInProcess {
		t.Errorf("the Fabric transport reports itself as in-process")
	}
}

func TestFabricTransportCloseReleasesSessions(t *testing.T) {
	r := testVoteRound(t, 3, true)
	f := newFakeFactory(fakeRoundJSON(r))
	tr := newFabricTransport(f)

	if _, err := tr.Collect(context.Background(), r); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for id, s := range f.created {
		if !s.closed {
			t.Errorf("session for %s was not closed", id)
		}
	}
}

// -----------------------------------------------------------------------------
// Wire format agreement with the chaincode
// -----------------------------------------------------------------------------

// TestWireFormatMatchesChaincode pins the JSON field names against the
// contract's struct tags.
//
// The chaincode is a separate Go module and cannot be imported here, so these
// types are a second declaration of the same wire format. A renamed field would
// decode as its zero value rather than failing — a zero Threshold, for
// instance, would close every round on its first vote — so the names are
// asserted literally.
func TestWireFormatMatchesChaincode(t *testing.T) {
	r := testVoteRound(t, 3, true)

	roundJSON, err := encodeRound(r)
	if err != nil {
		t.Fatalf("encodeRound: %v", err)
	}

	for _, field := range []string{
		`"contract_addr"`, `"request_id"`, `"target_tx_id"`, `"requester_id"`,
		`"cert"`, `"threshold"`,
		`"requester_known"`, `"redactable"`, `"satisfies"`,
		`"policy_id"`, `"policy_ver"`, `"attributes"`,
	} {
		if !strings.Contains(roundJSON, field) {
			t.Errorf("round JSON is missing %s; the contract would decode it as zero\n  %s",
				field, roundJSON)
		}
	}

	sig := &crypto.SchnorrSignature{E: big.NewInt(7), S: big.NewInt(9)}
	ballotJSON, err := encodeBallot("id-000", true, sig)
	if err != nil {
		t.Fatalf("encodeBallot: %v", err)
	}
	for _, field := range []string{`"node_id"`, `"approve"`, `"e"`, `"s"`} {
		if !strings.Contains(ballotJSON, field) {
			t.Errorf("ballot JSON is missing %s\n  %s", field, ballotJSON)
		}
	}
}

// TestEncodeRoundCarriesThreshold guards the field whose loss is silent: a
// threshold decoding as 0 would let a single ballot close the round.
func TestEncodeRoundCarriesThreshold(t *testing.T) {
	r := testVoteRound(t, 7, true)
	r.Threshold = 5

	roundJSON, err := encodeRound(r)
	if err != nil {
		t.Fatalf("encodeRound: %v", err)
	}
	var decoded chainRound
	if err := json.Unmarshal([]byte(roundJSON), &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Threshold != 5 {
		t.Errorf("threshold decoded as %d, want 5", decoded.Threshold)
	}
}

// TestEncodeBallotRejectsMissingSignature: an unsigned ballot must not reach
// the wire as an empty one, which the contract would reject as malformed and
// report as a network error.
func TestEncodeBallotRejectsMissingSignature(t *testing.T) {
	if _, err := encodeBallot("id-000", true, nil); err == nil {
		t.Errorf("a nil signature was encoded")
	}
	if _, err := encodeBallot("id-000", true, &crypto.SchnorrSignature{}); err == nil {
		t.Errorf("a signature with nil scalars was encoded")
	}
}

// TestEncodeNodesCarriesVotingKeys: the contract verifies signatures against
// these keys, so a node registered without one can never have a vote counted.
func TestEncodeNodesCarriesVotingKeys(t *testing.T) {
	r := testVoteRound(t, 3, true)

	nodesJSON, err := encodeNodes(r.Members, nil)
	if err != nil {
		t.Fatalf("encodeNodes: %v", err)
	}
	var nodes []chainNode
	if err := json.Unmarshal([]byte(nodesJSON), &nodes); err != nil {
		t.Fatalf("decode nodes: %v", err)
	}
	if len(nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(nodes))
	}
	for _, n := range nodes {
		if n.PubX == "" || n.PubY == "" {
			t.Errorf("node %s was registered without a voting key", n.ID)
		}
		if n.Attributes == nil {
			t.Errorf("node %s was registered without attributes; A_r could not be evaluated", n.ID)
		}
	}
}
