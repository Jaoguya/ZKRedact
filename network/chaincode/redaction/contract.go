// Package main implements Ref[10]'s redaction smart contract as Fabric
// chaincode.
//
// Source: Ref[10].md Algorithm 3, "Redaction Smart Contract Functions".
//
//	init(con_k)   N_auth <- RS_SHA256(addr(con_k), N_all, A_r);  store pk_j
//	query(con_k)  return {req, sigma}
//	vote(n_j, con_k, t)  verify xi_j; count yes; on threshold emit tx_rdt
//
// WHY THIS IS CHAINCODE AND NOT A GO STRUCT. The in-process implementation in
// internal/schemes/ref10 runs the same algorithm by function call. It produces
// correct cryptography and incorrect timings: Ref[10]'s authorization cost is
// dominated by votes crossing the network and reaching consensus, and a
// function call has neither. Exp 1's whole question is how that cost behaves
// under concurrent load, so the protocol has to actually run on the ledger.
//
// The contract deliberately does NOT trust its caller:
//
//   - Committee membership is recomputed from the stored node set, so a
//     non-member's vote is rejected rather than counted.
//   - Every signature is verified inside the contract. A client could otherwise
//     submit ballots for members that never voted, and the threshold would mean
//     nothing.
//   - Each member votes at most once. Without this, one member could pad
//     Sigma to the threshold alone.
//
// Each of those has a test, because each is a way for the measurement to look
// correct while being wrong.
package main

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"sort"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// State keys. Namespaced so several concurrent redaction contracts can share a
// channel without colliding — Exp 1 drives many rounds at once.
const (
	keyRound   = "round"  // round/<contractAddr>
	keyBallot  = "ballot" // ballot/<contractAddr>/<nodeID>
	keyRdt     = "rdt"    // rdt/<contractAddr>
	keyNodeSet = "nodes"  // nodes  (the network's registered nodes)
)

// SmartContract is the redaction contract con_k.
type SmartContract struct {
	contractapi.Contract
}

// Node is a registered network participant with its voting key.
type Node struct {
	ID string `json:"id"`

	// Attributes are the {S, R, V} roles of Ref[10] Eq. 5, used by A_r.
	Attributes map[string]string `json:"attributes"`

	// PubX, PubY are the Schnorr verification key P = x*G, hex-encoded.
	PubX string `json:"pub_x"`
	PubY string `json:"pub_y"`
}

// Round is one redaction request awaiting authorization: the {req, sigma} that
// query() returns and vote() tallies against.
type Round struct {
	ContractAddr string `json:"contract_addr"`
	RequestID    string `json:"request_id"`
	TargetTxID   string `json:"target_tx_id"`
	RequesterID  string `json:"requester_id"`

	// Cert is the CA's signed policy decision, P_C. Members re-derive their vote
	// from it rather than trusting the requester.
	Cert PolicyCert `json:"cert"`

	// Committee is N_auth, the output of RS_SHA256(addr, N_all, A_r).
	Committee []string `json:"committee"`

	// CommitteeSize is |N_auth|, from the fault assumption in config.
	//
	// Carried explicitly rather than inferred from the eligible pool: selecting
	// every eligible node would let a registered node that was NOT selected have
	// its vote counted, which is the membership guard failing open. The pool is
	// usually much larger than the committee, so the difference is not marginal.
	CommitteeSize int `json:"committee_size"`

	// Threshold is the approvals required, from the fault assumption in config.
	Threshold int `json:"threshold"`

	Closed   bool `json:"closed"`
	Approved bool `json:"approved"`
}

// PolicyCert mirrors the CA's signed P_C.
//
// RequesterKnown is kept separate from Redactable for the same reason as in the
// Go implementation: T_rdbl is a property of the transaction, not of whoever
// asked, so folding an unknown requester into it would make the certificate
// assert something false about the ledger.
type PolicyCert struct {
	TargetTxID     string `json:"target_tx_id"`
	RequesterID    string `json:"requester_id"`
	RequesterKnown bool   `json:"requester_known"`
	Redactable     bool   `json:"redactable"`
	Satisfies      bool   `json:"satisfies"`
	PolicyID       string `json:"policy_id"`
	PolicyVer      uint64 `json:"policy_ver"`
	Attributes     string `json:"attributes"`
}

// Granted reports whether P_C authorises the redaction: Eq. 5's two conditions,
// plus the requester being known to the CA at all.
func (c PolicyCert) Granted() bool {
	return c.RequesterKnown && c.Redactable && c.Satisfies
}

// Ballot is one member's vote, xi_j.
type Ballot struct {
	NodeID  string `json:"node_id"`
	Approve bool   `json:"approve"`

	// E, S are the Schnorr signature scalars, hex-encoded.
	E string `json:"e"`
	S string `json:"s"`
}

// RedactionTx is tx_rdt = {req, Sigma}: the transaction that authorises local
// redaction on every node.
type RedactionTx struct {
	ContractAddr string   `json:"contract_addr"`
	RequestID    string   `json:"request_id"`
	TargetTxID   string   `json:"target_tx_id"`
	Sigma        []Ballot `json:"sigma"`
	Approvals    int      `json:"approvals"`
	Threshold    int      `json:"threshold"`
}

// -----------------------------------------------------------------------------
// Node registry
// -----------------------------------------------------------------------------

// RegisterNodes stores N_all, the set the committee is drawn from.
//
// Called once during setup, which is not timed. Committee selection reads this
// rather than taking a node list from the caller: a client supplying its own
// list could hand itself a committee of colluding members.
func (s *SmartContract) RegisterNodes(ctx contractapi.TransactionContextInterface, nodesJSON string) error {
	var nodes []Node
	if err := json.Unmarshal([]byte(nodesJSON), &nodes); err != nil {
		return fmt.Errorf("redaction: decode nodes: %w", err)
	}
	if len(nodes) == 0 {
		return fmt.Errorf("redaction: node set is empty")
	}
	for _, n := range nodes {
		if n.ID == "" || n.PubX == "" || n.PubY == "" {
			return fmt.Errorf("redaction: node %q is missing an id or voting key", n.ID)
		}
	}
	// Sorted so committee selection is deterministic given the same node set;
	// map iteration order would otherwise make N_auth vary between peers and
	// break endorsement.
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

	b, err := json.Marshal(nodes)
	if err != nil {
		return fmt.Errorf("redaction: encode nodes: %w", err)
	}
	return ctx.GetStub().PutState(keyNodeSet, b)
}

func (s *SmartContract) nodes(ctx contractapi.TransactionContextInterface) ([]Node, error) {
	b, err := ctx.GetStub().GetState(keyNodeSet)
	if err != nil {
		return nil, fmt.Errorf("redaction: read node set: %w", err)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("redaction: no nodes registered; call RegisterNodes first")
	}
	var nodes []Node
	if err := json.Unmarshal(b, &nodes); err != nil {
		return nil, fmt.Errorf("redaction: decode node set: %w", err)
	}
	return nodes, nil
}

// -----------------------------------------------------------------------------
// Algorithm 3: init
// -----------------------------------------------------------------------------

// Init opens a voting round: selects N_auth and stores the round state.
//
// Implements Algorithm 3 init():
//
//	N_all  <- RegisterNodes()
//	N_auth <- RS_SHA256(addr(con_k), N_all, A_r)      (Eq. 7)
//	store N_auth in con_k
func (s *SmartContract) Init(ctx contractapi.TransactionContextInterface, roundJSON string) error {
	var r Round
	if err := json.Unmarshal([]byte(roundJSON), &r); err != nil {
		return fmt.Errorf("redaction: decode round: %w", err)
	}
	if r.ContractAddr == "" || r.RequestID == "" {
		return fmt.Errorf("redaction: round needs a contract address and request id")
	}
	if r.Threshold <= 0 {
		return fmt.Errorf("redaction: threshold must be positive, got %d", r.Threshold)
	}
	if r.CommitteeSize <= 0 {
		return fmt.Errorf("redaction: committee_size must be positive, got %d", r.CommitteeSize)
	}
	if r.Threshold > r.CommitteeSize {
		return fmt.Errorf(
			"redaction: threshold %d exceeds committee size %d; no redaction could be approved",
			r.Threshold, r.CommitteeSize)
	}

	key := stateKey(keyRound, r.ContractAddr)
	existing, err := ctx.GetStub().GetState(key)
	if err != nil {
		return fmt.Errorf("redaction: read round: %w", err)
	}
	if len(existing) > 0 {
		return fmt.Errorf("redaction: round %s already exists", r.ContractAddr)
	}

	all, err := s.nodes(ctx)
	if err != nil {
		return err
	}

	// The committee is computed here, not accepted from the caller. A client
	// choosing its own N_auth could stack the round with colluding members and
	// the threshold would carry no meaning.
	committee, err := selectCommittee(r.ContractAddr, all, r.Cert.Attributes, r.CommitteeSize)
	if err != nil {
		return err
	}
	if len(committee) < r.CommitteeSize {
		return fmt.Errorf(
			"redaction: only %d nodes satisfy the policy but committee_size is %d; "+
				"a silently shrunken committee would weaken the threshold",
			len(committee), r.CommitteeSize)
	}
	r.Committee = committee
	r.Closed = false
	r.Approved = false

	b, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("redaction: encode round: %w", err)
	}
	return ctx.GetStub().PutState(key, b)
}

// selectCommittee implements Eq. 7, RS_SHA256(addr(con_k), N_all, A_r).
//
// Eligibility is A_r: the node must carry at least one of the {S, R, V} roles
// the policy names. Ordering is by H(addr || nodeID), so the committee depends
// on the contract address — a fixed list would remove per-request selection
// from the measured path, and Exp 1 times exactly that path.
func selectCommittee(contractAddr string, all []Node, attributePolicy string, size int) ([]string, error) {
	type scored struct {
		id    string
		score []byte
	}
	eligible := make([]scored, 0, len(all))

	for _, n := range all {
		if !satisfies(n, attributePolicy) {
			continue
		}
		h := sha256.New()
		h.Write([]byte(contractAddr))
		h.Write([]byte{0x1f})
		h.Write([]byte(n.ID))
		eligible = append(eligible, scored{id: n.ID, score: h.Sum(nil)})
	}
	if len(eligible) == 0 {
		return nil, fmt.Errorf(
			"redaction: no node satisfies the attribute policy %q", attributePolicy)
	}

	sort.Slice(eligible, func(i, j int) bool {
		c := compareBytes(eligible[i].score, eligible[j].score)
		if c != 0 {
			return c < 0
		}
		return eligible[i].id < eligible[j].id // tie-break, keeps it total
	})

	if size > len(eligible) {
		size = len(eligible)
	}
	out := make([]string, size)
	for i := 0; i < size; i++ {
		out[i] = eligible[i].id
	}
	return out, nil
}

// satisfies evaluates A_r against a node's attributes.
//
// Ref[10]'s default is {S OR R OR V}: transaction participants and validators
// may vote. Only that form is supported; an unrecognised policy is an error
// rather than a silent "everyone qualifies", which would inflate the eligible
// pool and weaken the threshold.
func satisfies(n Node, policy string) bool {
	switch policy {
	case "S OR R OR V", "":
		return truthy(n.Attributes["sender"]) ||
			truthy(n.Attributes["receiver"]) ||
			truthy(n.Attributes["validator"])
	default:
		return false
	}
}

func truthy(v string) bool { return v == "true" }

func compareBytes(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}

// -----------------------------------------------------------------------------
// Algorithm 3: query
// -----------------------------------------------------------------------------

// Query returns {req, sigma} for a round, so members can verify P_C and derive
// their own decision.
//
// Read-only: evaluated on a peer without ordering, which is what Ref[10]'s
// query() is.
func (s *SmartContract) Query(ctx contractapi.TransactionContextInterface, contractAddr string) (*Round, error) {
	b, err := ctx.GetStub().GetState(stateKey(keyRound, contractAddr))
	if err != nil {
		return nil, fmt.Errorf("redaction: read round: %w", err)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("redaction: no round for contract %s", contractAddr)
	}
	var r Round
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("redaction: decode round: %w", err)
	}
	return &r, nil
}

// -----------------------------------------------------------------------------
// Algorithm 3: vote
// -----------------------------------------------------------------------------

// Vote submits one ballot and verifies it. It does NOT tally.
//
// Implements Algorithm 3 vote() together with Algorithm 4's verification step.
// Three checks make the threshold meaningful, and each corresponds to a way a
// client could otherwise manufacture authorization:
//
//	membership   a non-member's vote is rejected, not counted
//	signature    verified here, so ballots cannot be fabricated for absent members
//	one-per-node a member cannot pad Sigma to the threshold alone
//
// WHY THE TALLY IS NOT HERE. Counting requires reading every committee member's
// ballot key, which puts all of them in this transaction's read set. Two
// ballots cut into the same block would then each carry the other's key, and
// the second would fail validation with MVCC_READ_CONFLICT — so ballots could
// only ever be submitted one per block, and a round cost
// (1 + committee_size) blocks.
//
// Nothing in Algorithm 3 or 4 requires that. Ref[10]'s committee members are
// independent nodes and their ballots belong in one block. Keeping the tally
// out means a Vote reads only round metadata (never written during voting) and
// writes only its own ballot key, so ballots are conflict-free and concurrent.
// Close() does the counting afterwards, in its own transaction.
//
// Returns nil on success: the ballot is recorded, and whether the round reached
// threshold is Close()'s answer, not this one's.
func (s *SmartContract) Vote(ctx contractapi.TransactionContextInterface, contractAddr, ballotJSON string) (*RedactionTx, error) {
	var bal Ballot
	if err := json.Unmarshal([]byte(ballotJSON), &bal); err != nil {
		return nil, fmt.Errorf("redaction: decode ballot: %w", err)
	}

	round, err := s.Query(ctx, contractAddr)
	if err != nil {
		return nil, err
	}
	if round.Closed {
		// Not an error: the round reached threshold while this vote was in
		// flight, which is normal under concurrency. Return the existing result.
		return s.Result(ctx, contractAddr)
	}

	if !contains(round.Committee, bal.NodeID) {
		return nil, fmt.Errorf(
			"redaction: %s is not on the committee for %s", bal.NodeID, contractAddr)
	}

	// One member, one vote.
	ballotKey := stateKey(keyBallot, contractAddr, bal.NodeID)
	prev, err := ctx.GetStub().GetState(ballotKey)
	if err != nil {
		return nil, fmt.Errorf("redaction: read ballot: %w", err)
	}
	if len(prev) > 0 {
		return nil, fmt.Errorf("redaction: %s has already voted in %s", bal.NodeID, contractAddr)
	}

	all, err := s.nodes(ctx)
	if err != nil {
		return nil, err
	}
	node, ok := findNode(all, bal.NodeID)
	if !ok {
		return nil, fmt.Errorf("redaction: unknown node %s", bal.NodeID)
	}

	// Algorithm 4 line 5: verify xi_j before counting it.
	ok, err = verifyBallot(node, contractAddr, round.RequestID, bal)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("redaction: invalid vote signature from %s", bal.NodeID)
	}

	stored, err := json.Marshal(bal)
	if err != nil {
		return nil, fmt.Errorf("redaction: encode ballot: %w", err)
	}
	if err := ctx.GetStub().PutState(ballotKey, stored); err != nil {
		return nil, fmt.Errorf("redaction: store ballot: %w", err)
	}

	return nil, nil
}

// Close tallies the ballots and, on reaching the threshold, emits tx_rdt.
//
// Split out of Vote so that ballots can share a block; see the note there. This
// is the transaction that reads every committee member's ballot, so it is the
// one that must run alone — which it does, once, after voting.
//
// Idempotent: a round already closed returns its existing tx_rdt rather than
// recomputing, so a retry cannot emit a second result.
func (s *SmartContract) Close(ctx contractapi.TransactionContextInterface, contractAddr string) (*RedactionTx, error) {
	round, err := s.Query(ctx, contractAddr)
	if err != nil {
		return nil, err
	}
	if round.Closed {
		return s.Result(ctx, contractAddr)
	}
	return s.tally(ctx, round)
}

// tally counts approvals and, on reaching the threshold, emits tx_rdt.
func (s *SmartContract) tally(ctx contractapi.TransactionContextInterface, round *Round) (*RedactionTx, error) {
	approving := make([]Ballot, 0, len(round.Committee))

	for _, id := range round.Committee {
		b, err := ctx.GetStub().GetState(stateKey(keyBallot, round.ContractAddr, id))
		if err != nil {
			return nil, fmt.Errorf("redaction: read ballot for %s: %w", id, err)
		}
		if len(b) == 0 {
			continue
		}
		var bal Ballot
		if err := json.Unmarshal(b, &bal); err != nil {
			return nil, fmt.Errorf("redaction: decode ballot for %s: %w", id, err)
		}
		if bal.Approve {
			approving = append(approving, bal)
		}
	}

	if len(approving) < round.Threshold {
		// Round stays open; the caller sees a nil result and keeps collecting.
		return nil, nil
	}

	rdt := &RedactionTx{
		ContractAddr: round.ContractAddr,
		RequestID:    round.RequestID,
		TargetTxID:   round.TargetTxID,
		Sigma:        approving,
		Approvals:    len(approving),
		Threshold:    round.Threshold,
	}
	rb, err := json.Marshal(rdt)
	if err != nil {
		return nil, fmt.Errorf("redaction: encode tx_rdt: %w", err)
	}
	if err := ctx.GetStub().PutState(stateKey(keyRdt, round.ContractAddr), rb); err != nil {
		return nil, fmt.Errorf("redaction: store tx_rdt: %w", err)
	}

	round.Closed = true
	round.Approved = true
	rounb, err := json.Marshal(round)
	if err != nil {
		return nil, fmt.Errorf("redaction: encode round: %w", err)
	}
	if err := ctx.GetStub().PutState(stateKey(keyRound, round.ContractAddr), rounb); err != nil {
		return nil, fmt.Errorf("redaction: close round: %w", err)
	}
	return rdt, nil
}

// Result returns tx_rdt for a closed round, or an error if none was emitted.
func (s *SmartContract) Result(ctx contractapi.TransactionContextInterface, contractAddr string) (*RedactionTx, error) {
	b, err := ctx.GetStub().GetState(stateKey(keyRdt, contractAddr))
	if err != nil {
		return nil, fmt.Errorf("redaction: read tx_rdt: %w", err)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("redaction: no tx_rdt for %s; the round did not reach threshold", contractAddr)
	}
	var rdt RedactionTx
	if err := json.Unmarshal(b, &rdt); err != nil {
		return nil, fmt.Errorf("redaction: decode tx_rdt: %w", err)
	}
	return &rdt, nil
}

// -----------------------------------------------------------------------------
// Signature verification
// -----------------------------------------------------------------------------

// verifyBallot checks xi_j against the vote message.
//
// The message binds addr(con_k) and the request id, so a signature captured
// from one round cannot be replayed into another.
//
// The verification is Schnorr in (e, s) form and MUST match pkg/crypto exactly,
// including the public key in the challenge — a divergence here would make
// valid votes look invalid on chain and quietly starve every round.
func verifyBallot(n Node, contractAddr, requestID string, bal Ballot) (bool, error) {
	curve := elliptic.P256()

	px, ok := new(big.Int).SetString(n.PubX, 16)
	if !ok {
		return false, fmt.Errorf("redaction: node %s has a malformed public key x", n.ID)
	}
	py, ok := new(big.Int).SetString(n.PubY, 16)
	if !ok {
		return false, fmt.Errorf("redaction: node %s has a malformed public key y", n.ID)
	}
	e, ok := new(big.Int).SetString(bal.E, 16)
	if !ok {
		return false, fmt.Errorf("redaction: ballot from %s has a malformed e", bal.NodeID)
	}
	sv, ok := new(big.Int).SetString(bal.S, 16)
	if !ok {
		return false, fmt.Errorf("redaction: ballot from %s has a malformed s", bal.NodeID)
	}

	if !curve.IsOnCurve(px, py) {
		return false, fmt.Errorf("redaction: node %s has an off-curve public key", n.ID)
	}
	nOrder := curve.Params().N
	if e.Sign() <= 0 || e.Cmp(nOrder) >= 0 || sv.Sign() <= 0 || sv.Cmp(nOrder) >= 0 {
		return false, nil
	}

	msg := voteMessage(contractAddr, requestID, bal.Approve)

	// R' = s*G - e*P, computed as s*G + (n-e)*P.
	//
	// MUST match pkg/crypto.SchnorrPublicKey.Verify. Getting the sign wrong here
	// would reject every honest vote, and the symptom would be rounds that never
	// reach threshold — which reads as a slow network rather than a broken
	// verifier. TestChaincodeVerifiesPkgCryptoSignatures pins the agreement.
	sgx, sgy := curve.ScalarBaseMult(sv.Bytes())
	negE := new(big.Int).Sub(nOrder, e)
	epx, epy := curve.ScalarMult(px, py, negE.Bytes())
	rx, ry := curve.Add(sgx, sgy, epx, epy)

	// The identity element marshals to a fixed encoding, so an attacker able to
	// force it could produce a challenge independent of the key.
	if rx.Sign() == 0 && ry.Sign() == 0 {
		return false, nil
	}

	got := schnorrChallenge(curve, rx, ry, px, py, msg)
	return got.Cmp(e) == 0, nil
}

// voteMessage must match internal/schemes/ref10.voteMessage byte for byte.
func voteMessage(contractAddr, requestID string, approve bool) []byte {
	h := sha256.New()
	h.Write([]byte(contractAddr))
	h.Write([]byte{0x1f})
	h.Write([]byte(requestID))
	h.Write([]byte{0x1f})
	if approve {
		h.Write([]byte("yes"))
	} else {
		h.Write([]byte("no"))
	}
	return h.Sum(nil)
}

// schnorrChallenge must match pkg/crypto.SchnorrPublicKey.challenge byte for
// byte, including the public key binding.
func schnorrChallenge(curve elliptic.Curve, rx, ry, px, py *big.Int, m []byte) *big.Int {
	h := sha256.New()
	h.Write(elliptic.Marshal(curve, rx, ry))
	h.Write(elliptic.Marshal(curve, px, py))
	h.Write(m)
	e := new(big.Int).SetBytes(h.Sum(nil))
	return e.Mod(e, curve.Params().N)
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func stateKey(prefix string, parts ...string) string {
	key := prefix
	for _, p := range parts {
		key += "/" + p
	}
	return key
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func findNode(all []Node, id string) (Node, bool) {
	for _, n := range all {
		if n.ID == id {
			return n, true
		}
	}
	return Node{}, false
}

// hexPoint encodes a curve point for storage. Exported for the client side to
// mirror.
func hexPoint(v *big.Int) string { return hex.EncodeToString(v.Bytes()) }

// main runs the contract either as a peer-launched chaincode or as a chaincode
// service (ccaas), selected by CHAINCODE_SERVER_ADDRESS.
//
// The service mode exists because the peer-launched mode asks the peer to build
// a container image through the Docker socket, which does not work under Docker
// Desktop on Windows: the proxy closes the connection mid-build and the error
// surfaces as "broken pipe" from the peer rather than as anything about the
// chaincode. Running the contract as its own container removes the peer's build
// step entirely.
//
// It is also what production Fabric deployments use, so this is not a
// workaround the evaluation carries as debt — the same packaging works on the
// Linux target.
func main() {
	cc, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		panic(fmt.Sprintf("redaction: create chaincode: %v", err))
	}

	if addr := os.Getenv("CHAINCODE_SERVER_ADDRESS"); addr != "" {
		ccid := os.Getenv("CHAINCODE_ID")
		if ccid == "" {
			panic("redaction: CHAINCODE_SERVER_ADDRESS is set but CHAINCODE_ID is not; " +
				"the peer matches a chaincode service by its package id")
		}
		server := &shim.ChaincodeServer{
			CCID:    ccid,
			Address: addr,
			CC:      cc,
			// TLS is disabled on the chaincode link only. The channel, the
			// gateway and every client connection remain TLS-protected; this is
			// the peer-to-chaincode hop inside the compose network.
			TLSProps: shim.TLSProperties{Disabled: true},
		}
		if err := server.Start(); err != nil {
			panic(fmt.Sprintf("redaction: start chaincode server: %v", err))
		}
		return
	}

	if err := cc.Start(); err != nil {
		panic(fmt.Sprintf("redaction: start chaincode: %v", err))
	}
}
