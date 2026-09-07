// Package main implements Ref[10]'s redaction smart contract as Fabric
// chaincode.
//
// Source: Ref[10].md Algorithm 3, "Redaction Smart Contract Functions".
//
//	init(con_k)   N_auth <- RS_SHA256(addr(con_k), N_all, A_r);  store pk_j
//	query(con_k)  return {req, sigma}
//	vote(n_j, con_k, t)  verify xi_j; count yes; on threshold emit tx_rdt
//
// A ROUND COSTS TWO BLOCKS, NOT THREE, AND THE MISSING ONE IS init().
//
// Algorithm 3 line 4 says "Store N_auth in con_k", which we implemented as its
// own Init transaction. A ballot then had to WAIT for that write to commit
// before it could read the round, so every authorization paid a block of pure
// latency before any vote existed. On an unsaturated network that is a full
// BatchTimeout, and it is an artefact of storing N_auth rather than of
// authorizing anything.
//
// N_auth is a pure function of addr(con_k), the registered node set and A_r
// (Eq. 7), so every peer can recompute it instead of reading it. Vote does
// exactly that. What the stored round also carried was {req, sigma}, which
// Algorithm 4 line 1 requires a member to verify "against P_C from the CA" —
// and :317 defines the CA's reply as a SIGNED message, msg = {P_C, sigma}.
// So the trust anchor Algorithm 4 names is the CA's signature, not the ledger
// write. Each ballot now carries the CA-signed certificate and this contract
// verifies that signature before deriving anything from it.
//
// Recorded as a deviation in docs/baselines/ref10-emt.md with its direction:
// it removes a block from Ref[10]'s measured cost (favours Ref[10]) while
// adding one CA signature verification per ballot (counts against it), and it
// strengthens the contract, which until now accepted an UNSIGNED certificate.
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
	"encoding/binary"
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
	keyBallot  = "ballot" // ballot/<contractAddr>/<nodeID>
	keyRdt     = "rdt"    // rdt/<contractAddr>
	keyNodeSet = "nodes"  // nodes  (the network's registered nodes)

	// keyPolicy holds |N_auth| and the threshold, plus the CA's verification
	// key. Registered once at setup, never per round.
	//
	// These must NOT arrive with a ballot. A voter that could name the
	// threshold could set it to 1 and authorize alone, and a voter that could
	// name the committee size could shrink N_auth until its own vote was a
	// majority. They are protocol parameters, not per-request input.
	keyPolicy = "roundpolicy" // roundpolicy
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

	// SigE, SigS are the CA's Schnorr signature over Bytes(), hex-encoded.
	//
	// Algorithm 4 line 1 has each member verify {req, sigma} "against P_C from
	// the CA", and :317 defines the CA's reply as msg = {P_C, sigma}. Without
	// this the certificate is just a struct the caller filled in, and every
	// eligibility decision below rests on it.
	SigE string `json:"sig_e"`
	SigS string `json:"sig_s"`
}

// Bytes serialises P_C for signature verification.
//
// MUST match internal/schemes/ref10.policyCert.bytes() byte for byte. The CA
// signs there and this verifies here, so a divergence makes every honest
// certificate fail — and the symptom is rounds that never reach threshold,
// which reads as a slow network. TestChaincodeVerifiesCACertificate pins it.
func (c PolicyCert) Bytes() []byte {
	var b []byte
	b = append(b, c.TargetTxID...)
	b = append(b, 0x1f)
	b = append(b, c.RequesterID...)
	b = append(b, 0x1f)
	b = append(b, c.PolicyID...)
	b = append(b, 0x1f)
	b = append(b, c.Attributes...)
	b = append(b, 0x1f)
	var ver [8]byte
	binary.BigEndian.PutUint64(ver[:], c.PolicyVer)
	b = append(b, ver[:]...)
	for _, flag := range []bool{c.RequesterKnown, c.Redactable, c.Satisfies} {
		if flag {
			b = append(b, 1)
		} else {
			b = append(b, 0)
		}
	}
	return b
}

// Digest identifies WHICH certificate a ballot voted on.
//
// Every ballot signs it, and Close counts only ballots that agree on it. Two
// members handed different certificates for the same contract address are not
// voting on the same thing, and counting them together would let a requester
// assemble a threshold out of votes on different requests.
func (c PolicyCert) Digest() string {
	sum := sha256.Sum256(c.Bytes())
	return hex.EncodeToString(sum[:])
}

// RoundPolicy is the protocol parameter set, registered once at setup.
type RoundPolicy struct {
	// CommitteeSize is |N_auth| and Threshold is the approvals required, both
	// from the fault assumption in config/experiment.yaml.
	CommitteeSize int `json:"committee_size"`
	Threshold     int `json:"threshold"`

	// CAPubX, CAPubY verify PolicyCert.SigE/SigS.
	CAPubX string `json:"ca_pub_x"`
	CAPubY string `json:"ca_pub_y"`
}

// Granted reports whether P_C authorises the redaction: Eq. 5's two conditions,
// plus the requester being known to the CA at all.
func (c PolicyCert) Granted() bool {
	return c.RequesterKnown && c.Redactable && c.Satisfies
}

// Ballot is one member's vote, xi_j, together with the request it votes on.
//
// The request travels WITH the ballot rather than being read from a stored
// round, which is what removes init()'s block. It is safe because Cert carries
// the CA's signature: a member is not taking the requester's word for P_C, it
// is checking the CA's, which is what Algorithm 4 line 1 asks for.
type Ballot struct {
	NodeID  string `json:"node_id"`
	Approve bool   `json:"approve"`

	// RequestID and TargetTxID identify the redaction request req.
	RequestID  string `json:"request_id"`
	TargetTxID string `json:"target_tx_id"`

	// Cert is the CA's signed P_C. Verified before anything is derived from it.
	Cert PolicyCert `json:"cert"`

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
// Algorithm 3: init, without a transaction
// -----------------------------------------------------------------------------

// RegisterRoundPolicy stores |N_auth|, the threshold, and the CA's key.
//
// Called once during setup, which is not timed — the same place RegisterNodes
// is called. This is what lets init() disappear from the per-round path: the
// only parts of the stored round that a client must not choose are these, and
// they do not vary per request.
//
// Registering them here rather than accepting them per ballot is the whole
// guard. A voter that named its own threshold could authorize alone; a voter
// that named its own committee size could shrink N_auth until it held a
// majority. Neither is reachable once the values live in state that voting
// never writes.
func (s *SmartContract) RegisterRoundPolicy(ctx contractapi.TransactionContextInterface, policyJSON string) error {
	var p RoundPolicy
	if err := json.Unmarshal([]byte(policyJSON), &p); err != nil {
		return fmt.Errorf("redaction: decode round policy: %w", err)
	}
	if p.CommitteeSize <= 0 {
		return fmt.Errorf("redaction: committee_size must be positive, got %d", p.CommitteeSize)
	}
	if p.Threshold <= 0 {
		return fmt.Errorf("redaction: threshold must be positive, got %d", p.Threshold)
	}
	if p.Threshold > p.CommitteeSize {
		return fmt.Errorf(
			"redaction: threshold %d exceeds committee size %d; no redaction could be approved",
			p.Threshold, p.CommitteeSize)
	}
	if p.CAPubX == "" || p.CAPubY == "" {
		return fmt.Errorf(
			"redaction: round policy has no CA verification key; every ballot's " +
				"certificate would then be unverifiable and P_C would mean nothing")
	}
	b, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("redaction: encode round policy: %w", err)
	}
	return ctx.GetStub().PutState(keyPolicy, b)
}

func (s *SmartContract) roundPolicy(ctx contractapi.TransactionContextInterface) (*RoundPolicy, error) {
	b, err := ctx.GetStub().GetState(keyPolicy)
	if err != nil {
		return nil, fmt.Errorf("redaction: read round policy: %w", err)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("redaction: no round policy registered; call RegisterRoundPolicy first")
	}
	var p RoundPolicy
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("redaction: decode round policy: %w", err)
	}
	return &p, nil
}

// verifyCert checks the CA's signature on P_C.
//
// This is Algorithm 4 line 1's "against P_C from the CA". It runs before the
// committee is derived, because the derivation consumes cert.Attributes: an
// unverified certificate could otherwise name an attribute policy that selects
// a committee of the caller's choosing.
func verifyCert(p *RoundPolicy, cert PolicyCert) (bool, error) {
	if cert.SigE == "" || cert.SigS == "" {
		return false, nil
	}
	return verifySchnorr(p.CAPubX, p.CAPubY, cert.Bytes(), cert.SigE, cert.SigS)
}

// committeeFor recomputes N_auth = RS_SHA256(addr(con_k), N_all, A_r), Eq. 7.
//
// Algorithm 3 line 4 stores this; we derive it. The inputs are the contract
// address, the registered node set and the attribute policy, all of which are
// either fixed or carried on the CA-signed certificate, so every peer reaches
// the same answer without a stored round to read.
func (s *SmartContract) committeeFor(
	ctx contractapi.TransactionContextInterface,
	contractAddr string,
	cert PolicyCert,
	size int,
) ([]string, []Node, error) {

	all, err := s.nodes(ctx)
	if err != nil {
		return nil, nil, err
	}
	committee, err := selectCommittee(contractAddr, all, cert.Attributes, size)
	if err != nil {
		return nil, nil, err
	}
	if len(committee) < size {
		return nil, nil, fmt.Errorf(
			"redaction: only %d nodes satisfy the policy but committee_size is %d; "+
				"a silently shrunken committee would weaken the threshold",
			len(committee), size)
	}
	return committee, all, nil
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
// Algorithm 3: vote
// -----------------------------------------------------------------------------

// Vote submits one ballot and verifies it. It does NOT tally.
//
// Implements Algorithm 3 vote() together with Algorithm 4's verification step.
// Four checks make the threshold meaningful, and each corresponds to a way a
// client could otherwise manufacture authorization:
//
//	CA signature the certificate is the CA's, not the caller's invention
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
// independent nodes and their ballots belong in one block. Close() does the
// counting afterwards, in its own transaction.
//
// WHAT THIS READS AND WRITES, which is the property that keeps ballots in one
// block: it reads the node set, the round policy and its OWN ballot key — none
// of which another ballot writes — and it writes only its own ballot key. Add
// a read of anything voting writes and the concurrency collapses silently back
// to one ballot per block.
//
// Returns nil on success: the ballot is recorded, and whether the round reached
// threshold is Close()'s answer, not this one's.
func (s *SmartContract) Vote(ctx contractapi.TransactionContextInterface, contractAddr, ballotJSON string) (*RedactionTx, error) {
	var bal Ballot
	if err := json.Unmarshal([]byte(ballotJSON), &bal); err != nil {
		return nil, fmt.Errorf("redaction: decode ballot: %w", err)
	}
	if bal.NodeID == "" || bal.RequestID == "" {
		return nil, fmt.Errorf("redaction: ballot needs a node id and a request id")
	}

	policy, err := s.roundPolicy(ctx)
	if err != nil {
		return nil, err
	}

	// Algorithm 4 line 1, and it runs FIRST. Everything below derives from the
	// certificate — eligibility, the committee, the message signed — so an
	// unverified one would let the caller choose all three.
	certOK, err := verifyCert(policy, bal.Cert)
	if err != nil {
		return nil, err
	}
	if !certOK {
		return nil, fmt.Errorf(
			"redaction: certificate for %s does not carry a valid CA signature", contractAddr)
	}

	committee, all, err := s.committeeFor(ctx, contractAddr, bal.Cert, policy.CommitteeSize)
	if err != nil {
		return nil, err
	}
	if !contains(committee, bal.NodeID) {
		return nil, fmt.Errorf(
			"redaction: %s is not on the committee for %s", bal.NodeID, contractAddr)
	}

	// One member, one vote. Reads only this member's own key.
	ballotKey := stateKey(keyBallot, contractAddr, bal.NodeID)
	prev, err := ctx.GetStub().GetState(ballotKey)
	if err != nil {
		return nil, fmt.Errorf("redaction: read ballot: %w", err)
	}
	if len(prev) > 0 {
		return nil, fmt.Errorf("redaction: %s has already voted in %s", bal.NodeID, contractAddr)
	}

	node, ok := findNode(all, bal.NodeID)
	if !ok {
		return nil, fmt.Errorf("redaction: unknown node %s", bal.NodeID)
	}

	// Algorithm 4 line 5: verify xi_j before counting it.
	ok, err = verifyBallot(node, contractAddr, bal.RequestID, bal)
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
	if existing, err := ctx.GetStub().GetState(stateKey(keyRdt, contractAddr)); err != nil {
		return nil, fmt.Errorf("redaction: read tx_rdt: %w", err)
	} else if len(existing) > 0 {
		return s.Result(ctx, contractAddr)
	}
	return s.tally(ctx, contractAddr)
}

// tally counts approvals and, on reaching the threshold, emits tx_rdt.
//
// The committee is recomputed here rather than read from a stored round, from
// the certificate the ballots themselves carry. Every ballot got past Vote's
// CA-signature check, so any of them can supply it.
//
// BALLOTS ARE GROUPED BY CERTIFICATE DIGEST, and only the largest agreeing
// group can reach the threshold. Without this, a requester holding two
// CA-signed certificates for the same contract address could collect votes on
// one from half the committee and votes on the other from the rest, and present
// the sum as authorization for either. Members would each have voted honestly
// on something they never jointly approved.
func (s *SmartContract) tally(ctx contractapi.TransactionContextInterface, contractAddr string) (*RedactionTx, error) {
	policy, err := s.roundPolicy(ctx)
	if err != nil {
		return nil, err
	}

	// Read every ballot the address could hold. The committee depends on the
	// certificate, which is on the ballots, so the node set is scanned instead
	// — a ballot from a non-member cannot exist, because Vote rejected it.
	all, err := s.nodes(ctx)
	if err != nil {
		return nil, err
	}

	byCert := make(map[string][]Ballot)
	certs := make(map[string]PolicyCert)
	for _, n := range all {
		b, err := ctx.GetStub().GetState(stateKey(keyBallot, contractAddr, n.ID))
		if err != nil {
			return nil, fmt.Errorf("redaction: read ballot for %s: %w", n.ID, err)
		}
		if len(b) == 0 {
			continue
		}
		var bal Ballot
		if err := json.Unmarshal(b, &bal); err != nil {
			return nil, fmt.Errorf("redaction: decode ballot for %s: %w", n.ID, err)
		}
		if !bal.Approve {
			continue
		}
		d := bal.Cert.Digest()
		byCert[d] = append(byCert[d], bal)
		certs[d] = bal.Cert
	}

	// The winning group, chosen deterministically: most approvals, ties broken
	// by digest so every peer emits the same tx_rdt and endorsement matches.
	var bestDigest string
	for d, group := range byCert {
		switch {
		case bestDigest == "":
			bestDigest = d
		case len(group) > len(byCert[bestDigest]):
			bestDigest = d
		case len(group) == len(byCert[bestDigest]) && d < bestDigest:
			bestDigest = d
		}
	}
	if bestDigest == "" || len(byCert[bestDigest]) < policy.Threshold {
		// Round stays open; the caller sees a nil result and keeps collecting.
		return nil, nil
	}

	approving := byCert[bestDigest]
	cert := certs[bestDigest]

	// Membership is re-checked at tally time, not trusted from Vote. Vote
	// checked it against the committee derived from this same certificate, but
	// re-deriving here means a ballot stored under an earlier node registration
	// cannot be counted after the set changed.
	committee, _, err := s.committeeFor(ctx, contractAddr, cert, policy.CommitteeSize)
	if err != nil {
		return nil, err
	}
	counted := make([]Ballot, 0, len(approving))
	for _, bal := range approving {
		if contains(committee, bal.NodeID) {
			counted = append(counted, bal)
		}
	}
	if len(counted) < policy.Threshold {
		return nil, nil
	}

	rdt := &RedactionTx{
		ContractAddr: contractAddr,
		RequestID:    counted[0].RequestID,
		TargetTxID:   cert.TargetTxID,
		Sigma:        counted,
		Approvals:    len(counted),
		Threshold:    policy.Threshold,
	}
	rb, err := json.Marshal(rdt)
	if err != nil {
		return nil, fmt.Errorf("redaction: encode tx_rdt: %w", err)
	}
	if err := ctx.GetStub().PutState(stateKey(keyRdt, contractAddr), rb); err != nil {
		return nil, fmt.Errorf("redaction: store tx_rdt: %w", err)
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
	msg := voteMessage(contractAddr, requestID, bal.Cert.Digest(), bal.Approve)
	ok, err := verifySchnorr(n.PubX, n.PubY, msg, bal.E, bal.S)
	if err != nil {
		return false, fmt.Errorf("redaction: ballot from %s: %w", bal.NodeID, err)
	}
	return ok, nil
}

// verifySchnorr checks one Schnorr signature against a hex-encoded public key.
//
// Shared by ballot verification and by the CA-certificate check, so both use
// exactly the same verifier. Two copies of this arithmetic would be two places
// for the sign of e to drift, and a wrong sign rejects every honest signature
// while looking like a slow or unreachable network.
//
// MUST match pkg/crypto.SchnorrPublicKey.Verify.
// TestChaincodeVerifiesPkgCryptoSignatures pins the agreement.
func verifySchnorr(pubX, pubY string, msg []byte, sigE, sigS string) (bool, error) {
	curve := elliptic.P256()

	px, ok := new(big.Int).SetString(pubX, 16)
	if !ok {
		return false, fmt.Errorf("malformed public key x")
	}
	py, ok := new(big.Int).SetString(pubY, 16)
	if !ok {
		return false, fmt.Errorf("malformed public key y")
	}
	e, ok := new(big.Int).SetString(sigE, 16)
	if !ok {
		return false, fmt.Errorf("malformed signature scalar e")
	}
	sv, ok := new(big.Int).SetString(sigS, 16)
	if !ok {
		return false, fmt.Errorf("malformed signature scalar s")
	}

	if !curve.IsOnCurve(px, py) {
		return false, fmt.Errorf("off-curve public key")
	}
	nOrder := curve.Params().N
	if e.Sign() <= 0 || e.Cmp(nOrder) >= 0 || sv.Sign() <= 0 || sv.Cmp(nOrder) >= 0 {
		return false, nil
	}

	// R' = s*G - e*P, computed as s*G + (n-e)*P.
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
func voteMessage(contractAddr, requestID, certDigest string, approve bool) []byte {
	h := sha256.New()
	h.Write([]byte(contractAddr))
	h.Write([]byte{0x1f})
	h.Write([]byte(requestID))
	h.Write([]byte{0x1f})
	// THE CERTIFICATE IS PART OF WHAT A MEMBER SIGNS.
	//
	// The certificate travels with the ballot now that no stored round holds
	// it. Without binding it here, a ballot collected for one CA-signed
	// certificate could be re-submitted verbatim alongside a different one and
	// would verify, because the signature would say nothing about which P_C the
	// member actually saw. Close's grouping would then count it in the wrong
	// group. TestBallotSignatureBindsTheCertificate pins this.
	h.Write([]byte(certDigest))
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
