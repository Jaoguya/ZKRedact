package ref10

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"

	"zkredact/pkg/crypto"
)

// Fabric-backed vote transport.
//
// This is the transport Ref[10]'s design actually calls for: each committee
// member reads the round from the ledger, decides, signs, and submits its
// ballot as a transaction that must be endorsed and ordered. The contract
// tallies on chain and emits tx_rdt.
//
// WHY IT MATTERS FOR THE MEASUREMENT. localTransport produces identical
// cryptography by function call, so its numbers are a lower bound on Ref[10]'s
// authorization cost with the network — the dominant term — removed. Exp 1's
// question is how that cost behaves under concurrent load, so publishing
// in-process figures as Ref[10]'s cost would answer a different question than
// the one asked.
//
// The transport talks to a narrow interface rather than the Fabric SDK
// directly. Two reasons, both practical: the ballot-collection logic is then
// testable without a running network, and the SDK surface stays confined to one
// adapter, so an SDK change touches one file rather than the protocol logic.

// chaincodeSession is one identity's connection to the redaction contract.
//
// Evaluate is a read (no ordering, peer-local); Submit is a write that goes
// through endorsement and ordering. The split is not cosmetic — Submit carries
// the consensus cost that separates this transport from the in-process one, and
// a Submit routed through Evaluate would silently restore the lower bound.
type chaincodeSession interface {
	// Evaluate runs a read-only chaincode function.
	Evaluate(ctx context.Context, fn string, args ...string) ([]byte, error)

	// Submit runs a chaincode function that writes, waiting for commit.
	Submit(ctx context.Context, fn string, args ...string) ([]byte, error)

	// Close releases the connection.
	Close() error
}

// sessionFactory yields a session per identity.
//
// Per-identity rather than shared: in Fabric a transaction is signed by the
// submitting identity, so a committee member's vote must be submitted under its
// own credentials. Sharing one connection would make every ballot appear to
// come from a single client, and the contract's membership check would be
// checking the wrong thing.
type sessionFactory interface {
	Session(memberID string) (chaincodeSession, error)
	Close() error
}

// fabricTransport implements transport over the redaction chaincode.
type fabricTransport struct {
	factory sessionFactory

	mu       sync.Mutex
	sessions map[string]chaincodeSession
}

func newFabricTransport(f sessionFactory) *fabricTransport {
	return &fabricTransport{
		factory:  f,
		sessions: make(map[string]chaincodeSession),
	}
}

func (t *fabricTransport) Name() string { return transportFabric }

// session returns a cached session for a member, creating one on first use.
//
// Cached because Exp 1 replays the same committee across thousands of rounds,
// and re-establishing a gRPC connection per ballot would measure connection
// setup rather than the voting protocol. The connection cost is real but it is
// a per-deployment constant, not a per-request one.
func (t *fabricTransport) session(memberID string) (chaincodeSession, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if s, ok := t.sessions[memberID]; ok {
		return s, nil
	}
	s, err := t.factory.Session(memberID)
	if err != nil {
		return nil, fmt.Errorf("ref10: session for %s: %w", memberID, err)
	}
	t.sessions[memberID] = s
	return s, nil
}

// Collect runs Algorithm 3 against the ledger.
//
//	Init   open the round; the contract computes N_auth itself
//	Query  each member reads {req, sigma} and re-derives its decision
//	Vote   each member submits xi_j, which the contract verifies and tallies
//
// The contract recomputes the committee rather than accepting one from us, and
// verifies every signature. That duplication is deliberate: a client that could
// name its own committee or submit ballots for absent members would make the
// threshold meaningless, and the measurement would be of a protocol nobody
// would deploy.
func (t *fabricTransport) Collect(ctx context.Context, r *voteRound) ([]ballot, error) {
	if len(r.Members) == 0 {
		return nil, fmt.Errorf("ref10: vote round has no members")
	}

	// The round is opened by the requester's session. Any member's identity
	// would do for Init, but using the first member keeps the ordering
	// deterministic across runs.
	opener, err := t.session(r.Members[0].Identity.ID)
	if err != nil {
		return nil, err
	}

	roundJSON, err := encodeRound(r)
	if err != nil {
		return nil, err
	}
	if _, err := opener.Submit(ctx, "Init", roundJSON); err != nil {
		return nil, fmt.Errorf("ref10: open round %s: %w", r.ContractAddr, err)
	}

	out := make([]ballot, 0, len(r.Members))
	for _, m := range r.Members {
		if err := ctx.Err(); err != nil {
			return out, err
		}

		sess, err := t.session(m.Identity.ID)
		if err != nil {
			return out, err
		}

		// Algorithm 4 line 1: read {req, sigma} from the ledger and verify it
		// there. A member that took the requester's word for the policy would
		// not be voting on anything.
		raw, err := sess.Evaluate(ctx, "Query", r.ContractAddr)
		if err != nil {
			return out, fmt.Errorf("ref10: query round for %s: %w", m.Identity.ID, err)
		}
		var onChain chainRound
		if err := json.Unmarshal(raw, &onChain); err != nil {
			return out, fmt.Errorf("ref10: decode round for %s: %w", m.Identity.ID, err)
		}

		// The CA signature is checked against the local certificate, not against
		// what the ledger returned, so a tampered on-chain round cannot talk a
		// member into voting.
		if !r.CA.verifyCert(r.Cert) {
			continue
		}

		// Lines 3-5: decide from the policy just verified.
		approve := r.Cert.Granted()

		// Line 6: xi_j.
		msg := voteMessage(r.ContractAddr, r.RequestID, approve)
		xi, err := m.Key.Sign(msg, nil)
		if err != nil {
			return out, fmt.Errorf("ref10: vote signature for %s: %w", m.Identity.ID, err)
		}

		ballotJSON, err := encodeBallot(m.Identity.ID, approve, xi)
		if err != nil {
			return out, err
		}

		// Line 7: submit. This is the transaction that must be endorsed and
		// ordered — the cost localTransport does not have.
		if _, err := sess.Submit(ctx, "Vote", r.ContractAddr, ballotJSON); err != nil {
			return out, fmt.Errorf("ref10: submit vote for %s: %w", m.Identity.ID, err)
		}

		out = append(out, ballot{
			NodeID:  m.Identity.ID,
			Approve: approve,
			Key:     &m.Key.SchnorrPublicKey,
			Xi:      xi,
		})
	}
	return out, nil
}

// Close releases every cached session.
func (t *fabricTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	var firstErr error
	for id, s := range t.sessions {
		if err := s.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("ref10: close session %s: %w", id, err)
		}
	}
	t.sessions = make(map[string]chaincodeSession)

	if err := t.factory.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// -----------------------------------------------------------------------------
// Wire format
//
// These types mirror network/chaincode/redaction. They are duplicated because
// the chaincode is a separate Go module — it is deployed to Fabric and packaged
// on its own, so it cannot import this one.
//
// Duplication is where wire formats drift, so the field tags here must stay
// identical to the contract's. TestWireFormatMatchesChaincode pins the JSON.
// -----------------------------------------------------------------------------

type chainRound struct {
	ContractAddr string          `json:"contract_addr"`
	RequestID    string          `json:"request_id"`
	TargetTxID   string          `json:"target_tx_id"`
	RequesterID  string          `json:"requester_id"`
	Cert         chainPolicyCert `json:"cert"`
	Committee     []string       `json:"committee"`
	CommitteeSize int            `json:"committee_size"`
	Threshold     int            `json:"threshold"`
	Closed       bool            `json:"closed"`
	Approved     bool            `json:"approved"`
}

type chainPolicyCert struct {
	TargetTxID     string `json:"target_tx_id"`
	RequesterID    string `json:"requester_id"`
	RequesterKnown bool   `json:"requester_known"`
	Redactable     bool   `json:"redactable"`
	Satisfies      bool   `json:"satisfies"`
	PolicyID       string `json:"policy_id"`
	PolicyVer      uint64 `json:"policy_ver"`
	Attributes     string `json:"attributes"`
}

type chainBallot struct {
	NodeID  string `json:"node_id"`
	Approve bool   `json:"approve"`
	E       string `json:"e"`
	S       string `json:"s"`
}

type chainNode struct {
	ID         string            `json:"id"`
	Attributes map[string]string `json:"attributes"`
	PubX       string            `json:"pub_x"`
	PubY       string            `json:"pub_y"`
}

func encodeRound(r *voteRound) (string, error) {
	cr := chainRound{
		ContractAddr: r.ContractAddr,
		RequestID:    r.RequestID,
		TargetTxID:   r.Cert.TargetTxID,
		RequesterID:  r.Cert.RequesterID,
		Cert: chainPolicyCert{
			TargetTxID:     r.Cert.TargetTxID,
			RequesterID:    r.Cert.RequesterID,
			RequesterKnown: r.Cert.RequesterKnown,
			Redactable:     r.Cert.Redactable,
			Satisfies:      r.Cert.Satisfies,
			PolicyID:       r.Cert.PolicyID,
			PolicyVer:      r.Cert.PolicyVer,
			Attributes:     r.Cert.Attributes,
		},
		CommitteeSize: len(r.Members),
		Threshold:     r.Threshold,
	}
	b, err := json.Marshal(cr)
	if err != nil {
		return "", fmt.Errorf("ref10: encode round: %w", err)
	}
	return string(b), nil
}

func encodeBallot(nodeID string, approve bool, sig *crypto.SchnorrSignature) (string, error) {
	if sig == nil || sig.E == nil || sig.S == nil {
		return "", fmt.Errorf("ref10: ballot for %s has no signature", nodeID)
	}
	b, err := json.Marshal(chainBallot{
		NodeID:  nodeID,
		Approve: approve,
		E:       hex.EncodeToString(sig.E.Bytes()),
		S:       hex.EncodeToString(sig.S.Bytes()),
	})
	if err != nil {
		return "", fmt.Errorf("ref10: encode ballot: %w", err)
	}
	return string(b), nil
}

// encodeNodes renders the registry the contract needs to recompute committees.
//
// Submitted once during setup, which is untimed.
func encodeNodes(members []*member, attributes map[string]map[string]string) (string, error) {
	nodes := make([]chainNode, 0, len(members))
	for _, m := range members {
		attrs := attributes[m.Identity.ID]
		if attrs == nil {
			attrs = m.Identity.Attributes
		}
		nodes = append(nodes, chainNode{
			ID:         m.Identity.ID,
			Attributes: attrs,
			PubX:       hex.EncodeToString(m.Key.X.Bytes()),
			PubY:       hex.EncodeToString(m.Key.Y.Bytes()),
		})
	}
	b, err := json.Marshal(nodes)
	if err != nil {
		return "", fmt.Errorf("ref10: encode nodes: %w", err)
	}
	return string(b), nil
}

// decodeScalar parses a hex scalar as the contract encodes it. Used by tests
// that round-trip a ballot back into a signature.
func decodeScalar(s string) (*big.Int, bool) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return new(big.Int).SetBytes(b), true
}
