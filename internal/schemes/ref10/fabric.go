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

	// NO INIT TRANSACTION. Algorithm 3 line 4 says "Store N_auth in con_k", and
	// storing it cost a whole block before any vote could read it — on an
	// unsaturated network, a full BatchTimeout of pure latency per
	// authorization. N_auth is a pure function of addr(con_k), the registered
	// node set and A_r (Eq. 7), so the contract recomputes it per ballot
	// instead. What the stored round also carried, {req, sigma}, now travels on
	// the ballot with the CA's signature over it — which is the trust anchor
	// Algorithm 4 line 1 actually names.
	//
	// A round therefore costs TWO blocks: ballots, then Close. Recorded as a
	// deviation in docs/baselines/ref10-emt.md.

	// Ballots are submitted CONCURRENTLY, because Ref[10]'s committee members
	// are independent nodes. Algorithm 3 does not serialize them, and a loop
	// here would cost one block per member — (1 + committee_size) blocks per
	// round instead of two, inflating Ref[10]'s measured latency by roughly
	// committee_size and biasing Exp 1 in ZK-Redact's favour.
	//
	// This is only safe because the contract's Vote does not tally: it reads
	// round metadata that voting never writes, and writes only its own ballot
	// key. Restoring a tally inside Vote would put every member's ballot key in
	// every ballot's read set and the second ballot in each block would fail
	// with MVCC_READ_CONFLICT. Close() below does the counting, alone.
	type voteResult struct {
		b    ballot
		cast bool
		err  error
	}
	results := make(chan voteResult, len(r.Members))

	for _, m := range r.Members {
		go func(m *member) {
			if err := ctx.Err(); err != nil {
				results <- voteResult{err: err}
				return
			}

			sess, err := t.session(m.Identity.ID)
			if err != nil {
				results <- voteResult{err: err}
				return
			}

			// Algorithm 4 line 1: verify {req, sigma} against P_C from the CA.
			//
			// This used to Evaluate("Query") first, to read the round from the
			// ledger. It never decided anything — the signature was always
			// checked against the local certificate, precisely so a tampered
			// on-chain round could not talk a member into voting — so the read
			// was a round trip whose result was discarded. What makes a member
			// more than a rubber stamp is the CA signature below, and it is
			// verified here exactly as before.
			if !r.CA.verifyCert(r.Cert) {
				results <- voteResult{}
				return
			}

			// Lines 3-5: decide from the policy just verified.
			approve := r.Cert.Granted()

			// Line 6: xi_j.
			msg := voteMessage(r.ContractAddr, r.RequestID, certDigest(r.Cert), approve)
			xi, err := m.Key.Sign(msg, nil)
			if err != nil {
				results <- voteResult{err: fmt.Errorf("ref10: vote signature for %s: %w", m.Identity.ID, err)}
				return
			}

			ballotJSON, err := encodeBallot(m.Identity.ID, approve, r, xi)
			if err != nil {
				results <- voteResult{err: err}
				return
			}

			// Line 7: submit. This is the transaction that must be endorsed and
			// ordered — the cost localTransport does not have.
			if _, err := sess.Submit(ctx, "Vote", r.ContractAddr, ballotJSON); err != nil {
				results <- voteResult{err: fmt.Errorf("ref10: submit vote for %s: %w", m.Identity.ID, err)}
				return
			}

			results <- voteResult{cast: true, b: ballot{
				NodeID:  m.Identity.ID,
				Approve: approve,
				Key:     &m.Key.SchnorrPublicKey,
				Xi:      xi,
			}}
		}(m)
	}

	// Collect every goroutine before returning, so no ballot is still in flight
	// when Close tallies. Ordering is by arrival, which Collect's contract
	// permits; the tally on chain does not depend on it.
	out := make([]ballot, 0, len(r.Members))
	var firstErr error
	for range r.Members {
		res := <-results
		switch {
		case res.err != nil:
			if firstErr == nil {
				firstErr = res.err
			}
		case res.cast:
			out = append(out, res.b)
		}
	}
	if firstErr != nil {
		return out, firstErr
	}

	// Algorithm 3 close(): the contract counts the ballots and emits tx_rdt.
	// One transaction, after voting, because it reads every ballot key.
	closer, err := t.session(r.Members[0].Identity.ID)
	if err != nil {
		return out, err
	}
	if _, err := closer.Submit(ctx, "Close", r.ContractAddr); err != nil {
		return out, fmt.Errorf("ref10: close round %s: %w", r.ContractAddr, err)
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

// chainRoundPolicy is registered once at setup: the protocol parameters a
// voter must not be able to choose, plus the CA key that makes P_C checkable.
//
// These left the per-round payload when Init did. A voter that could name its
// own threshold would authorize alone, and one that could name its own
// committee size would shrink N_auth until it held a majority — so they live in
// contract state that voting never writes.
type chainRoundPolicy struct {
	CommitteeSize int    `json:"committee_size"`
	Threshold     int    `json:"threshold"`
	CAPubX        string `json:"ca_pub_x"`
	CAPubY        string `json:"ca_pub_y"`
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

	// SigE, SigS carry the CA's signature. Dropping them here is what made the
	// contract accept an unsigned certificate — the CA signed P_C and the
	// encoder discarded the signature at the boundary.
	SigE string `json:"sig_e"`
	SigS string `json:"sig_s"`
}

// chainBallot is one vote together with the request it votes on. The request
// rides with the ballot because no stored round holds it any more.
type chainBallot struct {
	NodeID     string          `json:"node_id"`
	Approve    bool            `json:"approve"`
	RequestID  string          `json:"request_id"`
	TargetTxID string          `json:"target_tx_id"`
	Cert       chainPolicyCert `json:"cert"`
	E          string          `json:"e"`
	S          string          `json:"s"`
}

type chainNode struct {
	ID         string            `json:"id"`
	Attributes map[string]string `json:"attributes"`
	PubX       string            `json:"pub_x"`
	PubY       string            `json:"pub_y"`
}

func encodeRoundPolicy(committeeSize, threshold int, ca *certAuthority) (string, error) {
	if ca == nil {
		return "", fmt.Errorf("ref10: no CA, so the contract could not verify any certificate")
	}
	b, err := json.Marshal(chainRoundPolicy{
		CommitteeSize: committeeSize,
		Threshold:     threshold,
		CAPubX:        hex.EncodeToString(ca.key.X.Bytes()),
		CAPubY:        hex.EncodeToString(ca.key.Y.Bytes()),
	})
	if err != nil {
		return "", fmt.Errorf("ref10: encode round policy: %w", err)
	}
	return string(b), nil
}

func encodeCert(c *policyCert) chainPolicyCert {
	out := chainPolicyCert{
		TargetTxID:     c.TargetTxID,
		RequesterID:    c.RequesterID,
		RequesterKnown: c.RequesterKnown,
		Redactable:     c.Redactable,
		Satisfies:      c.Satisfies,
		PolicyID:       c.PolicyID,
		PolicyVer:      c.PolicyVer,
		Attributes:     c.Attributes,
	}
	if c.Sig != nil && c.Sig.E != nil && c.Sig.S != nil {
		out.SigE = hex.EncodeToString(c.Sig.E.Bytes())
		out.SigS = hex.EncodeToString(c.Sig.S.Bytes())
	}
	return out
}

func encodeBallot(nodeID string, approve bool, r *voteRound, sig *crypto.SchnorrSignature) (string, error) {
	if sig == nil || sig.E == nil || sig.S == nil {
		return "", fmt.Errorf("ref10: ballot for %s has no signature", nodeID)
	}
	if r.Cert == nil {
		return "", fmt.Errorf("ref10: ballot for %s carries no certificate; the "+
			"contract would have nothing to verify against P_C", nodeID)
	}
	b, err := json.Marshal(chainBallot{
		NodeID:     nodeID,
		Approve:    approve,
		RequestID:  r.RequestID,
		TargetTxID: r.Cert.TargetTxID,
		Cert:       encodeCert(r.Cert),
		E:          hex.EncodeToString(sig.E.Bytes()),
		S:          hex.EncodeToString(sig.S.Bytes()),
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
