package ref10

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"strings"
	"time"

	"zkredact/pkg/crypto"
	"zkredact/pkg/scheme"
)

// Algorithm 2 (CA validation), Algorithm 3 (contract) and Algorithm 4 (voting).
//
// MEASUREMENT BOUNDARY (docs/baselines/ref10-emt.md §2). Exp 1 starts when the
// request is admitted and stops when the threshold is reached and Sigma is
// verified. Everything in this file is inside that boundary, which is why none
// of it may be precomputed, cached across requests, or short-circuited.

// certAuthority is the CA of Algorithm 2.
//
// It validates the requester V(n_i, C), constructs the policy P_C, and signs
// it. The signature is what lets committee members trust P_C without each
// re-querying the CA, and verifying it is part of every member's per-request
// work.
type certAuthority struct {
	key      *crypto.SchnorrPrivateKey
	registry map[string]scheme.Identity
}

func newCertAuthority(identities []scheme.Identity, curve elliptic.Curve, seed int64) (*certAuthority, error) {
	src := rand.New(rand.NewSource(seed + 0x2020))
	k, err := crypto.SchnorrKeyGen(curve, src)
	if err != nil {
		return nil, fmt.Errorf("ref10: CA key: %w", err)
	}
	reg := make(map[string]scheme.Identity, len(identities))
	for _, id := range identities {
		reg[id.ID] = id
	}
	return &certAuthority{key: k, registry: reg}, nil
}

// policyCert is msg = {P_C, sigma} from Algorithm 2.
type policyCert struct {
	// P_C = {tx_id in T_rdbl, n_i |= A_r}  (Eq. 5)
	TargetTxID  string
	RequesterID string

	// RequesterKnown is V(n_i, C): the CA recognises this requester at all.
	//
	// Kept separate from the two Eq. 5 conditions deliberately. Folding an
	// unknown requester into Redactable would make the certificate assert
	// something false about the LEDGER — T_rdbl is a property of the
	// transaction, not of whoever asked — and a committee member re-deriving
	// its decision from P_C would be reasoning from that false claim.
	RequesterKnown bool

	Redactable bool // tx_id in T_rdbl, per Eq. 6
	Satisfies  bool // n_i |= A_r
	PolicyID   string
	PolicyVer  uint64
	Attributes string // A_r as evaluated, recorded so a vote can re-check it

	Sig *crypto.SchnorrSignature
}

// Granted reports whether P_C permits the redaction at all.
func (p *policyCert) Granted() bool { return p.RequesterKnown && p.Redactable && p.Satisfies }

// bytes serialises P_C for signing and verification. Deterministic: two nodes
// must derive byte-identical input or the signature check becomes a coin flip.
func (p *policyCert) bytes() []byte {
	var b []byte
	b = append(b, p.TargetTxID...)
	b = append(b, 0x1f)
	b = append(b, p.RequesterID...)
	b = append(b, 0x1f)
	b = append(b, p.PolicyID...)
	b = append(b, 0x1f)
	b = append(b, p.Attributes...)
	b = append(b, 0x1f)
	var ver [8]byte
	binary.BigEndian.PutUint64(ver[:], p.PolicyVer)
	b = append(b, ver[:]...)
	for _, flag := range []bool{p.RequesterKnown, p.Redactable, p.Satisfies} {
		if flag {
			b = append(b, 1)
		} else {
			b = append(b, 0)
		}
	}
	return b
}

// validate runs Algorithm 2: verify the requester, evaluate Eq. 5 and Eq. 6,
// and sign the resulting policy.
func (ca *certAuthority) validate(
	req *scheme.Request,
	target *emtTx,
	policy scheme.Policy,
	attributePolicy string,
) (*policyCert, error) {
	// T_rdbl = T_all \ (T_gen U T_rdt U T_con)  (Eq. 6). Evaluated for every
	// request, including one from an unknown requester: it is a fact about the
	// ledger and does not depend on who is asking.
	redactable := target != nil && target.Kind == txNormal

	// V(n_i, C).
	identity, known := ca.registry[req.RequesterID]

	// n_i |= A_r. An unregistered requester has no attributes, so it satisfies
	// nothing — but that is recorded as a separate failure from the policy
	// evaluation, not merged into it.
	satisfies := false
	if known {
		var err error
		if satisfies, err = evalPolicy(attributePolicy, identity.Attributes); err != nil {
			return nil, err
		}
	}

	cert := &policyCert{
		TargetTxID:     req.TargetTxID,
		RequesterID:    req.RequesterID,
		RequesterKnown: known,
		Redactable:     redactable,
		Satisfies:      satisfies,
		PolicyID:       policy.ID,
		PolicyVer:      policy.Version,
		Attributes:     attributePolicy,
	}
	sig, err := ca.key.Sign(cert.bytes(), nil)
	if err != nil {
		return nil, fmt.Errorf("ref10: CA signature: %w", err)
	}
	cert.Sig = sig
	return cert, nil
}

// verifyCert is what each committee member runs at Algorithm 4 line 1.
func (ca *certAuthority) verifyCert(cert *policyCert) bool {
	if cert == nil || cert.Sig == nil {
		return false
	}
	return ca.key.SchnorrPublicKey.Verify(cert.bytes(), cert.Sig)
}

// -----------------------------------------------------------------------------
// Voting
// -----------------------------------------------------------------------------

// voteMessage is what an authorized node signs.
//
// It binds the decision to this specific request and contract instance, so a
// signature captured from one round cannot be replayed into another. Without
// the binding, one honest "yes" would authorise every subsequent redaction.
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

// ballot is one submitted vote: {yes/no, xi_j}.
type ballot struct {
	NodeID  string
	Approve bool
	Key     *crypto.SchnorrPublicKey
	Xi      *crypto.SchnorrSignature
}

// voteRound carries everything a round needs. Passed to the transport, which
// is responsible only for delivery — never for deciding.
type voteRound struct {
	ContractAddr string
	RequestID    string
	Cert         *policyCert
	CA           *certAuthority
	Members      []*member
	Threshold    int
	Window       time.Duration
}

// transport delivers a voting round to committee members and returns their
// ballots.
//
// WHY THIS IS AN INTERFACE. Ref[10]'s votes must cross the real network; that
// cost is what separates a committee protocol from a local trapdoor check, and
// it is the single largest component of its Exp 1 latency. The Fabric
// implementation is Task 3. Until it exists, the only implementation is
// in-process and is NAMED so — a run using it is not measuring Ref[10]'s
// authorization cost, and nothing in this package will pretend otherwise.
type transport interface {
	// Name identifies the transport in results. Recorded so no number can be
	// read as networked when it was not.
	Name() string

	// Collect delivers the round and returns ballots in arrival order.
	Collect(ctx context.Context, r *voteRound) ([]ballot, error)
}

// Transport names accepted in config.
const (
	transportInProcess = "in_process"
	transportFabric    = "fabric"
)

// localTransport runs Algorithm 4 in-process, with no network hop.
//
// The cryptography is real: every member verifies the CA signature, re-derives
// its own decision, and produces a genuine Schnorr signature. What is absent is
// the wire. Latency measured through this transport is a LOWER BOUND on
// Ref[10]'s true authorization cost and must not be published as its cost.
type localTransport struct{}

func (localTransport) Name() string { return transportInProcess }

func (localTransport) Collect(ctx context.Context, r *voteRound) ([]ballot, error) {
	out := make([]ballot, 0, len(r.Members))
	for _, m := range r.Members {
		if err := ctx.Err(); err != nil {
			return out, err
		}

		// Algorithm 4 line 1: verify {req, sigma} against P_C from the CA.
		// A member that cannot verify the CA's signature does not vote.
		if !r.CA.verifyCert(r.Cert) {
			continue
		}

		// Lines 3-5: decide. The decision is derived from the policy the member
		// just verified, not taken on trust from the requester. A member that
		// simply approved everything would make the threshold meaningless.
		approve := r.Cert.Granted()

		// Line 6: produce xi_j.
		msg := voteMessage(r.ContractAddr, r.RequestID, approve)
		xi, err := m.Key.Sign(msg, nil)
		if err != nil {
			return out, fmt.Errorf("ref10: vote signature for %s: %w", m.Identity.ID, err)
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

// newTransport resolves the configured transport.
//
// "fabric" without gateway settings is refused rather than silently downgraded:
// a config asking for network-measured votes must not quietly get in-process
// ones, because the resulting numbers would be a lower bound reported as a
// measurement.
func newTransport(name string, gw *GatewayConfig) (transport, error) {
	switch name {
	case transportInProcess:
		return localTransport{}, nil

	case transportFabric:
		if gw == nil {
			return nil, ErrGatewayUnconfigured
		}
		factory, err := newGatewayFactory(*gw)
		if err != nil {
			return nil, err
		}
		return newFabricTransport(factory), nil

	default:
		return nil, fmt.Errorf(
			"ref10: unknown vote_transport %q; want %q or %q",
			name, transportInProcess, transportFabric)
	}
}

// ErrVoteWindowExpired reports a round that timed out before reaching the
// threshold.
//
// config/experiment.yaml sets vote_window_ms generously precisely so this never
// fires; if it does, the run is invalid and must be discarded rather than
// recorded as a slow-but-valid result.
var ErrVoteWindowExpired = errors.New("ref10: vote window expired before threshold")

// runVoteRound is Algorithm 3's vote(): collect ballots, verify each signature,
// count approvals, and close on threshold.
//
// Returns the approving ballots that make up Sigma.
//
// CLOSING ON THRESHOLD is the deviation recorded in the spec §2: the round ends
// the moment enough approvals verify, rather than waiting out the window. It is
// the reading most favourable to Ref[10], and it is deliberate — the
// alternative would inflate its latency by a constant we chose.
func runVoteRound(ctx context.Context, t transport, r *voteRound) ([]ballot, error) {
	ctx, cancel := context.WithTimeout(ctx, r.Window)
	defer cancel()

	ballots, err := t.Collect(ctx, r)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, ErrVoteWindowExpired
		}
		return nil, err
	}

	approved := make([]ballot, 0, r.Threshold)
	for _, b := range ballots {
		if !b.Approve {
			continue
		}
		// Every counted vote is verified. An unverified ballot reaching the
		// tally is exactly Theorem 2's failure case.
		msg := voteMessage(r.ContractAddr, r.RequestID, true)
		if !b.Key.Verify(msg, b.Xi) {
			continue
		}
		approved = append(approved, b)
		if len(approved) >= r.Threshold {
			return approved, nil
		}
	}
	return approved, nil
}

// sigmaBytes serialises Sigma for storage in tx_rdt.
// The encoding must be PARSEABLE, not merely opaque bytes. An auditor
// re-verifying a redaction has only what the ledger stores, so Sigma has to be
// recoverable from tx_rdt alone — node identities and signature scalars
// included. Hex with explicit separators keeps the scalars unambiguous;
// concatenating raw big-endian bytes would not, since E and S are
// variable-length.
func sigmaBytes(approved []ballot) []byte {
	var b []byte
	for _, x := range approved {
		b = append(b, x.NodeID...)
		b = append(b, 0x1f)
		b = append(b, []byte(x.Xi.E.Text(16))...)
		b = append(b, 0x1f)
		b = append(b, []byte(x.Xi.S.Text(16))...)
		b = append(b, 0x1e)
	}
	return b
}

// sigmaEntry is one recovered vote: who signed, and with what.
type sigmaEntry struct {
	NodeID string
	Sig    *crypto.SchnorrSignature
}

// parseSigma recovers the vote set from a stored tx_rdt.
//
// Used by Audit, which must verify every located redaction transaction
// (docs/baselines/ref10-emt.md §2). A malformed Sigma is an error, not an empty
// set: silently returning nothing would let a corrupted record verify as though
// it carried no votes to check.
func parseSigma(b []byte) ([]sigmaEntry, error) {
	if len(b) == 0 {
		return nil, errors.New("ref10: empty Sigma")
	}
	var out []sigmaEntry
	for _, rec := range bytes.Split(b, []byte{0x1e}) {
		if len(rec) == 0 {
			continue
		}
		parts := bytes.Split(rec, []byte{0x1f})
		if len(parts) != 3 {
			return nil, fmt.Errorf("ref10: malformed Sigma entry (%d fields, want 3)", len(parts))
		}
		e, ok := new(big.Int).SetString(string(parts[1]), 16)
		if !ok {
			return nil, errors.New("ref10: malformed Sigma challenge scalar")
		}
		sc, ok := new(big.Int).SetString(string(parts[2]), 16)
		if !ok {
			return nil, errors.New("ref10: malformed Sigma response scalar")
		}
		out = append(out, sigmaEntry{
			NodeID: string(parts[0]),
			Sig:    &crypto.SchnorrSignature{E: e, S: sc},
		})
	}
	if len(out) == 0 {
		return nil, errors.New("ref10: Sigma contains no votes")
	}
	return out, nil
}

// requestIDFromRedactionTx recovers the request a tx_rdt authorised.
//
// The contract address is derived from it, and the address is half of what the
// vote signatures commit to — so without this an auditor cannot reconstruct the
// message the committee actually signed.
func requestIDFromRedactionTx(rdtID string) (string, bool) {
	const prefix = "tx-rdt-"
	if !strings.HasPrefix(rdtID, prefix) {
		return "", false
	}
	return strings.TrimPrefix(rdtID, prefix), true
}

// verifySigma re-verifies a full vote set, as Algorithm 5 line 4 and Algorithm 1
// both require.
//
// Unlike the voting round, this verifies EVERY signature with no early exit —
// crypto.VerifyVotes is deliberately linear. A verifier that stopped at the
// threshold would accept a Sigma padded with invalid signatures.
func verifySigma(contractAddr, requestID string, approved []ballot, threshold int) bool {
	if len(approved) < threshold {
		return false
	}
	msg := voteMessage(contractAddr, requestID, true)

	votes := make([]crypto.Vote, 0, len(approved))
	seen := make(map[string]bool, len(approved))
	for _, b := range approved {
		// One node, one vote. Without this, a single member's signature
		// repeated threshold times would satisfy the count.
		if seen[b.NodeID] {
			return false
		}
		seen[b.NodeID] = true
		votes = append(votes, crypto.Vote{Key: b.Key, Signature: b.Xi})
	}
	return crypto.VerifyVotes(msg, votes) == len(approved)
}

// describeCommittee renders committee membership for a denial reason, so a
// rejected request says which check failed rather than merely that one did.
func describeCommittee(ms []*member) string {
	ids := make([]string, 0, len(ms))
	for _, m := range ms {
		ids = append(ids, m.Identity.ID)
	}
	return strings.Join(ids, ",")
}
