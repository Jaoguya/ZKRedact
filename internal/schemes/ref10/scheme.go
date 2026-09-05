// Package ref10 re-implements the EMT baseline.
//
// Paper: Wu, Wang, Zhang, Feng, "EMT: Extended Merkle Tree Structure for
// Inserted Data Redaction in Permissioned Blockchain," IEEE TNSE 2025.
// Spec: docs/baselines/ref10-emt.md
//
// Primary competitor for Exp 1 — the only baseline with a genuine per-request
// authorization protocol, and the only one already on Fabric, which minimises
// platform-induced difference.
//
// Algorithm mapping:
//
//	Algorithm 1 EMT Verification       -> Audit
//	Algorithm 2 Redaction Request      -> Authorize (CA validation, policy)
//	Algorithm 3 Smart Contract         -> Authorize (committee, voting)
//	Algorithm 4 Redaction Voting       -> Authorize (Schnorr signatures)
//	Algorithm 5 Local Redaction        -> Redact
package ref10

import (
	"context"
	"crypto/elliptic"
	"errors"
	"fmt"
	"sync"
	"time"

	"zkredact/pkg/ch"
	"zkredact/pkg/crypto"
	"zkredact/pkg/merkle"
	"zkredact/pkg/scheme"
)

// Scheme is the EMT baseline.
type Scheme struct {
	mu    sync.RWMutex
	ready bool

	params scheme.SetupParams

	// committeeSize and voteThreshold come from an explicit fault assumption:
	// tolerate f Byzantine members, requiring 3f+1 members and 2f+1 approvals.
	// Undersizing these would make the primary Exp 1 competitor artificially
	// fast — the easiest objection for a reviewer to raise.
	committeeSize int
	voteThreshold int

	// voteWindowMS is a TIMEOUT, not a fixed wait. The round closes the moment
	// the threshold is reached. Waiting the full window instead would inflate
	// Ref[10]'s latency by a constant we chose rather than measuring its
	// protocol. See docs/baselines/ref10-emt.md §2.
	voteWindowMS int

	// attributePolicy is A_r, the paper's own default {S OR R OR V}. Anything
	// stricter would shrink the eligible committee and tilt Exp 1 our way.
	attributePolicy string

	// blockSize is the shared Fabric block-cutting parameter. Held constant
	// across all four systems, so it comes from environment.network rather than
	// from this baseline's own block.
	blockSize int

	curve elliptic.Curve

	ledger   *ledger
	registry *registry
	ca       *certAuthority

	// transport carries votes. Its name is recorded in every Authorization so a
	// result can never be read as network-measured when it was not.
	transport transport

	// policies indexes the shared corpus's policies by ID.
	policies map[string]scheme.Policy

	// rounds holds the vote record for each authorized request, which is what
	// the redaction contract con_k would retain. Redact re-verifies Sigma from
	// here, exactly as Algorithm 5 line 4 requires.
	roundsMu sync.Mutex
	rounds   map[string]*roundRecord
}

// roundRecord is the contract's retained record of one completed vote round.
type roundRecord struct {
	ContractAddr string
	Approved     []ballot
}

func New() *Scheme { return &Scheme{} }

func (s *Scheme) Name() string { return "ref10_emt" }

func (s *Scheme) Capabilities() scheme.Capabilities {
	return scheme.Capabilities{
		PrivacyPreservingAuth:  false, // votes are attributable to identified nodes
		PolicyBound:            true,  // P_C constrains redactable transactions, partially
		DecentralizedAuth:      true,  // committee vote, no single authority
		ParallelVerification:   false, // voting rounds serialise
		BatchRedaction:         false, // per-request; this is the B_R=1 point
		PerTxProvenance:        false, // no per-transaction history index
		LedgerIndependentAudit: false, // locating redaction transactions scans
		StateFreshnessCheck:    false, // no execution-time revalidation
	}
}

func (s *Scheme) Setup(ctx context.Context, p scheme.SetupParams) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Refuse to run on a chameleon hash construction other than the one this
	// scheme's paper specifies. A substituted construction changes CryptoTime,
	// which Exp 2 reports as a headline metric, and would fail no other check.
	if err := ch.CheckRequired(s.Name()); err != nil {
		return fmt.Errorf("%s: %w", s.Name(), err)
	}

	if p.Dataset == nil {
		return fmt.Errorf("ref10: setup requires a dataset")
	}
	if p.SecurityBits <= 0 {
		return fmt.Errorf("ref10: setup requires a security level")
	}

	var err error
	if s.committeeSize, err = intParam(p.Params, "committee_size"); err != nil {
		return fmt.Errorf("ref10: %w", err)
	}
	if s.voteThreshold, err = intParam(p.Params, "vote_threshold"); err != nil {
		return fmt.Errorf("ref10: %w", err)
	}
	if s.voteWindowMS, err = intParam(p.Params, "vote_window_ms"); err != nil {
		return fmt.Errorf("ref10: %w", err)
	}
	if s.blockSize, err = intParam(p.Params, "block_max_transactions"); err != nil {
		return fmt.Errorf("ref10: %w", err)
	}
	if v, ok := p.Params["attribute_policy"].(string); ok {
		s.attributePolicy = v
	} else {
		return fmt.Errorf("ref10: missing parameter attribute_policy")
	}

	// Guard the fairness properties of the committee. A threshold that is not a
	// real majority would let two conflicting redactions both pass, and would
	// also make this baseline faster than its own design permits.
	if s.voteThreshold > s.committeeSize {
		return fmt.Errorf("ref10: threshold %d exceeds committee size %d",
			s.voteThreshold, s.committeeSize)
	}
	if s.voteThreshold <= s.committeeSize/2 {
		return fmt.Errorf("ref10: threshold %d is not a majority of %d",
			s.voteThreshold, s.committeeSize)
	}

	// The signature curve and hash are shared parameters, not this baseline's
	// own. Resolving them through pkg/crypto means the level enforced here is
	// the level the config validator checked.
	curveName, ok := p.Params["signature_curve"].(string)
	if !ok {
		return fmt.Errorf("ref10: missing parameter signature_curve")
	}
	if s.curve, err = crypto.SignatureCurve(curveName, p.SecurityBits); err != nil {
		return fmt.Errorf("ref10: %w", err)
	}
	hashName, ok := p.Params["hash"].(string)
	if !ok {
		return fmt.Errorf("ref10: missing parameter hash")
	}
	if err = crypto.RequireHash(hashName); err != nil {
		return fmt.Errorf("ref10: %w", err)
	}

	transportName, ok := p.Params["vote_transport"].(string)
	if !ok {
		return fmt.Errorf("ref10: missing parameter vote_transport")
	}
	if s.transport, err = newTransport(transportName); err != nil {
		return err
	}

	// Materialise the shared corpus into this scheme's own on-chain form. Not
	// timed: the four systems cannot share a ledger format.
	if s.ledger, err = newLedger(p.Dataset.Transactions, s.blockSize); err != nil {
		return err
	}
	if s.registry, err = newRegistry(p.Dataset.Identities, s.curve, p.Seed); err != nil {
		return err
	}
	if s.ca, err = newCertAuthority(p.Dataset.Identities, s.curve, p.Seed); err != nil {
		return err
	}

	// Fail now rather than per-request if the policy can never fill a committee.
	if _, err = s.registry.selectCommittee(contractAddress("setup-probe"), s.attributePolicy, s.committeeSize); err != nil {
		return err
	}

	s.policies = make(map[string]scheme.Policy, len(p.Dataset.Policies))
	for _, pol := range p.Dataset.Policies {
		s.policies[pol.ID] = pol
	}

	s.rounds = make(map[string]*roundRecord)
	s.params = p
	s.ready = true
	return nil
}

// Authorize runs Algorithms 2, 3 and 4: CA validation, committee selection,
// vote collection, and aggregate signature verification.
//
// Measured boundary: request admitted -> threshold reached and Sigma verified.
// Every step below is inside it, and none of it is cached across requests —
// each request instantiates its own contract con_k and therefore its own
// committee (Ref[10].md:384).
func (s *Scheme) Authorize(ctx context.Context, req *scheme.Request) (*scheme.Authorization, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("ref10: nil request")
	}

	auth := &scheme.Authorization{
		Request:      req,
		AuthorizedAt: time.Now(),
	}

	target, found := s.ledger.lookup(req.TargetTxID)
	if found {
		auth.TxVersion = target.Version
	}

	policy, hasPolicy := s.policies[req.PolicyID]
	if !hasPolicy {
		auth.Granted = false
		auth.Reason = fmt.Sprintf("policy %s is not registered", req.PolicyID)
		return auth, nil
	}
	auth.PolicyVersion = policy.Version

	// Algorithm 2: CA validation, producing msg = {P_C, sigma}.
	cert, err := s.ca.validate(req, target, policy, s.attributePolicy)
	if err != nil {
		return nil, err
	}

	// A policy that denies outright still costs the CA round trip, but no vote
	// round is opened — the contract has nothing to put to a committee. Denials
	// are outcomes Exp 1 counts, not errors.
	if !cert.Granted() {
		auth.Granted = false
		switch {
		case !found:
			auth.Reason = fmt.Sprintf("target %s is not in the ledger", req.TargetTxID)
		case !cert.RequesterKnown:
			auth.Reason = fmt.Sprintf("requester %s is not registered with the CA (V(n_i, C) failed)",
				req.RequesterID)
		case !cert.Redactable:
			auth.Reason = fmt.Sprintf("target %s is %s, outside T_rdbl (Eq. 6)",
				req.TargetTxID, target.Kind)
		default:
			auth.Reason = fmt.Sprintf("requester %s does not satisfy A_r = %q",
				req.RequesterID, s.attributePolicy)
		}
		return auth, nil
	}

	// Algorithm 3 init(): RS_SHA256(addr(con_k), N_all, A_r) -> N_auth (Eq. 7).
	addr := contractAddress(req.ID)
	committee, err := s.registry.selectCommittee(addr, s.attributePolicy, s.committeeSize)
	if err != nil {
		return nil, err
	}

	// Algorithms 3 vote() and 4: collect ballots, verify each, close on
	// threshold.
	approved, err := runVoteRound(ctx, s.transport, &voteRound{
		ContractAddr: addr,
		RequestID:    req.ID,
		Cert:         cert,
		CA:           s.ca,
		Members:      committee,
		Threshold:    s.voteThreshold,
		Window:       time.Duration(s.voteWindowMS) * time.Millisecond,
	})
	if err != nil {
		return nil, err
	}

	if len(approved) < s.voteThreshold {
		auth.Granted = false
		auth.Reason = fmt.Sprintf("%d of %d approvals, below threshold %d (committee %s)",
			len(approved), len(committee), s.voteThreshold, describeCommittee(committee))
		return auth, nil
	}

	// The contract verifies Sigma in full before emitting tx_rdt.
	if !verifySigma(addr, req.ID, approved, s.voteThreshold) {
		auth.Granted = false
		auth.Reason = "aggregate signature Sigma failed verification"
		return auth, nil
	}

	s.roundsMu.Lock()
	s.rounds[req.ID] = &roundRecord{ContractAddr: addr, Approved: approved}
	s.roundsMu.Unlock()

	auth.Granted = true
	auth.Evidence = sigmaBytes(approved)
	return auth, nil
}

// Redact runs Algorithm 5. This scheme has no batching, so the slice is
// processed one entry at a time — which is exactly what makes it the B_R=1
// reference point for Exp 2.
//
// Redaction consensus IS included, unlike the paper, which excluded it
// (Ref[10].md:466). Excluding it would hide the cost ZK-Redact amortises, which
// is the effect Exp 2 exists to measure.
func (s *Scheme) Redact(ctx context.Context, batch []*scheme.Authorization) (*scheme.RedactionResult, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	res := &scheme.RedactionResult{}
	start := time.Now()

	for _, a := range batch {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if a == nil || !a.Granted {
			res.Failed++
			continue
		}

		s.roundsMu.Lock()
		rec, ok := s.rounds[a.Request.ID]
		s.roundsMu.Unlock()
		if !ok {
			res.Failed++
			continue
		}

		// Cryptographic work: re-verify Sigma in full (Algorithm 5 line 4) and
		// recompute the affected hashes. There is no chameleon hash here — that
		// absence is the point of including this baseline in Exp 2.
		cryptoStart := time.Now()
		valid := verifySigma(rec.ContractAddr, a.Request.ID, rec.Approved, s.voteThreshold)
		res.CryptoTime += time.Since(cryptoStart)
		if !valid {
			res.Failed++
			continue
		}

		// Ledger work: locate the block, rewrite d_w, rebuild the block's EMT,
		// and append tx_rdt. Charged per request because there is no batch.
		ledgerStart := time.Now()
		rdt := &redactionTx{
			ID:         fmt.Sprintf("tx-rdt-%s", a.Request.ID),
			TargetTxID: a.Request.TargetTxID,
			PolicyID:   a.Request.PolicyID,
			FromVer:    a.TxVersion,
			ToVer:      a.TxVersion + 1,
			NewDigest:  merkle.HashLeaf(a.Request.NewContent),
			Evidence:   a.Evidence,
		}
		if prev, ok := s.ledger.lookup(a.Request.TargetTxID); ok {
			rdt.OldDigest = append([]byte(nil), prev.HW...)
		}
		if _, err := s.ledger.applyRedaction(rdt, a.Request.NewContent); err != nil {
			res.LedgerTime += time.Since(ledgerStart)
			res.Failed++
			continue
		}
		s.ledger.appendRedactionTx(rdt)
		res.LedgerTime += time.Since(ledgerStart)

		res.Succeeded++
	}

	res.Total = time.Since(start)
	return res, nil
}

// Audit reconstructs a transaction's redaction history by locating every
// redaction transaction referencing it, then verifying via Algorithm 1.
//
// There is no per-transaction provenance index in Ref[10], so the only way to
// answer is to walk the chain. BlocksTraversed reflects that honestly, and the
// emtTx.RedactedBy field is deliberately NOT consulted: it exists so the
// harness can build history of a known depth during untimed setup, and reading
// it here would hand this baseline an index its design does not have.
func (s *Scheme) Audit(ctx context.Context, q *scheme.AuditQuery) (*scheme.AuditResult, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	if q == nil {
		return nil, errors.New("ref10: nil audit query")
	}

	res := &scheme.AuditResult{Semantics: scheme.SemanticsFullScan}

	retrievalStart := time.Now()
	found, traversed, bytesRead := s.ledger.scanForRedactions(q.TargetTxID)
	res.RetrievalTime = time.Since(retrievalStart)
	res.BlocksTraversed = traversed
	res.EvidenceBytes = bytesRead

	res.History = make([]scheme.ProvenanceRecord, 0, len(found))
	for _, f := range found {
		res.History = append(res.History, f.Record)
	}

	// Algorithm 1 on the target, then on EVERY located redaction transaction.
	//
	// The measurement boundary is "all located redaction transactions verified"
	// (docs/baselines/ref10-emt.md §2), so verification cost must grow with
	// history depth. Verifying only the target would report depth-independent
	// verification for a scheme that has no mechanism providing it, and Exp 3's
	// second plot — ledger fixed, depth growing — would show Ref[10] flat
	// against ZK-Redact for no reason its design supports.
	verifyStart := time.Now()
	res.Verified = s.verifyEMT(q.TargetTxID) && s.verifyRedactionRecords(found)
	res.VerificationTime = time.Since(verifyStart)

	return res, nil
}

// verifyRedactionRecords re-verifies each located tx_rdt: its own EMT
// inclusion, and the committee signatures that authorised it.
//
// An auditor has only what the ledger stores, so Sigma is parsed back out of
// tx_rdt and each signer's key is resolved from the contract's registered
// committee (Algorithm 3 stores pk_j in con_k). Nothing here reads state that a
// real auditor would not hold.
func (s *Scheme) verifyRedactionRecords(found []foundRedaction) bool {
	for _, f := range found {
		if !s.verifyEMT(f.RdtTxID) {
			return false
		}

		requestID, ok := requestIDFromRedactionTx(f.RdtTxID)
		if !ok {
			return false
		}
		entries, err := parseSigma(f.Record.AuthEvidence)
		if err != nil {
			return false
		}

		msg := voteMessage(contractAddress(requestID), requestID, true)
		seen := make(map[string]bool, len(entries))
		valid := 0
		for _, e := range entries {
			if seen[e.NodeID] {
				return false // one node, one vote
			}
			seen[e.NodeID] = true

			m, known := s.registry.lookup(e.NodeID)
			if !known {
				return false // a vote from outside N_all
			}
			if !m.Key.SchnorrPublicKey.Verify(msg, e.Sig) {
				return false
			}
			valid++
		}
		if valid < s.voteThreshold {
			return false
		}
	}
	return true
}

// verifyEMT is Algorithm 1 for one transaction.
//
// Recomputes both branches from stored content, checks H_tx, and proves
// inclusion of the two leaves against the block root. A redaction that altered
// core data fails at the H_c comparison, which the fidelity checklist requires.
func (s *Scheme) verifyEMT(txID string) bool {
	s.ledger.mu.RLock()
	defer s.ledger.mu.RUnlock()

	loc, ok := s.ledger.txLoc[txID]
	if !ok {
		return false
	}
	b := s.ledger.blocks[loc.Block]
	tx := b.Txs[loc.Index]

	if !bytesEqual(merkle.HashLeaf(tx.Core), tx.HC) {
		return false
	}
	if !bytesEqual(merkle.HashLeaf(tx.Redactable), tx.HW) {
		return false
	}
	if !bytesEqual(hashTx(tx.HC, tx.HW), tx.HTx) {
		return false
	}

	// Leaves are interleaved per Eq. 4: H_c at 2i, H_w at 2i+1.
	root := b.tree.Root()
	for off, want := range [][]byte{tx.HC, tx.HW} {
		proof, err := b.tree.Proof(loc.Index*2 + off)
		if err != nil {
			return false
		}
		if !merkle.VerifyHash(root, want, proof) {
			return false
		}
	}
	return true
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (s *Scheme) Teardown(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ready = false
	return nil
}

func (s *Scheme) check() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.ready {
		return fmt.Errorf("ref10: Setup has not completed")
	}
	return nil
}

func intParam(m map[string]any, key string) (int, error) {
	v, ok := m[key]
	if !ok {
		return 0, fmt.Errorf("missing parameter %s", key)
	}
	switch n := v.(type) {
	case int:
		return n, nil
	case int64:
		return int(n), nil
	case float64:
		return int(n), nil
	default:
		return 0, fmt.Errorf("parameter %s has type %T, want a number", key, v)
	}
}
