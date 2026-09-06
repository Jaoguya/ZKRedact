package zkredact

import (
	"context"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"sort"
	"time"

	"zkredact/internal/gateway"
	"zkredact/internal/pai"
	"zkredact/internal/redactor"
	"zkredact/pkg/ch"
	"zkredact/pkg/crypto"
	"zkredact/pkg/scheme"
	"zkredact/pkg/zk"
)

// buildRedaction wires Phases 4, 5 and 6 during Setup: the chameleon-hash
// trapdoor, the ledger, the provenance index, the batch executor, and the
// auditor registry.
//
// Called after the policies and the credential registry exist, because the
// executor's freshness check reads registered policy versions and the ledger's
// genesis digests seed the index.
//
// UNTIMED, like the rest of Setup. Materialising a million-transaction corpus
// into chameleon-hashed ledger entries is real work, but every scheme performs
// the equivalent ingestion and docs/experiments.md excludes all of it.
func (s *Scheme) buildRedaction(p scheme.SetupParams) error {
	curve, err := crypto.SignatureCurve(s.signatureCurve, p.SecurityBits)
	if err != nil {
		return fmt.Errorf("zkredact: %w", err)
	}

	// Phase 1 Step 3: (pk_ch, tk_ch) <- CH.KeyGen(1^lambda). The trapdoor is
	// held by the trusted redaction component and used only for authorized
	// adaptation; nothing outside this scheme is given a reference to it.
	//
	// ch.CheckRequired has already refused a construction other than the one
	// the scheme's paper admits — a substituted one would change the per-request
	// CryptoTime that Exp 2 reports as its headline.
	chKey, err := ch.KeyGen(curve, rand.Reader)
	if err != nil {
		return fmt.Errorf("zkredact: chameleon-hash keygen: %w", err)
	}
	s.chKey = chKey

	ledger, err := redactor.NewLedger(curve, chKey, s.blockTx, p.Dataset.Transactions)
	if err != nil {
		return fmt.Errorf("zkredact: %w", err)
	}
	s.ledger = ledger

	// Phase 1 Step 5: initialise the PAI over every indexed transaction and
	// anchor R_PAI^(0).
	index, err := pai.NewIndex(ledger.TxIDs(), ledger.InitialDigest)
	if err != nil {
		return fmt.Errorf("zkredact: %w", err)
	}
	s.index = index

	exec, err := redactor.NewExecutor(ledger, index, func(policyID string) (uint64, bool) {
		pol, ok := s.policies[policyID]
		if !ok {
			return 0, false
		}
		return pol.Version, true
	})
	if err != nil {
		return fmt.Errorf("zkredact: %w", err)
	}
	s.exec = exec

	return s.buildAuditors(curve)
}

// buildAuditors is Phase 1 Step 1's auditor half: each AU_a registers
// (AID_a, pk_a, Pi_a^audit).
//
// SCOPES ARE NOT ALL THE SAME, deliberately. auditor-0 holds an unrestricted
// scope because Exp 3 measures a PERMITTED query — a denied one would time the
// rejection path instead. Every other auditor is scoped to a single policy, so
// AuditAuth has inputs it must refuse. A registry where the check could never
// fail would be a check in name only, and TestAuditRejectsOutOfScopeAuditor is
// what proves this one can.
func (s *Scheme) buildAuditors(curve elliptic.Curve) error {
	if s.auditorCount < 1 {
		return fmt.Errorf("zkredact: auditor_count must be >= 1, got %d", s.auditorCount)
	}

	policyIDs := make([]string, 0, len(s.policies))
	for id := range s.policies {
		policyIDs = append(policyIDs, id)
	}
	sort.Strings(policyIDs) // deterministic scopes from a deterministic seed

	auditors := make([]pai.Auditor, 0, s.auditorCount)
	keys := make(map[string]*crypto.SchnorrPrivateKey, s.auditorCount)

	for i := 0; i < s.auditorCount; i++ {
		id := auditorID(i)
		sk, err := crypto.SchnorrKeyGen(curve, rand.Reader)
		if err != nil {
			return fmt.Errorf("zkredact: auditor key generation for %s: %w", id, err)
		}
		keys[id] = sk

		policy := &pai.AuditPolicy{}
		if i == 0 {
			policy.AllPolicies = true
		} else {
			policy.PolicyIDs = map[string]struct{}{
				policyIDs[(i-1)%len(policyIDs)]: {},
			}
		}
		auditors = append(auditors, pai.Auditor{ID: id, Key: &sk.SchnorrPublicKey, Policy: policy})
	}

	reg, err := pai.NewAuditorRegistry(auditors, s.freshnessWindow, time.Now)
	if err != nil {
		return fmt.Errorf("zkredact: %w", err)
	}
	s.auditors = reg
	s.auditorKeys = keys
	return nil
}

func auditorID(i int) string { return fmt.Sprintf("auditor-%d", i) }

// Redact implements Phase 4 and the record generation of Phase 5.
//
// The cost split reported in RedactionResult is the point of Exp 2: CH.Adapt is
// per-request and cannot be amortised, while the batch root, the record root,
// the PAI update, the anchor and the ledger write are amortised across the
// batch. Total is measured across the whole call, so the two components can be
// checked against it rather than assumed to sum to it.
func (s *Scheme) Redact(ctx context.Context, batch []*scheme.Authorization) (*scheme.RedactionResult, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	if len(batch) == 0 {
		return &scheme.RedactionResult{}, nil
	}

	s.mu.RLock()
	exec, gw := s.exec, s.gw
	s.mu.RUnlock()

	start := time.Now()
	res := &scheme.RedactionResult{}

	items := make([]*redactor.Item, 0, len(batch))
	for _, a := range batch {
		it, err := s.itemFor(a)
		if err != nil {
			// A malformed or ungranted authorization is a failure of this
			// request, not of the round.
			res.Failed++
			continue
		}
		items = append(items, it)
	}

	if len(items) > 0 {
		out, err := exec.Run(ctx, items)
		if err != nil {
			return nil, fmt.Errorf("zkredact: %w", err)
		}
		res.Succeeded = out.Succeeded
		res.StaleExcluded = out.StaleExcluded
		res.Failed += out.Failed
		res.CryptoTime = out.CryptoTime
		res.LedgerTime = out.LedgerTime
		res.BatchCommitment = out.BatchCommitment

		// The gateway's view of ledger state must follow the ledger, or the
		// next request against a redacted transaction would be admitted at a
		// version that no longer exists and excluded later as stale — which
		// would read as a batching cost rather than as unsynchronised state.
		if gw != nil {
			for _, it := range items {
				if v, ok := s.ledger.Version(it.TxID); ok {
					gw.AdvanceTx(it.TxID, v)
				}
			}
		}
	}

	res.Total = time.Since(start)
	return res, nil
}

// itemFor converts an Authorization into what Phase 4 executes.
//
// The statement and proof are taken from the PREPARED requester material rather
// than re-derived, because they are what the authorization was actually granted
// against. Rebuilding the statement here would silently paper over a mismatch
// between what was proved and what is about to be executed — exactly the
// binding Phase 6 Step 4 later checks.
func (s *Scheme) itemFor(a *scheme.Authorization) (*redactor.Item, error) {
	if a == nil || a.Request == nil || !a.Granted {
		return nil, fmt.Errorf("zkredact: authorization is absent or not granted")
	}

	s.mu.RLock()
	pre, ok := s.prepared[a.Request.ID]
	s.mu.RUnlock()
	if !ok || pre == nil || pre.query == nil {
		return nil, fmt.Errorf(
			"zkredact: no prepared material for granted request %s", a.Request.ID)
	}

	did := didFor(pre.query.Statement, a.Request)
	if len(a.Evidence) == 0 {
		return nil, fmt.Errorf("zkredact: authorization for %s carries no proof", a.Request.ID)
	}

	return &redactor.Item{
		TxID:          a.Request.TargetTxID,
		NewContent:    a.Request.NewContent,
		PolicyID:      a.Request.PolicyID,
		PolicyVersion: a.PolicyVersion,
		TxVersion:     a.TxVersion,
		DID:           did,
		Statement:     pre.query.Statement,
		Proof:         a.Evidence,
		AuthorizedAt:  a.AuthorizedAt,
	}, nil
}

// didFor recomputes DID_i exactly as the gateway did in Phase 2 Step 3.
//
// Recomputed rather than carried through the Authorization, because
// scheme.Authorization is the SHARED cross-scheme type and a ZK-Redact-specific
// identifier has no place in it. The inputs are all fields of the request and
// the statement, so the two derivations cannot drift without the gateway's
// deduplication and the provenance record disagreeing — which the Phase 6
// evidence check would then report.
func didFor(st *zk.Statement, req *scheme.Request) []byte {
	return gateway.DedupID(req.TargetTxID, st.TxVersion, st.Loc, req.NewContent, req.PolicyID)
}
