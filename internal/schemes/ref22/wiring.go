package ref22

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"zkredact/pkg/accumulator"
	"zkredact/pkg/ch"
	"zkredact/pkg/crypto"
	"zkredact/pkg/scheme"
)

// build materialises the dataset into Ref[22]'s chain. Called from Setup and
// NOT timed: the four schemes cannot share a ledger format.
func (s *Scheme) build(p scheme.SetupParams) error {
	curve, err := crypto.SignatureCurve(s.chCurve, p.SecurityBits)
	if err != nil {
		return fmt.Errorf("ref22: %w", err)
	}

	// Both trapdoors are genuinely used: DoubleTrapdoorKeyGen produces the
	// key-exposure-free construction the paper specifies, and ch.CheckRequired
	// in Setup already refuses a single-trapdoor stand-in.
	key, err := ch.DoubleTrapdoorKeyGen(curve, rand.Reader)
	if err != nil {
		return fmt.Errorf("ref22: chameleon hash key generation: %w", err)
	}

	// The regulator holds phi(N), which is what Ref[22] specifies: §II-C states
	// that "since the deletion algorithm is costy without the knowledge of group
	// order, it is executed by the regulator with the RSA group order". Both
	// Modify (Algorithm 5) and Delete (Algorithm 7) take phi(N) as an input.
	//
	// No new trust is introduced. This scheme's regulator already holds the
	// double-trapdoor chameleon hash key above — it IS the redaction authority.
	// "Trapdoorless" constrains what VERIFIERS must trust, and they still need
	// nothing beyond N.
	//
	// Without it, Delete rebuilds the accumulator from the generator over every
	// surviving element: O(n) exponentiations rather than one. Delete is timed as
	// CryptoTime and is Ref[22]'s headline Exp 2 curve, so the fallback would
	// inflate that curve by a factor of n and make this baseline look far worse
	// than its design.
	modulus, groupOrder, err := accumulator.GenerateUntrustedWithOrder(s.accumulatorBits)
	if err != nil {
		return err
	}
	acc, err := accumulator.New(accumulator.Config{
		Bits: s.accumulatorBits, Modulus: modulus, GroupOrder: groupOrder,
	})
	if err != nil {
		return err
	}
	if !acc.HasGroupOrder() {
		return fmt.Errorf(
			"ref22: accumulator was built without the regulator's group order; " +
				"Delete would fall back to the O(n) rebuild that §II-C says this scheme does not use")
	}

	s.curve = curve
	s.ledger = newLedger(curve, key, acc)
	s.blockOf = make(map[string]uint64, len(p.Dataset.Transactions))

	// One block per source transaction. Ref[22] operates at block granularity,
	// so a transaction IS a block here; mapping several transactions into one
	// block would make its per-redaction cost depend on a packing factor no
	// other scheme has.
	for _, tx := range p.Dataset.Transactions {
		b, err := s.ledger.Append(tx.Core, tx.Redactable)
		if err != nil {
			return err
		}
		s.blockOf[tx.ID] = b.Seq
	}

	// Witnesses once, after the chain exists. See ledger.Finalize.
	if err := s.ledger.Finalize(); err != nil {
		return err
	}

	// The regulator holds the editing key. Ref[22] defines no per-request
	// authorization protocol, so this is key possession and nothing more — see
	// Authorize.
	s.regulatorKey = key
	return nil
}

// Authorize verifies regulator key possession.
//
// THIS IS DELIBERATELY CHEAP, and the cheapness is a finding rather than a
// handicap. Ref[22] defines no per-request authorization protocol; the regulator
// simply holds the editing key. Inventing a protocol to make the comparison look
// fairer would be fabricating a result, so the capability matrix carries the
// interpretation instead.
func (s *Scheme) Authorize(ctx context.Context, req *scheme.Request) (*scheme.Authorization, error) {
	if err := s.check(); err != nil {
		return nil, err
	}

	auth := &scheme.Authorization{Request: req, AuthorizedAt: time.Now()}

	seq, known := s.blockOf[req.TargetTxID]
	if !known {
		auth.Granted = false
		auth.Reason = fmt.Sprintf("target %s is not in the chain", req.TargetTxID)
		return auth, nil
	}

	// A real check that can fail: without the trapdoor no collision can be
	// produced, so the redaction is impossible.
	if !s.regulatorKey.HasTrapdoor() {
		auth.Granted = false
		auth.Reason = "caller does not hold the regulator editing key"
		return auth, nil
	}

	auth.Granted = true
	auth.TxVersion = s.versionOf(seq)
	auth.Evidence = s.regulatorKey.Public()[0].Bytes()
	return auth, nil
}

// Redact runs Modify (Algorithm 5) per authorized entry.
func (s *Scheme) Redact(ctx context.Context, batch []*scheme.Authorization) (*scheme.RedactionResult, error) {
	if err := s.check(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	res := &scheme.RedactionResult{}
	start := time.Now()

	for _, a := range batch {
		if a == nil || !a.Granted {
			res.Failed++
			continue
		}
		seq, known := s.blockOf[a.Request.TargetTxID]
		if !known {
			res.Failed++
			continue
		}

		// Freshness: a request authorized against an older version is stale.
		// Ref[22]'s largest-sequence-number rule forces adoption of the latest
		// version, so an edit against a superseded one must not apply.
		if a.TxVersion != s.versionOf(seq) {
			res.StaleExcluded++
			continue
		}

		// CH.Adapt plus the accumulator's Del/Add pair. All of it is
		// per-request cryptographic work: Ref[22] has no batching, so there is
		// no ledger cost to amortise and CryptoTime carries the whole redaction.
		cryptoStart := time.Now()
		if err := s.ledger.Modify(seq, a.Request.NewContent); err != nil {
			res.Failed++
			continue
		}
		res.CryptoTime += time.Since(cryptoStart)

		s.versions[seq]++
		res.Succeeded++
	}

	res.Total = time.Since(start)
	return res, nil
}

// DeleteSet runs Delete (Algorithm 7) over a set of block positions.
func (s *Scheme) DeleteSet(ctx context.Context, positions []int, consecutive bool) (*scheme.RedactionResult, error) {
	if err := s.check(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	seqs := make([]uint64, 0, len(positions))
	for _, p := range positions {
		if p < 0 {
			return nil, fmt.Errorf("ref22: negative block position %d", p)
		}
		seqs = append(seqs, uint64(p))
	}

	res := &scheme.RedactionResult{}
	start := time.Now()

	cryptoStart := time.Now()
	adaptations, err := s.ledger.Delete(seqs)
	res.CryptoTime = time.Since(cryptoStart)
	res.Total = time.Since(start)

	if err != nil {
		res.Failed = len(positions)
		return res, err
	}
	res.Succeeded = len(positions)

	// The adaptation count IS the cost model Exp 2 compares: one per consecutive
	// run, so a consecutive set of 8 costs one and a scattered set of 8 costs
	// eight. Recorded so the curve can be read against the structure that
	// produced it.
	res.BatchCommitment = []byte(fmt.Sprintf("adaptations=%d", adaptations))
	return res, nil
}

// Audit runs ValChain (Algorithm 9).
//
// A FULL SCAN, and that is the point: this is Exp 3's linear baseline. The
// result reports SemanticsLedgerIntegrity because Ref[22] verifies that the
// chain is untampered — it has no per-transaction redaction history to return,
// which is exactly the capability difference Exp 3 measures.
func (s *Scheme) Audit(ctx context.Context, q *scheme.AuditQuery) (*scheme.AuditResult, error) {
	if err := s.check(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	start := time.Now()
	visited, err := s.ledger.ValChain()
	elapsed := time.Since(start)

	return &scheme.AuditResult{
		Semantics:        scheme.SemanticsLedgerIntegrity,
		Verified:         err == nil,
		BlocksTraversed:  visited,
		VerificationTime: elapsed,
	}, nil
}

// versionOf reports how many times a block has been modified.
func (s *Scheme) versionOf(seq uint64) uint64 {
	if s.versions == nil {
		return 0
	}
	return s.versions[seq]
}
