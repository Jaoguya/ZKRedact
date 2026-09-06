package ref13

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

	"zkredact/pkg/ch"
	"zkredact/pkg/crypto"
	"zkredact/pkg/scheme"
	"zkredact/pkg/vc"
)

// block is one ledger entry: the chameleon-hashed content, plus what the BAT
// commits to.
type block struct {
	seq int

	// core is the immutable portion; redactable is the part CH.Adapt replaces.
	core       []byte
	redactable []byte

	// prevHash is h_{i-1}, the context the chameleon hash is bound to.
	prevHash []byte

	// digest is m_i, the value the BAT commits to.
	digest []byte

	// randomness is (r, Y) — the ephemeral verification string. Redaction
	// replaces it with a collision rather than changing the hash.
	randomness ch.EphemeralRandomness
	value      *ch.Value
}

// build materialises the ledger and its BAT. Not timed — every scheme ingests
// the shared dataset into its own representation before measurement.
func (s *Scheme) build(p scheme.SetupParams) error {
	curve, err := crypto.SignatureCurve(s.chCurve, p.SecurityBits)
	if err != nil {
		return fmt.Errorf("ref13: %w", err)
	}

	// Ephemeral-trapdoor CH is what Ref[13] specifies, and ch.CheckRequired in
	// Setup already refuses a substitute. The ephemeral key per redaction is
	// the construction's whole point: a collision exposes the ephemeral
	// trapdoor, never the long-term one.
	key, err := ch.EphemeralKeyGen(curve, rand.Reader)
	if err != nil {
		return fmt.Errorf("ref13: chameleon hash key generation: %w", err)
	}

	// N = q+1 is derived, never configured; NewBAT re-checks it against the
	// commitment parameters so the two cannot disagree.
	params, err := vc.Setup(s.vectorDimension)
	if err != nil {
		return fmt.Errorf("ref13: vector commitment setup: %w", err)
	}

	// The master secret seeds the child placeholders a node commits to before
	// its children exist. Derived from the run seed so a run is reproducible.
	secret := sha256.Sum256([]byte(fmt.Sprintf("ref13/master/%d", p.Seed)))

	bat, err := NewBAT(s.arityQ, params, secret[:])
	if err != nil {
		return err
	}

	s.curve = curve
	s.key = key
	s.vcParams = params
	s.bat = bat
	s.blocks = make([]*block, 0, len(p.Dataset.Transactions)+1)
	s.blockOf = make(map[string]int, len(p.Dataset.Transactions))

	// One block per source transaction, as Ref[22] does, so neither baseline's
	// per-redaction cost depends on a packing factor the other does not have.
	// Block indices start at 1: node 0 is the BAT root, which holds no block.
	for i, tx := range p.Dataset.Transactions {
		seq := i + 1
		b, err := s.appendBlock(seq, tx.Core, tx.Redactable)
		if err != nil {
			return err
		}
		s.blocks = append(s.blocks, b)
		s.blockOf[tx.ID] = seq
	}
	return nil
}

// appendBlock chameleon-hashes the content and binds it into the BAT.
func (s *Scheme) appendBlock(seq int, core, redactable []byte) (*block, error) {
	blockCtx := blockContext(seq, s.prevHash)
	m := blockDigest(core, redactable)

	// r is sampled per block. The ephemeral point in force is recorded with it,
	// because a verifier holding only X needs to know which Y was used — that is
	// why EphemeralRandomness carries the point rather than just the scalar.
	r, err := rand.Int(rand.Reader, s.curve.Params().N)
	if err != nil {
		return nil, fmt.Errorf("ref13: sample randomness for block %d: %w", seq, err)
	}
	if r.Sign() == 0 {
		r = big.NewInt(1)
	}

	// The chameleon hash covers m_i, per Eq. 1.
	value, err := s.key.Hash(blockCtx, m, r)
	if err != nil {
		return nil, fmt.Errorf("ref13: hash block %d: %w", seq, err)
	}
	pub := s.key.Public()
	rnd := ch.EphemeralRandomness{R: r, Yx: pub[2], Yy: pub[3]}

	b := &block{
		seq: seq, core: core, redactable: redactable,
		prevHash: append([]byte(nil), s.prevHash...),
		digest:   m, randomness: rnd, value: value,
	}
	if err := s.bat.Bind(seq, scalarOf(m)); err != nil {
		return nil, err
	}
	s.prevHash = chainHash(value)
	return b, nil
}

// blockContext is h_{i-1}, the previous block's hash. Eq. 1 binds the chameleon
// hash to it, which is what stops a collision being replayed onto another block.
func blockContext(seq int, prevHash []byte) []byte {
	h := sha256.New()
	h.Write([]byte("ref13/block"))
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], uint64(seq))
	h.Write(idx[:])
	h.Write(prevHash)
	return h.Sum(nil)
}

// blockDigest is m_i: the Merkle root over the block's transactions (§2.2).
//
// One transaction per block here, as for Ref[22], so the root is the digest of
// that transaction's content. Both halves are covered — a redaction replaces the
// redactable part, and the immutable part must still be bound or it could be
// swapped freely.
func blockDigest(core, redactable []byte) []byte {
	h := sha256.New()
	h.Write([]byte("ref13/block/m"))
	writeChunk(h, core)
	writeChunk(h, redactable)
	return h.Sum(nil)
}

// writeChunk length-prefixes, so (core, redactable) cannot be re-split to give
// the same digest from different content.
func writeChunk(h io.Writer, b []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(b)))
	_, _ = h.Write(n[:])
	_, _ = h.Write(b)
}

// chainHash is h_i = H(ch_i, ctr_i). The counter is fixed at zero: this harness
// runs no proof-of-work, and Ref[10] is the baseline that pays for consensus.
func chainHash(v *ch.Value) []byte {
	h := sha256.New()
	h.Write([]byte("ref13/chain"))
	h.Write(v.X.Bytes())
	h.Write(v.Y.Bytes())
	return h.Sum(nil)
}

// scalarOf maps m_i into the commitment's scalar field.
//
// THE BAT COMMITS TO m_i, THE CONTENT — not to the chameleon hash. The two do
// different jobs, and confusing them breaks the scheme in opposite directions:
//
//   - ch_i is INVARIANT under a collision, which preserves h_i = H(ch_i, ctr_i)
//     and lets the chain survive a redaction without re-mining.
//   - m_i CHANGES with the content, which is what forces Algorithm 1's path
//     update — the cost Exp 2 measures, and the reason the BAT exists at all.
//
// Committing the chameleon hash here instead leaves the root unmoved by every
// redaction, so a light node cannot tell redacted data from stale data. That is
// exactly the bug this file had, caught by TestRedactionIsVisibleInTheAudit.
func scalarOf(digest []byte) fr.Element {
	var out fr.Element
	out.SetBigInt(new(big.Int).SetBytes(digest))
	return out
}

// Authorize verifies trapdoor possession.
//
// DELIBERATELY CHEAP, and the cheapness is the finding. Ref[13] defines no
// per-request authorization protocol: redaction authority rests with the system
// manager who holds the trapdoor. Synthesising a richer protocol to make Exp 1
// look fairer would be fabricating a result, so the capability matrix carries
// the interpretation instead. Structured to match Ref[22]'s check, since the two
// schemes make the same claim and an asymmetry here would be ours, not theirs.
func (s *Scheme) Authorize(ctx context.Context, req *scheme.Request) (*scheme.Authorization, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	auth := &scheme.Authorization{Request: req, AuthorizedAt: time.Now()}

	seq, known := s.blockOf[req.TargetTxID]
	if !known {
		auth.Granted = false
		auth.Reason = fmt.Sprintf("target %s is not in the chain", req.TargetTxID)
		return auth, nil
	}

	// A real check that can fail: without the trapdoor no collision exists, so
	// the redaction is impossible.
	if !s.key.HasTrapdoor() {
		auth.Granted = false
		auth.Reason = "caller does not hold the system manager's trapdoor"
		return auth, nil
	}

	auth.Granted = true
	auth.TxVersion = uint64(s.versions[seq])
	auth.Evidence = s.key.Public()[0].Bytes()
	return auth, nil
}

// Redact computes a CH collision per entry and updates the BAT path from each
// redacted block to the root.
//
// Delayed redaction (§4.1) is deliberately NOT implemented: the paper proposes
// it but specifies no batch-formation policy, wait bound or conflict handling,
// and never measures it. Building it would mean inventing those and then
// benchmarking our own design under Ref[13]'s name. So this is per-request by
// construction, and contributes the B_R = 1 point.
func (s *Scheme) Redact(ctx context.Context, batch []*scheme.Authorization) (*scheme.RedactionResult, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	start := time.Now()
	res := &scheme.RedactionResult{}

	for _, auth := range batch {
		if auth == nil || auth.Request == nil || !auth.Granted {
			res.Failed++
			continue
		}
		seq, known := s.blockOf[auth.Request.TargetTxID]
		if !known {
			res.Failed++
			continue
		}
		b := s.blocks[seq-1]

		if uint64(s.versions[seq]) != auth.TxVersion {
			res.StaleExcluded++
			continue
		}

		// --- CryptoTime: the collision. Per request, and the floor batching
		// cannot go below.
		cryptoStart := time.Now()
		blockCtx := blockContext(seq, b.prevHash)
		newDigest := blockDigest(b.core, auth.Request.NewContent)
		newRnd, err := s.key.EphemeralAdapt(blockCtx, b.digest, b.randomness, newDigest)
		if err != nil {
			res.Failed++
			continue
		}
		res.CryptoTime += time.Since(cryptoStart)

		// --- LedgerTime: the path update, which is Ref[13]'s real redaction
		// cost and the reason the BAT exists.
		ledgerStart := time.Now()

		// ch_i is unchanged — that is what the collision buys, and it is why
		// h_i and every later block survive untouched. m_i DOES change, and
		// updating the path commitments for it is Algorithm 1: the real
		// redaction cost, and the reason the BAT exists.
		b.redactable = append([]byte(nil), auth.Request.NewContent...)
		b.digest = newDigest
		b.randomness = newRnd
		s.versions[seq]++

		if err := s.bat.Bind(seq, scalarOf(newDigest)); err != nil {
			return nil, err
		}
		res.LedgerTime += time.Since(ledgerStart)

		res.Succeeded++
	}

	root := s.bat.Root()
	rootBytes := root.Bytes()
	res.BatchCommitment = rootBytes[:]
	res.Total = time.Since(start)
	return res, nil
}

// Audit runs the §3.2.5 challenge-response protocol.
//
// SEMANTICS: this verifies LEDGER INTEGRITY, not one transaction's redaction
// history. Ref[13] has no per-transaction provenance, and answering as though it
// did would misreport the scheme. Exp 3 compares cost SCALING, which both can
// answer; it does not claim feature equivalence, which they do not have.
func (s *Scheme) Audit(ctx context.Context, q *scheme.AuditQuery) (*scheme.AuditResult, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := &scheme.AuditResult{Semantics: scheme.SemanticsLedgerIntegrity}

	// A fresh challenge per audit. A fixed one would let a prover precompute,
	// and the spot check would measure nothing.
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("ref13: audit challenge: %w", err)
	}
	chal := Challenge{
		Z:    s.challengedBlocks,
		Phi1: append([]byte("phi1"), seed...),
		Phi2: append([]byte("phi2"), seed...),
	}

	retrieveStart := time.Now()
	challenged, err := s.bat.SelectChallenged(chal, s.optimizedAuditing)
	if err != nil {
		return nil, err
	}
	proof, err := s.bat.ProveAudit(chal, challenged)
	if err != nil {
		return nil, err
	}
	res.RetrievalTime = time.Since(retrieveStart)

	verifyStart := time.Now()
	ok, err := s.bat.VerifyAudit(s.bat.Root(), chal, proof)
	if err != nil {
		return nil, err
	}
	res.VerificationTime = time.Since(verifyStart)
	res.Verified = ok

	// BlocksTraversed is the PATH UNION, not the ledger. That is the number
	// §4.1 says the cost is determined by, and reporting the ledger size here
	// would hide exactly the property Exp 3 is testing. A scheme claiming
	// ledger independence whose value grows with ledger size is contradicting
	// itself, and the harness is meant to catch that.
	res.BlocksTraversed = proof.PathUnionSize

	// One G1 commitment and one field element per opening, plus the aggregate.
	const g1Bytes, frBytes = 48, 32
	res.EvidenceBytes = proof.PathUnionSize*(g1Bytes+frBytes+frBytes) + g1Bytes + frBytes

	// No auditor authentication step exists in this scheme; reported as zero
	// rather than folded into the total, so ZK-Redact is not penalised for
	// providing a capability this baseline lacks.
	res.AuthorizationTime = 0

	return res, nil
}

// versionOf is used by tests to observe redaction bookkeeping.
func (s *Scheme) versionOf(seq int) int { return s.versions[seq] }
