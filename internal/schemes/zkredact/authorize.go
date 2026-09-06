package zkredact

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"zkredact/internal/gateway"
	"zkredact/internal/pvl"
	"zkredact/pkg/crypto"
	"zkredact/pkg/scheme"
	"zkredact/pkg/zk"
)

// credential is one requester's private authorization material: w_i's
// (Cred_i, A_i, rho_i).
type credential struct {
	attrs  [zk.NumAttributes]uint64
	secret []byte
	key    *crypto.SchnorrPrivateKey
}

// prepared is everything a REQUESTER produces before submitting. Built in
// PrepareTrace and therefore excluded from what Exp 1 measures.
type prepared struct {
	query *gateway.Query
}

// buildAuthorization wires Phases 1-3 during Setup.
//
// Every step here is untimed setup. What Exp 1 measures is Authorize, which
// does exactly two things: gateway admission and sharded proof verification.
func (s *Scheme) buildAuthorization(p scheme.SetupParams) error {
	ds := p.Dataset

	// --- circuit shape, derived from the dataset rather than chosen ---
	depth, err := predicateDepth(ds)
	if err != nil {
		return err
	}
	treeDepth := zk.TreeDepthFor(len(ds.Identities))

	params, err := zk.Setup(depth, treeDepth, p.SecurityBits)
	if err != nil {
		return err
	}
	s.zkParams = params

	// --- policies ---
	s.policies = make(map[string]*zk.Policy, len(ds.Policies))
	policyRecords := make(map[string]gateway.PolicyRecord, len(ds.Policies))
	for _, pol := range ds.Policies {
		compiled, err := zk.CompilePolicy(pol, depth, s.scopeHigh)
		if err != nil {
			return err
		}
		s.policies[pol.ID] = compiled
		policyRecords[pol.ID] = gateway.PolicyRecord{
			Version:    compiled.Version,
			Commitment: compiled.Commitment(),
		}
	}

	// --- credentials and the registry ---
	curve, err := crypto.SignatureCurve(s.signatureCurve, p.SecurityBits)
	if err != nil {
		return fmt.Errorf("zkredact: %w", err)
	}

	s.credentials = make(map[string]*credential, len(ds.Identities))
	leaves := make([][]byte, 0, len(ds.Identities))
	regs := make([]gateway.Registration, 0, len(ds.Identities))

	for _, id := range ds.Identities {
		attrs, err := zk.CompileAttributes(id)
		if err != nil {
			return fmt.Errorf("zkredact: %w", err)
		}
		secret, err := zk.RandomFieldElement()
		if err != nil {
			return err
		}
		sk, err := crypto.SchnorrKeyGen(curve, rand.Reader)
		if err != nil {
			return fmt.Errorf("zkredact: key generation for %s: %w", id.ID, err)
		}

		s.credentials[id.ID] = &credential{attrs: attrs, secret: secret, key: sk}
		leaves = append(leaves, zk.CredentialLeaf(secret, attrs))
		regs = append(regs, gateway.Registration{ID: id.ID, Key: &sk.SchnorrPublicKey})
	}

	registry, err := zk.NewRegistry(leaves, treeDepth)
	if err != nil {
		return err
	}
	s.registry = registry

	// --- ledger state the gateway checks freshness against ---
	versions := make(map[string]uint64, len(ds.Transactions))
	for _, tx := range ds.Transactions {
		versions[tx.ID] = 0
	}
	s.txVersions = versions

	// --- Phase 2: the gateway ---
	gw, err := gateway.New(
		gateway.Config{FreshnessWindow: s.freshnessWindow},
		regs, policyRecords, versions)
	if err != nil {
		return err
	}
	s.gw = gw

	// --- Phase 3: the proof verification layer ---
	layer, err := pvl.New(pvl.Config{
		ShardCount:        s.shardCount,
		BatchSize:         s.proofBatchSize,
		BatchWait:         time.Duration(s.proofBatchWait) * time.Millisecond,
		NativeBatchVerify: s.nativeBatchVerify,
	}, params)
	if err != nil {
		return err
	}
	s.pvl = layer

	svc, err := pvl.NewService(layer, s.queueDepth)
	if err != nil {
		return err
	}
	svc.Start()
	s.pvlSvc = svc

	s.prepared = make(map[string]*prepared)
	return nil
}

// predicateDepth reads the arity every policy in the dataset uses.
//
// Derived from the corpus rather than taken from config: the circuit is
// compiled for one arity, and a dataset carrying a different one would produce
// policies that cannot be proved at all. A mixed dataset is refused rather than
// compiled for the first policy found.
func predicateDepth(ds *scheme.Dataset) (int, error) {
	if len(ds.Policies) == 0 {
		return 0, fmt.Errorf("zkredact: dataset carries no policies")
	}
	depth := -1
	for _, pol := range ds.Policies {
		terms, _, err := zk.ParsePredicateArity(pol.Predicate)
		if err != nil {
			return 0, fmt.Errorf("zkredact: policy %s: %w", pol.ID, err)
		}
		if depth == -1 {
			depth = terms
			continue
		}
		if terms != depth {
			return 0, fmt.Errorf(
				"zkredact: dataset mixes predicate arities (%d and %d); the circuit "+
					"is compiled for one, and policies of the other arity could never "+
					"be proved", depth, terms)
		}
	}
	return depth, nil
}

// PrepareTrace produces the REQUESTER-side material for a replay: statement,
// proof and signature for every request.
//
// NOT TIMED, and that is the point. Groth16 proving costs roughly an order of
// magnitude more than verification, and docs/experiments.md §2.2 scopes
// ZK-Redact's authorization work to verification, shard assignment and
// batching. Producing proofs inside Authorize would report ZK-Redact as an
// order of magnitude slower than it is.
//
// It also clears the gateway's deduplication state. Each replay is a separate
// measurement of the same workload, so carrying DIDs across replays would make
// every replay after the first a wall of duplicate rejections — the in-memory
// equivalent of replaying a trace against a ledger that was never reset.
func (s *Scheme) PrepareTrace(ctx context.Context, trace []*scheme.Request) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.ready {
		return fmt.Errorf("zkredact: PrepareTrace before Setup")
	}

	// A fresh gateway drops the pending-DID set with it.
	regs := make([]gateway.Registration, 0, len(s.credentials))
	for id, c := range s.credentials {
		regs = append(regs, gateway.Registration{ID: id, Key: &c.key.SchnorrPublicKey})
	}
	policyRecords := make(map[string]gateway.PolicyRecord, len(s.policies))
	for id, pol := range s.policies {
		policyRecords[id] = gateway.PolicyRecord{Version: pol.Version, Commitment: pol.Commitment()}
	}
	versions := make(map[string]uint64, len(s.txVersions))
	for k, v := range s.txVersions {
		versions[k] = v
	}
	// THE GATEWAY'S CLOCK IS THE TRACE'S, NOT THE WALL'S.
	//
	// pkg/workload stamps the trace from a fixed epoch (2026-01-01) so a run is
	// reproducible from its seed. Checking freshness against time.Now() then
	// compares a synthetic timestamp with real time, and every request in every
	// run is months stale — which is what happened: 60 of 60 denied, at a very
	// impressive throughput, because rejecting a request costs almost nothing.
	//
	// Anchoring "now" at the newest request in the replay keeps the check doing
	// its real job — a request outside the window relative to the trace's own
	// timeline is still rejected — while staying deterministic. The alternative,
	// restamping requests at submission, would mutate the trace every scheme
	// shares.
	anchor := traceAnchor(trace)
	gw, err := gateway.New(gateway.Config{
		FreshnessWindow: s.freshnessWindow,
		Now:             func() time.Time { return anchor },
	}, regs, policyRecords, versions)
	if err != nil {
		return err
	}
	s.gw = gw

	s.prepared = make(map[string]*prepared, len(trace))

	// Identical statements yield identical proofs, so a replay of the same
	// request reuses the earlier proof rather than paying for it again. This is
	// what keeps the untimed preparation affordable across a sweep, and it is
	// sound: the same requester submitting the same statement really would send
	// the same proof.
	for _, req := range trace {
		if err := ctx.Err(); err != nil {
			return err
		}
		p, err := s.prepareOne(req)
		if err != nil {
			// A request the requester cannot prove is a DENIAL, recorded as such
			// at Authorize time rather than failing the whole preparation.
			s.prepared[req.ID] = &prepared{}
			continue
		}
		s.prepared[req.ID] = p
	}
	return nil
}

// prepareOne builds one requester's query.
func (s *Scheme) prepareOne(req *scheme.Request) (*prepared, error) {
	cred, ok := s.credentials[req.RequesterID]
	if !ok {
		return nil, fmt.Errorf("unregistered requester %s", req.RequesterID)
	}
	pol, ok := s.policies[req.PolicyID]
	if !ok {
		return nil, fmt.Errorf("unknown policy %s", req.PolicyID)
	}

	version, ok := s.txVersions[req.TargetTxID]
	if !ok {
		return nil, fmt.Errorf("unknown transaction %s", req.TargetTxID)
	}

	st, err := zk.BuildStatement(req, pol, version, s.redactionLoc)
	if err != nil {
		return nil, err
	}

	digest := st.Digest()
	proof, cached := s.proofCache[string(digest)]
	if !cached {
		a, err := zk.NewAssignment(st, pol, cred.attrs, cred.secret, s.registry)
		if err != nil {
			return nil, err
		}
		proof, err = zk.Prove(s.zkParams, a)
		if err != nil {
			return nil, err
		}
		s.proofCache[string(digest)] = proof
	}

	sig, err := cred.key.Sign(digest, rand.Reader)
	if err != nil {
		return nil, err
	}

	return &prepared{query: &gateway.Query{
		Request:          req,
		Statement:        st,
		Proof:            proof,
		PolicyVersion:    pol.Version,
		PolicyCommitment: pol.Commitment(),
		Signature:        sig,
	}}, nil
}

// Authorize is Phases 2 and 3: gateway admission, then sharded proof
// verification. This is the operation Exp 1 measures, and it contains nothing
// else.
func (s *Scheme) Authorize(ctx context.Context, req *scheme.Request) (*scheme.Authorization, error) {
	s.mu.RLock()
	ready := s.ready
	pre, hasPrepared := s.prepared[req.ID]
	gw, svc := s.gw, s.pvlSvc
	s.mu.RUnlock()

	if !ready {
		return nil, fmt.Errorf("zkredact: Authorize before Setup")
	}

	// An unprepared request must NOT be proved inline. Doing so would put the
	// requester's proving cost — an order of magnitude above verification —
	// back into the measured path, with nothing in the results to show it.
	if !hasPrepared {
		return nil, fmt.Errorf(
			"zkredact: no prepared proof for request %s. PrepareTrace must run "+
				"before the timed replay; proving here would charge Exp 1 for the "+
				"requester's work", req.ID)
	}

	auth := &scheme.Authorization{
		Request:      req,
		AuthorizedAt: time.Now(),
	}

	// The requester could not construct a proof: a denial, not a failure.
	if pre.query == nil {
		auth.Granted = false
		auth.Reason = "requester cannot satisfy the policy for this request"
		return auth, nil
	}

	// --- Phase 2: admission ---
	minimized, err := gw.Admit(pre.query)
	if err != nil {
		auth.Granted = false
		auth.Reason = err.Error()
		return auth, nil
	}

	// --- Phase 3: sharded, batched verification ---
	//
	// Submitted into the standing layer rather than verified inline, so this
	// request's proof shares a batch with whatever else is in flight and its
	// shard runs in parallel with the others. That is the mechanism Exp 1
	// measures; verifying here would make N and B inert.
	r := svc.Submit(ctx, minimized)

	if !r.Verified {
		// Phase 3 Step 4: release the identifier so the redaction can be retried.
		gw.Release(minimized.DID)
		auth.Granted = false
		auth.Reason = fmt.Sprintf("proof verification failed: %v", r.Err)
		return auth, nil
	}

	evidence, err := zk.MarshalProof(pre.query.Proof)
	if err != nil {
		return nil, fmt.Errorf("zkredact: retain audit evidence: %w", err)
	}

	auth.Granted = true
	auth.Evidence = evidence
	auth.TxVersion = minimized.TxVersion
	auth.PolicyVersion = minimized.PolicyVersion
	return auth, nil
}

// Reshard changes N between Exp 1 sweep points.
//
// Implements scheme.Resharder. Cheap by construction: the circuit does not
// depend on the shard count, so this reconfigures dispatch rather than
// recompiling anything. Re-running Setup per sweep point would pay for a
// circuit compilation and trusted setup at each one, which would dominate the
// very measurement being taken.
func (s *Scheme) Reshard(n int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ready {
		return fmt.Errorf("zkredact: Reshard before Setup")
	}
	s.shardCount = n

	// The worker set IS the shard set, so the service is rebuilt. Cheap: it
	// starts goroutines and channels, not a circuit compilation.
	if s.pvlSvc != nil {
		s.pvlSvc.Stop()
	}
	if err := s.pvl.Reshard(n); err != nil {
		return err
	}
	svc, err := pvl.NewService(s.pvl, s.queueDepth)
	if err != nil {
		return err
	}
	svc.Start()
	s.pvlSvc = svc
	return nil
}

// traceAnchor returns the newest timestamp in a replay.
//
// The gateway's virtual "now". Every request in the replay is then at most the
// trace's own span old, and the freshness window is checked against that span
// rather than against how long ago the corpus happened to be generated.
func traceAnchor(trace []*scheme.Request) time.Time {
	var newest time.Time
	for _, r := range trace {
		if r.Timestamp.After(newest) {
			newest = r.Timestamp
		}
	}
	return newest
}

// SetNativeBatchVerify switches the PVL between per-record and batch
// verification.
//
// Implements scheme.BatchVerifierTuner. Like Reshard, this is runtime
// reconfiguration: the circuit and keys are untouched, so an Exp 1 sweep point
// costs new goroutines rather than a trusted setup.
func (s *Scheme) SetNativeBatchVerify(native bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ready {
		return fmt.Errorf("zkredact: SetNativeBatchVerify before Setup")
	}
	s.nativeBatchVerify = native

	if s.pvlSvc != nil {
		s.pvlSvc.Stop()
	}
	if err := s.pvl.SetNativeBatchVerify(native); err != nil {
		return err
	}
	svc, err := pvl.NewService(s.pvl, s.queueDepth)
	if err != nil {
		return err
	}
	svc.Start()
	s.pvlSvc = svc
	return nil
}

// Rebatch changes B, the intra-shard batch size.
//
// Implements scheme.Rebatcher. The service holds a SNAPSHOT of the PVL config
// taken at NewService, so running workers keep the old B until they are
// replaced — which is why this rebuilds rather than only mutating the PVL.
func (s *Scheme) Rebatch(batchSize int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ready {
		return fmt.Errorf("zkredact: Rebatch before Setup")
	}
	s.proofBatchSize = batchSize

	if s.pvlSvc != nil {
		s.pvlSvc.Stop()
	}
	if err := s.pvl.SetBatchSize(batchSize); err != nil {
		return err
	}
	svc, err := pvl.NewService(s.pvl, s.queueDepth)
	if err != nil {
		return err
	}
	svc.Start()
	s.pvlSvc = svc
	return nil
}
