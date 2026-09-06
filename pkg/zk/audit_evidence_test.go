package zk

import (
	"testing"
)

// auditFixture builds one proof together with everything the AUDITOR is given:
// the statement, the registry root, and the marshalled proof. Nothing the
// prover holds in memory crosses into the verification under test.
func auditFixture(t *testing.T) (p *Params, st *Statement, root, proofBytes []byte) {
	t.Helper()

	p = batchFixture(t)
	pol := testPolicy(t, "((sender OR receiver) AND validator)")
	attrs := [NumAttributes]uint64{
		AttrSender: 1, AttrReceiver: 1, AttrValidator: 1, AttrRole: RoleAdmin,
	}
	secret := Uint64Bytes(31337)
	reg := testRegistry(t, CredentialLeaf(secret, attrs))

	req := testRequest()
	req.Nonce = []byte("audit-nonce")
	st, err := BuildStatement(req, pol, 0, 100)
	if err != nil {
		t.Fatalf("BuildStatement: %v", err)
	}
	a, err := NewAssignment(st, pol, attrs, secret, reg)
	if err != nil {
		t.Fatalf("NewAssignment: %v", err)
	}
	pr, err := Prove(p, a)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}
	proofBytes, err = MarshalProof(pr)
	if err != nil {
		t.Fatalf("MarshalProof: %v", err)
	}
	return p, st, reg.Root(), proofBytes
}

// TestVerifyEvidenceAcceptsHonestEvidence is the baseline: a proof produced by
// Prove must verify when rebuilt entirely from stored bytes.
func TestVerifyEvidenceAcceptsHonestEvidence(t *testing.T) {
	p, st, root, proofBytes := auditFixture(t)
	if err := VerifyEvidence(p, st, root, proofBytes); err != nil {
		t.Fatalf("honest evidence rejected: %v", err)
	}
}

// TestVerifyEvidenceRejectsAlteredStatement is the check that justifies
// rebuilding the public witness rather than reusing the prover's.
//
// The proof bytes are untouched; only the retrieved statement differs. An
// auditor that trusted the prover's stored witness would accept this, and
// Phase 6's authorization check would be verifying that the prover proved
// SOMETHING rather than that it proved THIS record.
func TestVerifyEvidenceRejectsAlteredStatement(t *testing.T) {
	p, st, root, proofBytes := auditFixture(t)

	for _, tc := range []struct {
		name  string
		alter func(*Statement)
	}{
		{"tx version", func(s *Statement) { s.TxVersion++ }},
		{"modification", func(s *Statement) { s.Mod = FieldBytes([]byte("someone else's content")) }},
		{"policy version", func(s *Statement) { s.PolicyVersion++ }},
		{"location", func(s *Statement) { s.Loc++ }},
		{"timestamp", func(s *Statement) { s.Timestamp++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			altered := *st
			tc.alter(&altered)
			if err := VerifyEvidence(p, &altered, root, proofBytes); err == nil {
				t.Errorf("a record whose %s was altered still verified; the audit "+
					"is checking the prover's claim rather than the stored record", tc.name)
			}
		})
	}
}

// TestVerifyEvidenceRejectsForeignRegistry pins the second public input. A
// proof of membership in a DIFFERENT credential registry must not pass, or the
// audit would accept a credential the system never registered.
func TestVerifyEvidenceRejectsForeignRegistry(t *testing.T) {
	p, st, root, proofBytes := auditFixture(t)

	other := append([]byte(nil), root...)
	other[0] ^= 0xff
	if err := VerifyEvidence(p, st, other, proofBytes); err == nil {
		t.Error("evidence verified against a foreign registry root")
	}
}

// TestVerifyEvidenceRejectsCorruptProof separates corrupted bytes from a false
// proof: both must fail, and neither may panic.
func TestVerifyEvidenceRejectsCorruptProof(t *testing.T) {
	p, st, root, proofBytes := auditFixture(t)

	t.Run("truncated", func(t *testing.T) {
		if err := VerifyEvidence(p, st, root, proofBytes[:len(proofBytes)/2]); err == nil {
			t.Error("a truncated proof verified")
		}
	})
	t.Run("flipped bit", func(t *testing.T) {
		bad := append([]byte(nil), proofBytes...)
		bad[len(bad)-1] ^= 0x01
		if err := VerifyEvidence(p, st, root, bad); err == nil {
			t.Error("a corrupted proof verified")
		}
	})
	t.Run("empty", func(t *testing.T) {
		if err := VerifyEvidence(p, st, root, nil); err == nil {
			t.Error("empty evidence verified")
		}
	})
}

// TestPublicWitnessOrderMatchesTheProver checks the rebuilt witness against the
// one Prove produced, field by field.
//
// The order of the two public inputs cannot be verified by a passing proof
// alone in a circuit where both happen to be field elements — a swap would just
// reject everything. This compares the encodings directly, so a reordering is
// reported as what it is.
func TestPublicWitnessOrderMatchesTheProver(t *testing.T) {
	p := batchFixture(t)
	pol := testPolicy(t, "((sender OR receiver) AND validator)")
	attrs := [NumAttributes]uint64{
		AttrSender: 1, AttrReceiver: 1, AttrValidator: 1, AttrRole: RoleAdmin,
	}
	secret := Uint64Bytes(31337)
	reg := testRegistry(t, CredentialLeaf(secret, attrs))

	req := testRequest()
	st, err := BuildStatement(req, pol, 0, 100)
	if err != nil {
		t.Fatalf("BuildStatement: %v", err)
	}
	a, err := NewAssignment(st, pol, attrs, secret, reg)
	if err != nil {
		t.Fatalf("NewAssignment: %v", err)
	}
	pr, err := Prove(p, a)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	rebuilt, err := PublicWitness(st.Digest(), reg.Root())
	if err != nil {
		t.Fatalf("PublicWitness: %v", err)
	}

	fromProver, err := pr.Witness.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal prover witness: %v", err)
	}
	fromAuditor, err := rebuilt.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal rebuilt witness: %v", err)
	}
	if string(fromProver) != string(fromAuditor) {
		t.Errorf("rebuilt public witness differs from the prover's:\n prover  %x\n auditor %x",
			fromProver, fromAuditor)
	}
}
