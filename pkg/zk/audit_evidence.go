package zk

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
)

// This file is the AUDITOR's side of the proof system: Phase 6 Step 4's
//
//	ZK.Verify(vk_zk, x_{i,k}, pi_{i,k}) = 1
//
// which is a different operation from the one Phase 3 performs, and the
// difference is the whole point of the check.
//
// Phase 3 verifies a *Proof the prover just handed over — that object carries
// the public witness the prover built. An auditor who reused it would be
// checking the proof against the prover's OWN claim about what was proved, and
// a record whose statement had been altered after the fact would still verify.
//
// So the auditor rebuilds the public input from the retrieved statement
// x_{i,k}, deserialises pi_{i,k} from the evidence store, and verifies the two
// against vk_zk. Nothing the prover produced is trusted except the proof bytes
// themselves. That is what makes Phase 6's authorization check independent
// rather than a replay of Phase 3's result.

// UnmarshalProof reconstructs a proof from MarshalProof's output.
func UnmarshalProof(b []byte) (groth16.Proof, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("zk: empty proof bytes")
	}
	pr := groth16.NewProof(ecc.BLS12_381)
	if _, err := pr.ReadFrom(bytes.NewReader(b)); err != nil {
		return nil, fmt.Errorf("zk: unmarshal proof: %w", err)
	}
	return pr, nil
}

// PublicWitness builds the circuit's public input vector from its two members:
// the statement digest eta_i and the credential registry root.
//
// ORDER IS LOAD-BEARING and matches AuthorizationCircuit's public field
// declaration — StatementDigest first, RegistryRoot second. A swap would not
// fail to build a witness; it would simply reject every honest proof, which
// reads as tampered evidence rather than as an encoding mistake.
func PublicWitness(statementDigest, registryRoot []byte) (witness.Witness, error) {
	if len(statementDigest) == 0 || len(registryRoot) == 0 {
		return nil, fmt.Errorf("zk: public witness needs both the statement digest and the registry root")
	}

	w, err := witness.New(ecc.BLS12_381.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("zk: new witness: %w", err)
	}

	vals := make(chan any, 2)
	vals <- new(big.Int).SetBytes(statementDigest)
	vals <- new(big.Int).SetBytes(registryRoot)
	close(vals)

	if err := w.Fill(2, 0, vals); err != nil {
		return nil, fmt.Errorf("zk: fill public witness: %w", err)
	}
	return w, nil
}

// VerifyEvidence is the auditor's check: recompute eta_i from the retrieved
// statement, rebuild the public input, and verify the stored proof bytes
// against vk_zk.
//
// Returns an error rather than a bool so a malformed proof and a false one stay
// distinguishable — the audit reports the first as evidence corruption and the
// second as a failed authorization, and conflating them would let a truncated
// record read as a policy violation.
func VerifyEvidence(p *Params, st *Statement, registryRoot, proofBytes []byte) error {
	if p == nil || p.VK == nil {
		return fmt.Errorf("zk: no verification key")
	}
	if st == nil {
		return fmt.Errorf("zk: no statement to verify against")
	}

	pub, err := PublicWitness(st.Digest(), registryRoot)
	if err != nil {
		return err
	}
	pr, err := UnmarshalProof(proofBytes)
	if err != nil {
		return err
	}
	if err := groth16.Verify(pr, p.VK, pub); err != nil {
		return fmt.Errorf("zk: evidence verification failed: %w", err)
	}
	return nil
}
