package crypto

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"
)

func testCurve() elliptic.Curve { return elliptic.P256() }

func mustSchnorrKey(t *testing.T, curve elliptic.Curve) *SchnorrPrivateKey {
	t.Helper()
	sk, err := SchnorrKeyGen(curve, rand.Reader)
	if err != nil {
		t.Fatalf("SchnorrKeyGen: %v", err)
	}
	return sk
}

func mustSign(t *testing.T, sk *SchnorrPrivateKey, m []byte) *SchnorrSignature {
	t.Helper()
	sig, err := sk.Sign(m, rand.Reader)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return sig
}

// -----------------------------------------------------------------------------
// Correctness
// -----------------------------------------------------------------------------

func TestSchnorrKeyGenProducesValidKey(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			sk := mustSchnorrKey(t, curve)
			n := curve.Params().N

			if sk.D.Sign() <= 0 || sk.D.Cmp(n) >= 0 {
				t.Errorf("signing key out of range [1, n-1]")
			}
			if !sk.Curve.IsOnCurve(sk.X, sk.Y) {
				t.Errorf("public key is not on the curve")
			}
			// P must actually equal x*G, not merely be a valid point.
			wx, wy := curve.ScalarBaseMult(sk.D.Bytes())
			if wx.Cmp(sk.X) != 0 || wy.Cmp(sk.Y) != 0 {
				t.Errorf("public key does not match the signing key")
			}
		})
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name    string
		curve   elliptic.Curve
		message []byte
	}{
		{"P-256 vote yes", elliptic.P256(), []byte("yes")},
		{"P-256 vote no", elliptic.P256(), []byte("no")},
		{"P-256 empty message", elliptic.P256(), []byte{}},
		{"P-256 structured vote", elliptic.P256(), []byte("tx_id=42|decision=yes|con_k=0xab")},
		{"P-384 vote yes", elliptic.P384(), []byte("yes")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sk := mustSchnorrKey(t, tc.curve)
			sig := mustSign(t, sk, tc.message)
			if !sk.SchnorrPublicKey.Verify(tc.message, sig) {
				t.Errorf("valid signature was rejected")
			}
		})
	}
}

func TestSignatureComponentsInRange(t *testing.T) {
	sk := mustSchnorrKey(t, testCurve())
	n := testCurve().Params().N

	for i := 0; i < 50; i++ {
		sig := mustSign(t, sk, []byte("vote"))
		if sig.E.Sign() <= 0 || sig.E.Cmp(n) >= 0 {
			t.Fatalf("e out of range [1, n-1]")
		}
		if sig.S.Sign() <= 0 || sig.S.Cmp(n) >= 0 {
			t.Fatalf("s out of range [1, n-1]")
		}
	}
}

// Each signature must draw a fresh nonce. Two signatures over the same message
// sharing a nonce would expose the signing key as (s1-s2)/(e1-e2), which in
// Ref[10]'s setting means one committee member's key recovered from two votes.
func TestSignUsesFreshNonce(t *testing.T) {
	sk := mustSchnorrKey(t, testCurve())
	m := []byte("same message")

	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		sig := mustSign(t, sk, m)
		key := sig.E.String() + "|" + sig.S.String()
		if seen[key] {
			t.Fatalf("identical signature produced twice; nonce is not fresh")
		}
		seen[key] = true
	}
}

// The challenge must bind the public key, not only (R, m).
//
// Without key prefixing the scheme still signs and verifies correctly, so every
// other test here passes either way — this is the only one that detects its
// absence. It is pinned because the deviation from Schnorr's 1989 formulation
// is recorded in docs/baselines/ref10-emt.md, and a recorded deviation that
// nothing enforces is the failure this project is built to avoid.
func TestChallengeBindsPublicKey(t *testing.T) {
	a := mustSchnorrKey(t, testCurve())
	b := mustSchnorrKey(t, testCurve())
	m := []byte("tx_id=42|decision=yes")

	// One shared nonce point, so the public key is the only difference.
	rx, ry := testCurve().ScalarBaseMult(big.NewInt(7).Bytes())

	if a.SchnorrPublicKey.challenge(rx, ry, m).Cmp(b.SchnorrPublicKey.challenge(rx, ry, m)) == 0 {
		t.Errorf("challenge is identical under two different public keys; key prefixing is absent")
	}
}

// -----------------------------------------------------------------------------
// Negative tests — verification must actually reject
//
// A signature scheme that accepts everything passes every positive test above
// and benchmarks beautifully. These are the tests that establish it does not.
// -----------------------------------------------------------------------------

func TestVerifyRejectsWrongMessage(t *testing.T) {
	sk := mustSchnorrKey(t, testCurve())
	sig := mustSign(t, sk, []byte("yes"))

	for _, m := range [][]byte{
		[]byte("no"),
		[]byte("yes "),
		[]byte("ye"),
		[]byte(""),
		[]byte("YES"),
	} {
		if sk.SchnorrPublicKey.Verify(m, sig) {
			t.Errorf("accepted a signature over a different message (%q)", m)
		}
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	signer := mustSchnorrKey(t, testCurve())
	other := mustSchnorrKey(t, testCurve())
	m := []byte("yes")
	sig := mustSign(t, signer, m)

	if other.SchnorrPublicKey.Verify(m, sig) {
		t.Errorf("accepted a signature under an unrelated public key")
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	sk := mustSchnorrKey(t, testCurve())
	m := []byte("yes")
	n := testCurve().Params().N

	for _, tc := range []struct {
		name  string
		alter func(*SchnorrSignature)
	}{
		{"s incremented", func(s *SchnorrSignature) { s.S.Add(s.S, big.NewInt(1)) }},
		{"e incremented", func(s *SchnorrSignature) { s.E.Add(s.E, big.NewInt(1)) }},
		{"s negated", func(s *SchnorrSignature) { s.S.Sub(n, s.S) }},
		{"e and s swapped", func(s *SchnorrSignature) { s.E, s.S = s.S, s.E }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sig := mustSign(t, sk, m)
			tc.alter(sig)
			if sk.SchnorrPublicKey.Verify(m, sig) {
				t.Errorf("accepted a tampered signature")
			}
		})
	}
}

func TestVerifyRejectsOutOfRangeComponents(t *testing.T) {
	sk := mustSchnorrKey(t, testCurve())
	n := testCurve().Params().N
	m := []byte("yes")

	for _, tc := range []struct {
		name string
		sig  *SchnorrSignature
	}{
		{"nil signature", nil},
		{"nil e", &SchnorrSignature{E: nil, S: big.NewInt(1)}},
		{"nil s", &SchnorrSignature{E: big.NewInt(1), S: nil}},
		{"zero e", &SchnorrSignature{E: big.NewInt(0), S: big.NewInt(1)}},
		{"zero s", &SchnorrSignature{E: big.NewInt(1), S: big.NewInt(0)}},
		{"negative e", &SchnorrSignature{E: big.NewInt(-1), S: big.NewInt(1)}},
		{"negative s", &SchnorrSignature{E: big.NewInt(1), S: big.NewInt(-1)}},
		{"e equal to n", &SchnorrSignature{E: new(big.Int).Set(n), S: big.NewInt(1)}},
		{"s equal to n", &SchnorrSignature{E: big.NewInt(1), S: new(big.Int).Set(n)}},
		{"s above n", &SchnorrSignature{E: big.NewInt(1), S: new(big.Int).Add(n, big.NewInt(1))}},
	} {
		if sk.SchnorrPublicKey.Verify(m, tc.sig) {
			t.Errorf("accepted %s", tc.name)
		}
	}
}

func TestVerifyRejectsMalformedKey(t *testing.T) {
	sk := mustSchnorrKey(t, testCurve())
	m := []byte("yes")
	sig := mustSign(t, sk, m)

	offCurve := &SchnorrPublicKey{
		Curve: testCurve(),
		X:     new(big.Int).Add(sk.X, big.NewInt(1)),
		Y:     new(big.Int).Set(sk.Y),
	}
	if offCurve.Verify(m, sig) {
		t.Errorf("accepted a public key that is not on the curve")
	}

	var nilKey *SchnorrPublicKey
	if nilKey.Verify(m, sig) {
		t.Errorf("accepted a nil public key")
	}
	if (&SchnorrPublicKey{Curve: testCurve()}).Verify(m, sig) {
		t.Errorf("accepted a public key with nil coordinates")
	}
}

func TestSignWithoutPrivateKeyFails(t *testing.T) {
	sk := mustSchnorrKey(t, testCurve())
	pkOnly := &SchnorrPrivateKey{SchnorrPublicKey: sk.SchnorrPublicKey} // D left nil

	if _, err := pkOnly.Sign([]byte("yes"), rand.Reader); err == nil {
		t.Errorf("Sign succeeded without a private key")
	}
	var nilKey *SchnorrPrivateKey
	if _, err := nilKey.Sign([]byte("yes"), rand.Reader); err == nil {
		t.Errorf("Sign succeeded on a nil key")
	}
}

// -----------------------------------------------------------------------------
// Vote counting — the fidelity property Experiment 1 depends on
// -----------------------------------------------------------------------------

func TestVerifyVotesCountsOnlyValidSignatures(t *testing.T) {
	m := []byte("tx_id=42|decision=yes")
	var votes []Vote

	const honest = 5
	for i := 0; i < honest; i++ {
		sk := mustSchnorrKey(t, testCurve())
		votes = append(votes, Vote{Key: &sk.SchnorrPublicKey, Signature: mustSign(t, sk, m)})
	}

	// A forged vote: a real signature over a different message, submitted under
	// a committee member's key. If this counted, the threshold could be reached
	// without that member's approval — Ref[10]'s Theorem 2 is precisely the
	// claim that it cannot.
	forger := mustSchnorrKey(t, testCurve())
	votes = append(votes, Vote{
		Key:       &forger.SchnorrPublicKey,
		Signature: mustSign(t, forger, []byte("tx_id=42|decision=no")),
	})

	// A vote whose signature belongs to someone else entirely.
	impostor := mustSchnorrKey(t, testCurve())
	votes = append(votes, Vote{
		Key:       &impostor.SchnorrPublicKey,
		Signature: mustSign(t, mustSchnorrKey(t, testCurve()), m),
	})

	// Structurally broken submissions.
	votes = append(votes, Vote{Key: nil, Signature: mustSign(t, forger, m)})
	votes = append(votes, Vote{Key: &forger.SchnorrPublicKey, Signature: nil})

	if got := VerifyVotes(m, votes); got != honest {
		t.Errorf("counted %d valid votes, want %d", got, honest)
	}
}

func TestVerifyVotesEmpty(t *testing.T) {
	if got := VerifyVotes([]byte("m"), nil); got != 0 {
		t.Errorf("counted %d votes in an empty set, want 0", got)
	}
}

// -----------------------------------------------------------------------------
// Configuration surface
// -----------------------------------------------------------------------------

func TestSignatureCurveResolvesAndEnforcesLevel(t *testing.T) {
	for _, tc := range []struct {
		name    string
		curve   string
		target  int
		wantErr bool
		why     string
	}{
		{"P-256 at 128", CurveP256, 128, false, ""},
		{"P-384 at 128", CurveP384, 128, false, ""},
		{"P-384 at 192", CurveP384, 192, false, ""},
		{"P-256 at 192", CurveP256, 192, true, "below target level"},
		{"BN254 at 128", CurveBN254, 128, true, "the exTNFS trap"},
		{"unknown curve", "P-192", 128, true, "not in the registry"},
		{"registered but not implemented", CurveBLS12381, 128, true, "no stdlib arithmetic"},
		{"secp256k1 not implemented", CurveSecp256k1, 128, true, "no stdlib arithmetic"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := SignatureCurve(tc.curve, tc.target)
			if tc.wantErr {
				if err == nil {
					t.Errorf("accepted %s at %d-bit target (%s)", tc.curve, tc.target, tc.why)
				}
				return
			}
			if err != nil {
				t.Fatalf("rejected %s at %d: %v", tc.curve, tc.target, err)
			}
			if c == nil {
				t.Fatalf("returned a nil curve with no error")
			}
		})
	}
}

// The resolved curve must be usable end to end, not merely non-nil — otherwise
// a curve could pass the config gate and fail at the first signature.
func TestSignatureCurveIsUsable(t *testing.T) {
	curve, err := SignatureCurve(CurveP256, 128)
	if err != nil {
		t.Fatalf("SignatureCurve: %v", err)
	}
	sk := mustSchnorrKey(t, curve)
	m := []byte("yes")
	if !sk.SchnorrPublicKey.Verify(m, mustSign(t, sk, m)) {
		t.Errorf("signature over the resolved curve did not verify")
	}
}

func TestRequireHash(t *testing.T) {
	if err := RequireHash("SHA-256"); err != nil {
		t.Errorf("rejected the implemented hash: %v", err)
	}
	for _, name := range []string{"SHA-3", "SHA3-256", "BLAKE2b", "SHA-512", "sha-256", ""} {
		if err := RequireHash(name); err == nil {
			t.Errorf("accepted %q, which the challenge does not use", name)
		}
	}
}
