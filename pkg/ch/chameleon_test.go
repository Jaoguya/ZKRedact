package ch

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"
)

func testCurve() elliptic.Curve { return elliptic.P256() }

func mustKey(t *testing.T) *PrivateKey {
	t.Helper()
	sk, err := KeyGen(testCurve(), rand.Reader)
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	return sk
}

func mustRand(t *testing.T) *big.Int {
	t.Helper()
	r, err := Randomness(testCurve(), rand.Reader)
	if err != nil {
		t.Fatalf("Randomness: %v", err)
	}
	return r
}

func TestKeyGenProducesValidKey(t *testing.T) {
	sk := mustKey(t)
	n := testCurve().Params().N

	if sk.D.Sign() <= 0 || sk.D.Cmp(n) >= 0 {
		t.Errorf("trapdoor out of range [1, n-1]")
	}
	if !sk.Curve.IsOnCurve(sk.X, sk.Y) {
		t.Errorf("public key is not on the curve")
	}

	// Y must actually equal D*G, not merely be a valid point.
	wx, wy := testCurve().ScalarBaseMult(sk.D.Bytes())
	if wx.Cmp(sk.X) != 0 || wy.Cmp(sk.Y) != 0 {
		t.Errorf("public key does not match the trapdoor")
	}
}

func TestHashIsDeterministic(t *testing.T) {
	sk := mustKey(t)
	m := []byte("transaction payload")
	r := mustRand(t)

	h1, err := sk.Hash(m, r)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	h2, err := sk.Hash(m, r)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !h1.Equal(h2) {
		t.Errorf("same (m, r) produced different hashes")
	}
}

func TestDifferentMessagesHashDifferently(t *testing.T) {
	sk := mustKey(t)
	r := mustRand(t)

	h1, _ := sk.Hash([]byte("original"), r)
	h2, _ := sk.Hash([]byte("modified"), r)

	if h1.Equal(h2) {
		t.Errorf("distinct messages collided under the same randomness")
	}
}

// TestAdaptProducesCollision covers the property the whole scheme rests on:
// after redaction the stored hash is unchanged, so the chain does not break.
func TestAdaptProducesCollision(t *testing.T) {
	sk := mustKey(t)
	oldM := []byte("harmful content that must be removed")
	newM := []byte("[redacted]")

	oldR := mustRand(t)
	oldH, err := sk.Hash(oldM, oldR)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	newR, err := sk.Adapt(oldM, oldR, newM)
	if err != nil {
		t.Fatalf("Adapt: %v", err)
	}

	newH, err := sk.Hash(newM, newR)
	if err != nil {
		t.Fatalf("Hash after adapt: %v", err)
	}

	if !oldH.Equal(newH) {
		t.Fatalf("Adapt did not produce a collision:\n old %x\n new %x", oldH.X, newH.X)
	}
	if oldR.Cmp(newR) == 0 {
		t.Errorf("randomness unchanged; Adapt did no work")
	}
}

func TestAdaptRoundTrip(t *testing.T) {
	sk := mustKey(t)
	m0 := []byte("v0")
	r0 := mustRand(t)
	h0, _ := sk.Hash(m0, r0)

	// Chained redactions must all preserve the original hash, since a
	// transaction may be redacted more than once over its lifetime.
	msgs := [][]byte{[]byte("v1"), []byte("v2"), []byte("v3")}
	curM, curR := m0, r0
	for i, next := range msgs {
		nr, err := sk.Adapt(curM, curR, next)
		if err != nil {
			t.Fatalf("Adapt %d: %v", i, err)
		}
		h, err := sk.Hash(next, nr)
		if err != nil {
			t.Fatalf("Hash %d: %v", i, err)
		}
		if !h0.Equal(h) {
			t.Fatalf("redaction %d broke the hash", i)
		}
		curM, curR = next, nr
	}
}

func TestVerify(t *testing.T) {
	sk := mustKey(t)
	m := []byte("payload")
	r := mustRand(t)
	h, _ := sk.Hash(m, r)

	if !sk.PublicKey.Verify(m, r, h) {
		t.Errorf("Verify rejected a valid triple")
	}
	if sk.PublicKey.Verify([]byte("tampered"), r, h) {
		t.Errorf("Verify accepted a tampered message")
	}

	otherR := mustRand(t)
	if sk.PublicKey.Verify(m, otherR, h) {
		t.Errorf("Verify accepted wrong randomness")
	}
}

// TestVerifyRejectsAdaptedPairUnderWrongKey guards the property that makes the
// trapdoor meaningful: a collision is only valid under the key that produced it.
func TestVerifyRejectsAdaptedPairUnderWrongKey(t *testing.T) {
	sk1 := mustKey(t)
	sk2 := mustKey(t)

	m := []byte("original")
	r := mustRand(t)
	h, _ := sk1.Hash(m, r)

	newR, err := sk1.Adapt(m, r, []byte("redacted"))
	if err != nil {
		t.Fatalf("Adapt: %v", err)
	}
	if sk2.PublicKey.Verify([]byte("redacted"), newR, h) {
		t.Errorf("a collision under key 1 verified under key 2")
	}
}

// TestKeyExposure asserts the documented weakness of this construction: one
// published collision reveals the trapdoor.
//
// The test exists so the property is demonstrated rather than merely asserted in
// a comment, and so that a future switch to a key-exposure-resistant variant
// fails loudly here instead of passing unnoticed.
func TestKeyExposure(t *testing.T) {
	sk := mustKey(t)
	m1 := []byte("before")
	m2 := []byte("after")
	r1 := mustRand(t)

	r2, err := sk.Adapt(m1, r1, m2)
	if err != nil {
		t.Fatalf("Adapt: %v", err)
	}

	recovered, err := RecoverTrapdoor(testCurve(), m1, r1, m2, r2)
	if err != nil {
		t.Fatalf("RecoverTrapdoor: %v", err)
	}
	if recovered.Cmp(sk.D) != 0 {
		t.Errorf("expected the classic construction to leak the trapdoor from one collision;\n got  %s\n want %s",
			recovered.String(), sk.D.String())
	}
}

func TestRejectsOutOfRangeRandomness(t *testing.T) {
	sk := mustKey(t)
	n := testCurve().Params().N

	for _, tc := range []struct {
		name string
		r    *big.Int
	}{
		{"zero", big.NewInt(0)},
		{"negative", big.NewInt(-1)},
		{"equal to n", new(big.Int).Set(n)},
		{"above n", new(big.Int).Add(n, big.NewInt(1))},
		{"nil", nil},
	} {
		if _, err := sk.Hash([]byte("m"), tc.r); err == nil {
			t.Errorf("Hash accepted %s randomness", tc.name)
		}
	}
}

func TestAdaptWithoutTrapdoorFails(t *testing.T) {
	sk := mustKey(t)
	pkOnly := &PrivateKey{PublicKey: sk.PublicKey} // D left nil
	if _, err := pkOnly.Adapt([]byte("a"), mustRand(t), []byte("b")); err == nil {
		t.Errorf("Adapt succeeded without a trapdoor")
	}
}

func TestValueBytesRoundTrip(t *testing.T) {
	sk := mustKey(t)
	h, _ := sk.Hash([]byte("m"), mustRand(t))

	b := h.Bytes(testCurve())
	if len(b) == 0 {
		t.Fatalf("empty encoding")
	}
	x, y := elliptic.Unmarshal(testCurve(), b)
	if x == nil {
		t.Fatalf("encoding did not round-trip")
	}
	if x.Cmp(h.X) != 0 || y.Cmp(h.Y) != 0 {
		t.Errorf("decoded point differs from the original")
	}
}

func TestRandScalarStaysInRange(t *testing.T) {
	n := testCurve().Params().N
	for i := 0; i < 200; i++ {
		k, err := randScalar(rand.Reader, n)
		if err != nil {
			t.Fatalf("randScalar: %v", err)
		}
		if k.Sign() <= 0 || k.Cmp(n) >= 0 {
			t.Fatalf("scalar out of range: %s", k)
		}
	}
}

func TestRandScalarRejectsExhaustedReader(t *testing.T) {
	// An empty reader must surface an error rather than silently yielding a
	// zero scalar, which would produce a degenerate key.
	if _, err := randScalar(bytes.NewReader(nil), testCurve().Params().N); err == nil {
		t.Errorf("expected an error from an exhausted reader")
	}
}

// -----------------------------------------------------------------------------
// Benchmarks — Adapt is the per-request floor Exp 2 isolates as CryptoTime.
// -----------------------------------------------------------------------------

func BenchmarkHash(b *testing.B) {
	sk, _ := KeyGen(testCurve(), rand.Reader)
	r, _ := Randomness(testCurve(), rand.Reader)
	m := make([]byte, 512)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := sk.Hash(m, r); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAdapt(b *testing.B) {
	sk, _ := KeyGen(testCurve(), rand.Reader)
	r, _ := Randomness(testCurve(), rand.Reader)
	oldM := make([]byte, 512)
	newM := make([]byte, 512)
	newM[0] = 1

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := sk.Adapt(oldM, r, newM); err != nil {
			b.Fatal(err)
		}
	}
}
