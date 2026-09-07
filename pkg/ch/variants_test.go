package ch

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
	"testing"
)

// errNoCollision reports an adaptation that verified against the wrong hash.
var errNoCollision = errors.New("adapted randomness does not collide onto the original hash")

// -----------------------------------------------------------------------------
// Ref[13] — ephemeral trapdoor (Ref[13].md Eq. 5)
// -----------------------------------------------------------------------------

func TestEphemeralHashMatchesPaperEquation(t *testing.T) {
	curve := testCurve()
	k, err := EphemeralKeyGen(curve, rand.Reader)
	if err != nil {
		t.Fatalf("EphemeralKeyGen: %v", err)
	}
	n := curve.Params().N

	ctx := []byte("h_{i-1}")
	m := []byte("block payload")
	r, _ := NewRandomness(curve, rand.Reader)

	got, err := k.Hash(ctx, m, r)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	// Independently compute g^{H1(...)·(x+y) + r}, the right-hand form of Eq. 5,
	// so the implementation is checked against the paper rather than itself.
	// y_s = H2(x ‖ m_s), the component Eq. 5 hashes m_s under. Derived from the
	// message, not read off the key: Ref[13] indexes y by the block.
	y, yx, yy, err := k.EphemeralPointFor(m)
	if err != nil {
		t.Fatalf("EphemeralPointFor: %v", err)
	}
	e := ephemeralChallenge(curve, ctx, m, yx, yy)
	sum := new(big.Int).Add(k.x, y)
	sum.Mod(sum, n)
	exp := new(big.Int).Mul(e, sum)
	exp.Add(exp, r)
	exp.Mod(exp, n)
	wx, wy := curve.ScalarBaseMult(exp.Bytes())

	if got.X.Cmp(wx) != 0 || got.Y.Cmp(wy) != 0 {
		t.Errorf("hash does not match Eq. 5 exponent form g^{H1(...)(x+y)+r}")
	}
}

func TestEphemeralAdaptProducesCollision(t *testing.T) {
	curve := testCurve()
	k, _ := EphemeralKeyGen(curve, rand.Reader)

	ctx := []byte("prev-block-hash")
	oldM := []byte("harmful content")
	newM := []byte("[redacted]")

	r, _ := NewRandomness(curve, rand.Reader)
	_, oldYx, oldYy, err := k.EphemeralPointFor(oldM)
	if err != nil {
		t.Fatalf("EphemeralPointFor: %v", err)
	}
	oldR := EphemeralRandomness{R: r, Yx: oldYx, Yy: oldYy}

	oldH, err := k.Hash(ctx, oldM, r)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	newR, err := k.EphemeralAdapt(ctx, oldM, oldR, newM)
	if err != nil {
		t.Fatalf("EphemeralAdapt: %v", err)
	}

	newH, err := EphemeralHash(curve, k.Xx, k.Xy, newR.Yx, newR.Yy, ctx, newM, newR.R)
	if err != nil {
		t.Fatalf("EphemeralHash: %v", err)
	}
	if !oldH.Equal(newH) {
		t.Fatalf("adaptation did not preserve the hash")
	}
}

// TestEphemeralAdaptRotatesY covers the behaviour that distinguishes this
// construction from the classic one: Y is per-BLOCK state, derived from the
// message, and must change when the message does.
//
// It also pins the invariant that makes a ledger redactable at all. Adapt must
// NOT advance a key-wide component: Ref[13] §3.2.3 stores Y_s with the block
// (B_s = (ch_s, m_s, Y_s, r_s)) and Eq. 8 uses the y_s belonging to that block.
// A key-wide Y serves one block, so mutating it here left every other block
// carrying a point the key would no longer accept — Exp 2 redacted 20 blocks
// and committed 1.
func TestEphemeralAdaptRotatesY(t *testing.T) {
	curve := testCurve()
	k, _ := EphemeralKeyGen(curve, rand.Reader)

	ctx := []byte("ctx")
	r, _ := NewRandomness(curve, rand.Reader)
	_, oldYx, oldYy, err := k.EphemeralPointFor([]byte("m"))
	if err != nil {
		t.Fatalf("EphemeralPointFor: %v", err)
	}
	oldR := EphemeralRandomness{R: r, Yx: oldYx, Yy: oldYy}

	keyYx, keyYy := new(big.Int).Set(k.Yx), new(big.Int).Set(k.Yy)

	newR, err := k.EphemeralAdapt(ctx, []byte("m"), oldR, []byte("m'"))
	if err != nil {
		t.Fatalf("EphemeralAdapt: %v", err)
	}

	if newR.Yx.Cmp(oldYx) == 0 && newR.Yy.Cmp(oldYy) == 0 {
		t.Errorf("ephemeral point Y did not change; the per-redaction key derivation is missing")
	}
	if k.Yx.Cmp(keyYx) != 0 || k.Yy.Cmp(keyYy) != 0 {
		t.Errorf("EphemeralAdapt mutated key-wide ephemeral state; Y_s belongs to the block")
	}
}

// TestEphemeralAdaptIndependentBlocks is the regression for the defect Exp 2
// and Exp 3 hit: two blocks hashed under the same key must BOTH be adaptable,
// in either order, with neither adaptation disturbing the other.
func TestEphemeralAdaptIndependentBlocks(t *testing.T) {
	curve := testCurve()
	k, _ := EphemeralKeyGen(curve, rand.Reader)
	ctx := []byte("ctx")

	adapt := func(oldM, newM string) error {
		r, _ := NewRandomness(curve, rand.Reader)
		_, yx, yy, err := k.EphemeralPointFor([]byte(oldM))
		if err != nil {
			return err
		}
		oldR := EphemeralRandomness{R: r, Yx: yx, Yy: yy}
		h, err := k.Hash(ctx, []byte(oldM), r)
		if err != nil {
			return err
		}
		newR, err := k.EphemeralAdapt(ctx, []byte(oldM), oldR, []byte(newM))
		if err != nil {
			return err
		}
		if !k.Verify(ctx, []byte(newM), newR, h) {
			return errNoCollision
		}
		return nil
	}

	if err := adapt("block-A", "A redacted"); err != nil {
		t.Fatalf("first block: %v", err)
	}
	if err := adapt("block-B", "B redacted"); err != nil {
		t.Fatalf("second block, after the first was adapted: %v", err)
	}
	if err := adapt("block-A", "A redacted twice"); err != nil {
		t.Fatalf("first block again: %v", err)
	}
}

// TestEphemeralVerifyNeedsCorrectY confirms Y is genuinely bound into the
// challenge: verifying a redacted value against the stale Y must fail.
func TestEphemeralVerifyNeedsCorrectY(t *testing.T) {
	curve := testCurve()
	k, _ := EphemeralKeyGen(curve, rand.Reader)

	ctx := []byte("ctx")
	r, _ := NewRandomness(curve, rand.Reader)
	_, mYx, mYy, err := k.EphemeralPointFor([]byte("m"))
	if err != nil {
		t.Fatalf("EphemeralPointFor: %v", err)
	}
	staleY := EphemeralRandomness{R: r, Yx: mYx, Yy: mYy}

	h, _ := k.Hash(ctx, []byte("m"), r)
	newR, err := k.EphemeralAdapt(ctx, []byte("m"), staleY, []byte("m'"))
	if err != nil {
		t.Fatalf("EphemeralAdapt: %v", err)
	}

	// Correct Y verifies.
	if !k.Verify(ctx, []byte("m'"), newR, h) {
		t.Errorf("verification failed with the correct ephemeral point")
	}
	// Stale Y must not.
	wrong := EphemeralRandomness{R: newR.R, Yx: staleY.Yx, Yy: staleY.Yy}
	if k.Verify(ctx, []byte("m'"), wrong, h) {
		t.Errorf("verification succeeded with a stale ephemeral point")
	}
}

func TestEphemeralAdaptRejectsForeignY(t *testing.T) {
	curve := testCurve()
	k, _ := EphemeralKeyGen(curve, rand.Reader)
	other, _ := EphemeralKeyGen(curve, rand.Reader)

	r, _ := NewRandomness(curve, rand.Reader)
	foreign := EphemeralRandomness{R: r, Yx: other.Yx, Yy: other.Yy}

	if _, err := k.EphemeralAdapt([]byte("ctx"), []byte("m"), foreign, []byte("m'")); err == nil {
		t.Errorf("adaptation accepted an ephemeral point this key never produced")
	}
}

func TestEphemeralContextBinding(t *testing.T) {
	curve := testCurve()
	k, _ := EphemeralKeyGen(curve, rand.Reader)
	r, _ := NewRandomness(curve, rand.Reader)

	// ctx is the previous block hash in Ref[13]; different positions in the
	// chain must give different hashes for the same payload.
	h1, _ := k.Hash([]byte("block-100"), []byte("same payload"), r)
	h2, _ := k.Hash([]byte("block-101"), []byte("same payload"), r)

	if h1.Equal(h2) {
		t.Errorf("chain position is not bound into the hash")
	}
}

// -----------------------------------------------------------------------------
// Ref[22] — double trapdoor (Ref[22].md §II-A)
// -----------------------------------------------------------------------------

// TestDoubleTrapdoorHGenEqualsTP checks the paper's defining property, h = tP.
func TestDoubleTrapdoorHGenEqualsTP(t *testing.T) {
	curve := testCurve()
	k, err := DoubleTrapdoorKeyGen(curve, rand.Reader)
	if err != nil {
		t.Fatalf("DoubleTrapdoorKeyGen: %v", err)
	}

	handle, _, err := k.HGen([]byte("message"), rand.Reader)
	if err != nil {
		t.Fatalf("HGen: %v", err)
	}

	wx, wy := curve.ScalarBaseMult(handle.T.Bytes())
	if handle.Hash.X.Cmp(wx) != 0 || handle.Hash.Y.Cmp(wy) != 0 {
		t.Errorf("HGen did not produce h = tP as specified in §II-A")
	}
}

// TestDoubleTrapdoorRHGenReproducesHash checks that a verifier holding only hk
// rebuilds the same hash — the RHGen correctness identity.
func TestDoubleTrapdoorRHGenReproducesHash(t *testing.T) {
	curve := testCurve()
	k, _ := DoubleTrapdoorKeyGen(curve, rand.Reader)

	m := []byte("payload")
	handle, ck, err := k.HGen(m, rand.Reader)
	if err != nil {
		t.Fatalf("HGen: %v", err)
	}

	got, err := RHGen(curve, m, ck, k.Yx, k.Yy)
	if err != nil {
		t.Fatalf("RHGen: %v", err)
	}
	if !got.Equal(handle.Hash) {
		t.Errorf("RHGen did not reproduce the hash from public data alone")
	}
	if !k.Verify(handle.Hash, m, ck) {
		t.Errorf("Verify rejected a freshly generated hash")
	}
}

func TestDoubleTrapdoorAdaptProducesCollision(t *testing.T) {
	curve := testCurve()
	k, _ := DoubleTrapdoorKeyGen(curve, rand.Reader)

	oldM := []byte("harmful content")
	newM := []byte("[redacted]")

	handle, _, err := k.HGen(oldM, rand.Reader)
	if err != nil {
		t.Fatalf("HGen: %v", err)
	}

	newCk, err := k.Adapt(handle, newM, rand.Reader)
	if err != nil {
		t.Fatalf("Adapt: %v", err)
	}
	if !k.Verify(handle.Hash, newM, newCk) {
		t.Errorf("adapted checking string does not verify against the original hash")
	}
}

func TestDoubleTrapdoorVerifyRejectsTampering(t *testing.T) {
	curve := testCurve()
	k, _ := DoubleTrapdoorKeyGen(curve, rand.Reader)

	m := []byte("payload")
	handle, ck, _ := k.HGen(m, rand.Reader)

	if k.Verify(handle.Hash, []byte("different"), ck) {
		t.Errorf("verified a different message under the same checking string")
	}

	bad := DoubleTrapdoorChecking{R: new(big.Int).Add(ck.R, big.NewInt(1)), Kx: ck.Kx, Ky: ck.Ky}
	if k.Verify(handle.Hash, m, bad) {
		t.Errorf("verified a tampered r")
	}

	other, _ := DoubleTrapdoorKeyGen(curve, rand.Reader)
	if other.Verify(handle.Hash, m, ck) {
		t.Errorf("verified under the wrong hash key")
	}
}

// TestDoubleTrapdoorKeyExposureFreeness is the property that forced this
// construction into the design. The classic scheme leaks its trapdoor from a
// single collision (see TestKeyExposure); this one must not, no matter how many
// collisions an observer collects.
//
// Each Adapt samples a fresh k', so every collision introduces a new unknown
// rather than a new equation. The test asserts the concrete consequence: the
// classic recovery formula, applied to these collisions, does not yield x.
func TestDoubleTrapdoorKeyExposureFreeness(t *testing.T) {
	curve := testCurve()
	k, _ := DoubleTrapdoorKeyGen(curve, rand.Reader)

	m0 := []byte("v0")
	handle, ck0, err := k.HGen(m0, rand.Reader)
	if err != nil {
		t.Fatalf("HGen: %v", err)
	}

	collisions := []struct {
		m  []byte
		ck DoubleTrapdoorChecking
	}{{m0, ck0}}

	for i, m := range [][]byte{[]byte("v1"), []byte("v2"), []byte("v3"), []byte("v4")} {
		ck, err := k.Adapt(handle, m, rand.Reader)
		if err != nil {
			t.Fatalf("Adapt %d: %v", i, err)
		}
		if !k.Verify(handle.Hash, m, ck) {
			t.Fatalf("collision %d does not verify", i)
		}
		collisions = append(collisions, struct {
			m  []byte
			ck DoubleTrapdoorChecking
		}{m, ck})
	}

	// The classic recovery x = (e - e')/(r' - r) must fail here. Every K differs
	// between collisions, so the two equations do not share an unknown k.
	for i := 0; i < len(collisions); i++ {
		for j := i + 1; j < len(collisions); j++ {
			a, b := collisions[i], collisions[j]
			if a.ck.Kx.Cmp(b.ck.Kx) == 0 {
				t.Errorf("collisions %d and %d reused K; the fresh k' per adaptation is missing", i, j)
			}
			recovered, err := RecoverTrapdoor(curve, a.m, a.ck.R, b.m, b.ck.R)
			if err != nil {
				continue // degenerate pair, nothing recovered
			}
			if recovered.Cmp(k.x) == 0 {
				t.Fatalf("collisions %d and %d leaked the long-term trapdoor; "+
					"key-exposure freeness is broken", i, j)
			}
		}
	}
}

// TestDoubleTrapdoorDistinctTPerHash covers the storage property the paper
// calls out: the same (x, Y) with different t gives different hash values.
func TestDoubleTrapdoorDistinctTPerHash(t *testing.T) {
	curve := testCurve()
	k, _ := DoubleTrapdoorKeyGen(curve, rand.Reader)

	h1, _, _ := k.HGen([]byte("m"), rand.Reader)
	h2, _, _ := k.HGen([]byte("m"), rand.Reader)

	if h1.T.Cmp(h2.T) == 0 {
		t.Fatalf("two HGen calls produced the same per-hash trapdoor t")
	}
	if h1.Hash.Equal(h2.Hash) {
		t.Errorf("distinct t values produced the same hash value")
	}
}

func TestDoubleTrapdoorAdaptNeedsPerHashTrapdoor(t *testing.T) {
	curve := testCurve()
	k, _ := DoubleTrapdoorKeyGen(curve, rand.Reader)
	handle, _, _ := k.HGen([]byte("m"), rand.Reader)

	if _, err := k.Adapt(&DoubleTrapdoorHandle{Hash: handle.Hash}, []byte("m'"), rand.Reader); err == nil {
		t.Errorf("adaptation succeeded without the per-hash trapdoor t")
	}
}

// -----------------------------------------------------------------------------
// Cross-construction: the mapping recorded in variants.go
// -----------------------------------------------------------------------------

func TestRequiredConstructionMapping(t *testing.T) {
	// Guards the finding that prompted variants.go: two baselines must not be
	// run on the classic construction. If a future edit points them at
	// "classic", this fails.
	want := map[string]string{
		"zkredact":   "classic",
		"ref13_vrbc": "ephemeral_trapdoor",
		"ref22_shen": "double_trapdoor",
	}
	for scheme, construction := range want {
		got, ok := Required[scheme]
		if !ok {
			t.Errorf("%s has no required construction recorded", scheme)
			continue
		}
		if got != construction {
			t.Errorf("%s requires %q, want %q", scheme, got, construction)
		}
	}
	if _, ok := Required["ref10_emt"]; ok {
		t.Errorf("ref10_emt uses no chameleon hash and must not appear in Required")
	}
}

// -----------------------------------------------------------------------------
// Benchmarks — the three constructions differ in per-redaction cost, which is
// exactly what Exp 2 reports as CryptoTime.
// -----------------------------------------------------------------------------

func BenchmarkEphemeralAdapt(b *testing.B) {
	curve := elliptic.P256()
	k, _ := EphemeralKeyGen(curve, rand.Reader)
	ctx := []byte("ctx")
	r, _ := NewRandomness(curve, rand.Reader)
	er := EphemeralRandomness{R: r, Yx: k.Yx, Yy: k.Yy}
	oldM := make([]byte, 512)
	newM := make([]byte, 512)
	newM[0] = 1

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		next, err := k.EphemeralAdapt(ctx, oldM, er, newM)
		if err != nil {
			b.Fatal(err)
		}
		er = next
		oldM, newM = newM, oldM
	}
}

func BenchmarkDoubleTrapdoorAdapt(b *testing.B) {
	curve := elliptic.P256()
	k, _ := DoubleTrapdoorKeyGen(curve, rand.Reader)
	handle, _, _ := k.HGen(make([]byte, 512), rand.Reader)
	newM := make([]byte, 512)
	newM[0] = 1

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := k.Adapt(handle, newM, rand.Reader); err != nil {
			b.Fatal(err)
		}
	}
}
