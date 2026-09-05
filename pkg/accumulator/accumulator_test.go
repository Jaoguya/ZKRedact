package accumulator

import (
	"math/big"
	"testing"
)

// Tests use a small modulus for speed. The 3072-bit path is exercised once, in
// TestOperatesAtTheConfiguredSecurityLevel, because generating a 3072-bit
// modulus per test would dominate the suite.
const testBits = 512

func testAccumulator(t *testing.T) *Accumulator {
	t.Helper()
	n, err := GenerateUntrusted(testBits)
	if err != nil {
		t.Fatalf("GenerateUntrusted: %v", err)
	}
	a, err := New(Config{Bits: testBits, Modulus: n})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

// -----------------------------------------------------------------------------
// Membership
// -----------------------------------------------------------------------------

func TestMembershipWitnessVerifies(t *testing.T) {
	a := testAccumulator(t)

	elements := [][]byte{[]byte("block-0"), []byte("block-1"), []byte("block-2")}
	for _, e := range elements {
		if _, err := a.Add(e); err != nil {
			t.Fatalf("Add(%s): %v", e, err)
		}
	}

	// Witnesses are regenerated after the final state is reached; an RSA
	// accumulator invalidates earlier ones on every update, which is the cost
	// Ref[22]'s Modify pays.
	for _, e := range elements {
		w, err := a.MembershipWitness(e)
		if err != nil {
			t.Fatalf("MembershipWitness(%s): %v", e, err)
		}
		ok, err := VerifyMembership(a.Modulus(), a.State(), w, e)
		if err != nil {
			t.Fatalf("VerifyMembership(%s): %v", e, err)
		}
		if !ok {
			t.Errorf("membership witness for %s does not verify", e)
		}
	}
}

// TestForgedMembershipWitnessIsRejected is the negative control. Without it, a
// VerifyMembership that always returned true would pass every other test here.
func TestForgedMembershipWitnessIsRejected(t *testing.T) {
	a := testAccumulator(t)
	if _, err := a.Add([]byte("block-0")); err != nil {
		t.Fatalf("Add: %v", err)
	}

	forged := big.NewInt(12345)
	ok, err := VerifyMembership(a.Modulus(), a.State(), forged, []byte("block-0"))
	if err != nil {
		t.Fatalf("VerifyMembership: %v", err)
	}
	if ok {
		t.Fatal("a forged witness verified; the accumulator proves nothing")
	}
}

// TestWitnessForAnUnaccumulatedElementIsRejected pins that membership means
// membership: a witness must not verify for an element never added.
func TestWitnessForAnUnaccumulatedElementIsRejected(t *testing.T) {
	a := testAccumulator(t)
	if _, err := a.Add([]byte("block-0")); err != nil {
		t.Fatalf("Add: %v", err)
	}

	w, err := a.MembershipWitness([]byte("block-0"))
	if err != nil {
		t.Fatalf("MembershipWitness: %v", err)
	}
	ok, err := VerifyMembership(a.Modulus(), a.State(), w, []byte("never-added"))
	if err != nil {
		t.Fatalf("VerifyMembership: %v", err)
	}
	if ok {
		t.Fatal("a witness verified for an element that was never accumulated")
	}
}

// -----------------------------------------------------------------------------
// Non-membership — what makes the accumulator UNIVERSAL
// -----------------------------------------------------------------------------

func TestNonMembershipWitnessVerifies(t *testing.T) {
	a := testAccumulator(t)
	for _, e := range [][]byte{[]byte("block-0"), []byte("block-1")} {
		if _, err := a.Add(e); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}

	absent := []byte("block-absent")
	aCoef, d, err := a.NonMembershipWitness(absent)
	if err != nil {
		t.Fatalf("NonMembershipWitness: %v", err)
	}
	ok, err := VerifyNonMembership(a.Modulus(), a.Generator(), a.State(), aCoef, d, absent)
	if err != nil {
		t.Fatalf("VerifyNonMembership: %v", err)
	}
	if !ok {
		t.Fatal("a valid non-membership witness did not verify; Modify cannot prove " +
			"that a superseded version is gone")
	}
}

func TestNonMembershipIsRefusedForAPresentElement(t *testing.T) {
	a := testAccumulator(t)
	if _, err := a.Add([]byte("block-0")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, _, err := a.NonMembershipWitness([]byte("block-0")); err == nil {
		t.Fatal("a non-membership witness was produced for an accumulated element")
	}
}

// TestForgedNonMembershipIsRejected is the negative control for the above.
func TestForgedNonMembershipIsRejected(t *testing.T) {
	a := testAccumulator(t)
	if _, err := a.Add([]byte("block-0")); err != nil {
		t.Fatalf("Add: %v", err)
	}

	ok, err := VerifyNonMembership(a.Modulus(), a.Generator(), a.State(),
		big.NewInt(1), big.NewInt(1), []byte("block-0"))
	if err != nil {
		t.Fatalf("VerifyNonMembership: %v", err)
	}
	if ok {
		t.Fatal("a forged non-membership witness verified for an accumulated element")
	}
}

// -----------------------------------------------------------------------------
// The reversion attack — the paper's central security claim
// -----------------------------------------------------------------------------

// TestRevertedVersionIsDetected is the fidelity check docs/baselines/ref22-shen.md
// says carries the most weight.
//
// Ref[22]'s Modify calls UA.Del on the prior version and UA.Add on the new one.
// If Del does not genuinely invalidate, an adversary can present the OLD block
// with its OLD witness and have it accepted — the redaction is undone and the
// ledger reports itself consistent. A hash-set stand-in fails exactly here while
// passing every membership test above.
func TestRevertedVersionIsDetected(t *testing.T) {
	a := testAccumulator(t)

	oldVersion := []byte("block-7@v0")
	newVersion := []byte("block-7@v1")

	if _, err := a.Add([]byte("block-6")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := a.Add(oldVersion); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// The witness an adversary keeps from before the redaction.
	staleWitness, err := a.MembershipWitness(oldVersion)
	if err != nil {
		t.Fatalf("MembershipWitness: %v", err)
	}

	// --- the redaction: Modify = Del(old) then Add(new) ---
	if err := a.Delete(oldVersion); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := a.Add(newVersion); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// 1. The stale witness must no longer verify.
	ok, err := VerifyMembership(a.Modulus(), a.State(), staleWitness, oldVersion)
	if err != nil {
		t.Fatalf("VerifyMembership: %v", err)
	}
	if ok {
		t.Fatal("the pre-redaction witness still verifies: a reverted block would be " +
			"accepted and the redaction silently undone")
	}

	// 2. And the accumulator must be able to PROVE the old version is gone,
	//    which is what makes the detection positive rather than merely absent.
	aCoef, d, err := a.NonMembershipWitness(oldVersion)
	if err != nil {
		t.Fatalf("NonMembershipWitness for the reverted version: %v", err)
	}
	proved, err := VerifyNonMembership(a.Modulus(), a.Generator(), a.State(), aCoef, d, oldVersion)
	if err != nil {
		t.Fatalf("VerifyNonMembership: %v", err)
	}
	if !proved {
		t.Fatal("the superseded version's absence cannot be proved")
	}

	// 3. The new version must be present.
	w, err := a.MembershipWitness(newVersion)
	if err != nil {
		t.Fatalf("MembershipWitness(new): %v", err)
	}
	ok, err = VerifyMembership(a.Modulus(), a.State(), w, newVersion)
	if err != nil {
		t.Fatalf("VerifyMembership(new): %v", err)
	}
	if !ok {
		t.Fatal("the redacted version is not in the accumulator")
	}
}

// -----------------------------------------------------------------------------
// Hash-to-prime
// -----------------------------------------------------------------------------

// TestPrimeRepresentativesAreDeterministic pins that a verifier derives the same
// prime as the prover. If they could differ, a prover could pick a convenient
// representative and forge a witness.
func TestPrimeRepresentativesAreDeterministic(t *testing.T) {
	for i := 0; i < 50; i++ {
		x := []byte{byte(i)}
		p1, err := HashToPrime(x)
		if err != nil {
			t.Fatalf("HashToPrime: %v", err)
		}
		p2, err := HashToPrime(x)
		if err != nil {
			t.Fatalf("HashToPrime: %v", err)
		}
		if p1.Cmp(p2) != 0 {
			t.Fatalf("element %d hashed to two different primes", i)
		}
	}
}

func TestPrimeRepresentativesArePrime(t *testing.T) {
	for i := 0; i < 50; i++ {
		p, err := HashToPrime([]byte{byte(i)})
		if err != nil {
			t.Fatalf("HashToPrime: %v", err)
		}
		if !p.ProbablyPrime(millerRabinRounds) {
			t.Errorf("representative for %d is not prime", i)
		}
		if p.BitLen() != primeBits {
			t.Errorf("representative for %d is %d bits, want %d — a shorter prime is "+
				"cheaper to exponentiate, making some elements systematically cheaper",
				i, p.BitLen(), primeBits)
		}
	}
}

func TestDistinctElementsGetDistinctPrimes(t *testing.T) {
	seen := make(map[string]int, 500)
	for i := 0; i < 500; i++ {
		p, err := HashToPrime([]byte{byte(i % 256), byte(i / 256)})
		if err != nil {
			t.Fatalf("HashToPrime: %v", err)
		}
		if prev, dup := seen[p.String()]; dup {
			t.Fatalf("elements %d and %d share a prime: one's witness would prove "+
				"the other", prev, i)
		}
		seen[p.String()] = i
	}
}

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

// TestOperatesAtTheConfiguredSecurityLevel exercises the real 3072-bit modulus
// once, and pins that a mismatched size is refused.
func TestOperatesAtTheConfiguredSecurityLevel(t *testing.T) {
	const bits = 3072
	n, err := GenerateUntrusted(bits)
	if err != nil {
		t.Fatalf("GenerateUntrusted: %v", err)
	}
	a, err := New(Config{Bits: bits, Modulus: n})
	if err != nil {
		t.Fatalf("New at %d bits: %v", bits, err)
	}
	if _, err := a.Add([]byte("block-0")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	w, err := a.MembershipWitness([]byte("block-0"))
	if err != nil {
		t.Fatalf("MembershipWitness: %v", err)
	}
	ok, err := VerifyMembership(a.Modulus(), a.State(), w, []byte("block-0"))
	if err != nil || !ok {
		t.Fatalf("membership at %d bits failed: ok=%v err=%v", bits, ok, err)
	}

	// A modulus of the wrong size must be refused: a smaller one would make
	// every accumulator operation cheaper than the shared security level allows.
	if _, err := New(Config{Bits: bits, Modulus: big.NewInt(15)}); err == nil {
		t.Error("a 4-bit modulus was accepted for a 3072-bit configuration")
	}
}

func TestRefusesAMissingModulus(t *testing.T) {
	if _, err := New(Config{Bits: 3072}); err == nil {
		t.Fatal("an accumulator was built with no modulus")
	}
}

func TestDoubleAddIsRefused(t *testing.T) {
	a := testAccumulator(t)
	if _, err := a.Add([]byte("x")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := a.Add([]byte("x")); err == nil {
		t.Fatal("the same element was accumulated twice; its prime would appear " +
			"squared and witnesses would not verify")
	}
}

func TestDeleteOfAnAbsentElementIsRefused(t *testing.T) {
	a := testAccumulator(t)
	if err := a.Delete([]byte("never-added")); err == nil {
		t.Fatal("deleting an unaccumulated element was accepted")
	}
}
