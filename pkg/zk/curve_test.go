package zk

import (
	"testing"

	"zkredact/pkg/crypto"
)

// The curve pkg/zk pins must be one the config gate accepts.
//
// zk.Curve is a compile-time constant and the circuit is compiled against
// ecc.BLS12_381 directly, so this package cannot follow a configured curve. The
// config gate refuses any pairing curve without an implementation; this test is
// the other half of that agreement, and fails if the constant is changed to
// something the gate would reject.
func TestPinnedCurveIsAcceptedByTheConfigGate(t *testing.T) {
	if err := crypto.RequireImplementedPairingCurve(Curve); err != nil {
		t.Fatalf("zk.Curve = %s, which validate-config would reject: %v", Curve, err)
	}
	if err := crypto.RequirePairingCurve(Curve, 128); err != nil {
		t.Fatalf("zk.Curve = %s does not meet the 128-bit pairing requirement: %v", Curve, err)
	}
}
