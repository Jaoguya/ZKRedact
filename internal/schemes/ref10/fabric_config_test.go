package ref10

import (
	"strings"
	"testing"
	"time"
)

func fullGatewayParams() map[string]any {
	return map[string]any{
		"vote_transport": transportFabric,
		"gateway": map[string]any{
			"peer_endpoint":      "localhost:7051",
			"peer_server_name":   "peer0.org1.example.com",
			"tls_cert_path":      "network/organizations/.../ca.crt",
			"msp_id":             "Org1MSP",
			"crypto_path":        "network/organizations/peerOrganizations/org1.example.com",
			"channel":            "redaction",
			"chaincode":          "redaction",
			"endorse_timeout_ms": 30000,
			"commit_timeout_ms":  60000,
		},
	}
}

func TestGatewayConfigParsesFullSettings(t *testing.T) {
	cfg, err := gatewayConfigFrom(fullGatewayParams())
	if err != nil {
		t.Fatalf("gatewayConfigFrom: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected a gateway config for the fabric transport")
	}
	if cfg.PeerEndpoint != "localhost:7051" {
		t.Errorf("peer endpoint = %q", cfg.PeerEndpoint)
	}
	if cfg.EndorseTimeout != 30*time.Second {
		t.Errorf("endorse timeout = %v, want 30s", cfg.EndorseTimeout)
	}
	if cfg.CommitTimeout != 60*time.Second {
		t.Errorf("commit timeout = %v, want 60s", cfg.CommitTimeout)
	}
}

// TestGatewayConfigIgnoredForInProcess: the in-process transport needs no
// gateway, and demanding one would make the fast path depend on a network that
// is not being used.
func TestGatewayConfigIgnoredForInProcess(t *testing.T) {
	cfg, err := gatewayConfigFrom(map[string]any{"vote_transport": transportInProcess})
	if err != nil {
		t.Fatalf("gatewayConfigFrom: %v", err)
	}
	if cfg != nil {
		t.Errorf("in-process transport produced a gateway config")
	}
}

// TestFabricWithoutGatewayIsRefused is the guard that keeps a measurement
// honest: a config asking for network-measured votes must not silently receive
// in-process ones.
func TestFabricWithoutGatewayIsRefused(t *testing.T) {
	_, err := gatewayConfigFrom(map[string]any{"vote_transport": transportFabric})
	if err == nil {
		t.Fatal("fabric transport was accepted with no gateway settings")
	}
	if !strings.Contains(err.Error(), "no gateway configuration") {
		t.Errorf("error does not explain the cause: %v", err)
	}
}

// TestEveryGatewayFieldIsRequired covers the no-defaults rule field by field.
//
// A defaulted endpoint or channel would connect to some network and produce a
// complete, plausible set of results for a deployment nobody chose — a failure
// nothing in the output would reveal.
func TestEveryGatewayFieldIsRequired(t *testing.T) {
	fields := []string{
		"peer_endpoint", "peer_server_name", "tls_cert_path", "msp_id",
		"crypto_path", "channel", "chaincode",
		"endorse_timeout_ms", "commit_timeout_ms",
	}
	for _, f := range fields {
		t.Run("missing "+f, func(t *testing.T) {
			p := fullGatewayParams()
			delete(p["gateway"].(map[string]any), f)

			_, err := gatewayConfigFrom(p)
			if err == nil {
				t.Fatalf("gateway config accepted without %s", f)
			}
			if !strings.Contains(err.Error(), f) {
				t.Errorf("error does not name the missing field %s: %v", f, err)
			}
		})
	}
}

func TestGatewayRejectsMalformedValues(t *testing.T) {
	for _, tc := range []struct {
		name  string
		key   string
		value any
	}{
		{"empty endpoint", "peer_endpoint", ""},
		{"numeric channel", "channel", 42},
		{"zero endorse timeout", "endorse_timeout_ms", 0},
		{"negative commit timeout", "commit_timeout_ms", -1},
		{"string timeout", "endorse_timeout_ms", "30s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := fullGatewayParams()
			p["gateway"].(map[string]any)[tc.key] = tc.value
			if _, err := gatewayConfigFrom(p); err == nil {
				t.Errorf("accepted %s = %v", tc.key, tc.value)
			}
		})
	}
}

func TestGatewayRejectsNonMapping(t *testing.T) {
	p := map[string]any{"vote_transport": transportFabric, "gateway": "localhost:7051"}
	if _, err := gatewayConfigFrom(p); err == nil {
		t.Errorf("a string was accepted where a mapping is required")
	}
}

// TestNewTransportRefusesFabricWithoutGateway pins the same guard one level up,
// where Setup actually calls it.
func TestNewTransportRefusesFabricWithoutGateway(t *testing.T) {
	if _, err := newTransport(transportFabric, nil, nil); err == nil {
		t.Fatal("newTransport built a fabric transport with no gateway config")
	}
}

func TestNewTransportUnknownName(t *testing.T) {
	_, err := newTransport("grpc", nil, nil)
	if err == nil {
		t.Fatal("an unknown transport name was accepted")
	}
	// The message must name the alternatives; a bare "unknown" leaves the
	// reader guessing which spellings are valid.
	if !strings.Contains(err.Error(), transportInProcess) ||
		!strings.Contains(err.Error(), transportFabric) {
		t.Errorf("error does not list the valid transports: %v", err)
	}
}

func TestInProcessTransportStillBuilds(t *testing.T) {
	tr, err := newTransport(transportInProcess, nil, nil)
	if err != nil {
		t.Fatalf("newTransport: %v", err)
	}
	if tr.Name() != transportInProcess {
		t.Errorf("Name = %q, want %q", tr.Name(), transportInProcess)
	}
}
