package ref10

import (
	"fmt"
	"time"
)

// Gateway settings arrive through scheme.SetupParams.Params, like every other
// scheme parameter, so they are subject to the same rule as the rest: nothing
// is defaulted.
//
// A defaulted endpoint or channel would connect to *some* network and produce a
// full set of results for a topology nobody chose. That failure is invisible in
// the output — the numbers are real, they just describe the wrong deployment —
// so every field is required and a missing one stops Setup.

// gatewayConfigFrom extracts gateway settings when the fabric transport is
// selected.
//
// Returns (nil, nil) for the in-process transport, which needs none.
func gatewayConfigFrom(params map[string]any) (*GatewayConfig, error) {
	name, _ := params["vote_transport"].(string)
	if name != transportFabric {
		return nil, nil
	}

	raw, ok := params["gateway"]
	if !ok {
		return nil, ErrGatewayUnconfigured
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf(
			"ref10: gateway settings have type %T, want a mapping", raw)
	}

	str := func(key string) (string, error) {
		v, ok := m[key]
		if !ok {
			return "", fmt.Errorf("ref10: gateway settings are missing %s", key)
		}
		sv, ok := v.(string)
		if !ok || sv == "" {
			return "", fmt.Errorf("ref10: gateway setting %s must be a non-empty string", key)
		}
		return sv, nil
	}

	msec := func(key string) (time.Duration, error) {
		v, ok := m[key]
		if !ok {
			return 0, fmt.Errorf("ref10: gateway settings are missing %s", key)
		}
		var ms int
		switch n := v.(type) {
		case int:
			ms = n
		case int64:
			ms = int(n)
		case float64:
			ms = int(n)
		default:
			return 0, fmt.Errorf("ref10: gateway setting %s has type %T, want a number", key, v)
		}
		if ms <= 0 {
			return 0, fmt.Errorf("ref10: gateway setting %s must be positive, got %d", key, ms)
		}
		return time.Duration(ms) * time.Millisecond, nil
	}

	var (
		cfg GatewayConfig
		err error
	)
	if cfg.PeerEndpoint, err = str("peer_endpoint"); err != nil {
		return nil, err
	}
	if cfg.PeerServerName, err = str("peer_server_name"); err != nil {
		return nil, err
	}
	if cfg.TLSCertPath, err = str("tls_cert_path"); err != nil {
		return nil, err
	}
	if cfg.MSPID, err = str("msp_id"); err != nil {
		return nil, err
	}
	if cfg.CryptoPath, err = str("crypto_path"); err != nil {
		return nil, err
	}
	if cfg.Channel, err = str("channel"); err != nil {
		return nil, err
	}
	if cfg.Chaincode, err = str("chaincode"); err != nil {
		return nil, err
	}
	if cfg.EndorseTimeout, err = msec("endorse_timeout_ms"); err != nil {
		return nil, err
	}
	if cfg.CommitTimeout, err = msec("commit_timeout_ms"); err != nil {
		return nil, err
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}
