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

// gatewayConfigFrom extracts gateway settings whenever they are supplied.
//
// PARSED REGARDLESS OF THE CONFIGURED TRANSPORT. Exp 1 sweeps Ref[10] over
// exp1_vote_transports and calls Retransport("fabric") mid-run, which needs the
// settings Setup captured. Parsing them only when vote_transport was already
// "fabric" left gatewayCfg nil under the in-process setting, so the sweep's
// fabric arm failed with "no gateway configuration was supplied" on a config
// that carried a complete gateway block.
//
// Returns (nil, nil) only when no gateway block is present AND the transport in
// force does not need one. A fabric transport without settings is still
// refused, rather than falling back to in-process voting and reporting a lower
// bound as a measurement.
func gatewayConfigFrom(params map[string]any) (*GatewayConfig, error) {
	name, _ := params["vote_transport"].(string)

	raw, ok := params["gateway"]
	if !ok {
		if name == transportFabric {
			return nil, ErrGatewayUnconfigured
		}
		return nil, nil
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
