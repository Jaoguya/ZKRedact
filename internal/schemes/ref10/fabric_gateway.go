package ref10

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Fabric Gateway adapter.
//
// This is the only file that touches the Fabric SDK. Everything above it —
// the voting protocol, ballot encoding, the decision each member makes — talks
// to the chaincodeSession interface and is tested against a fake.
//
// The split is not decoration. It means an SDK upgrade touches one file, and it
// means the protocol logic can be verified on a machine with no Docker, which
// is where most of the development happens.

// GatewayConfig locates the network and the identities that vote on it.
//
// Every path comes from config; none is defaulted. A wrong-but-plausible
// default here would connect to some other network and produce results for a
// topology nobody chose.
type GatewayConfig struct {
	// PeerEndpoint is host:port of the gateway peer, e.g. "localhost:7051".
	PeerEndpoint string

	// PeerServerName must match the peer's TLS certificate CN, or the handshake
	// fails with an error that reads like a network fault.
	PeerServerName string

	// TLSCertPath is the peer's TLS CA certificate.
	TLSCertPath string

	// MSPID is the organisation the voting identities belong to.
	MSPID string

	// CryptoPath is the organisation's crypto material root. Each member's
	// signing key and certificate are resolved beneath it by member id.
	CryptoPath string

	// Channel and Chaincode name the deployed contract.
	Channel   string
	Chaincode string

	// Timeouts. Endorsement and commit are separate because they fail
	// differently: endorsement failing means the peers disagree, commit failing
	// means ordering did not deliver.
	EndorseTimeout time.Duration
	CommitTimeout  time.Duration
}

// Validate reports configuration that cannot produce a connection.
func (c GatewayConfig) Validate() error {
	missing := func(field string) error {
		return fmt.Errorf("ref10: gateway config is missing %s", field)
	}
	switch {
	case c.PeerEndpoint == "":
		return missing("peer_endpoint")
	case c.PeerServerName == "":
		return missing("peer_server_name")
	case c.TLSCertPath == "":
		return missing("tls_cert_path")
	case c.MSPID == "":
		return missing("msp_id")
	case c.CryptoPath == "":
		return missing("crypto_path")
	case c.Channel == "":
		return missing("channel")
	case c.Chaincode == "":
		return missing("chaincode")
	}
	if c.EndorseTimeout <= 0 || c.CommitTimeout <= 0 {
		return fmt.Errorf("ref10: gateway timeouts must be positive")
	}
	return nil
}

// gatewayFactory creates one Fabric Gateway connection per committee member.
//
// One gRPC connection is shared across identities; the Gateway client is
// per-identity because Fabric signs each transaction with the submitting
// member's key. Sharing an identity would make every ballot appear to come from
// one client, and the contract's membership check would be validating the wrong
// thing.
type gatewayFactory struct {
	cfg  GatewayConfig
	conn *grpc.ClientConn

	mu   sync.Mutex
	gws  map[string]*client.Gateway
}

// newGatewayFactory dials the peer and prepares per-identity connections.
func newGatewayFactory(cfg GatewayConfig) (*gatewayFactory, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	tlsCert, err := loadCertificate(cfg.TLSCertPath)
	if err != nil {
		return nil, fmt.Errorf("ref10: peer TLS certificate: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(tlsCert)

	conn, err := grpc.NewClient(
		cfg.PeerEndpoint,
		grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(pool, cfg.PeerServerName)),
	)
	if err != nil {
		return nil, fmt.Errorf("ref10: dial peer %s: %w", cfg.PeerEndpoint, err)
	}

	return &gatewayFactory{
		cfg:  cfg,
		conn: conn,
		gws:  make(map[string]*client.Gateway),
	}, nil
}

// Session returns a chaincodeSession bound to one member's identity.
func (f *gatewayFactory) Session(memberID string) (chaincodeSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	gw, ok := f.gws[memberID]
	if !ok {
		id, sign, err := f.identityFor(memberID)
		if err != nil {
			return nil, err
		}
		gw, err = client.Connect(
			id,
			client.WithSign(sign),
			client.WithClientConnection(f.conn),
			client.WithEvaluateTimeout(f.cfg.EndorseTimeout),
			client.WithEndorseTimeout(f.cfg.EndorseTimeout),
			client.WithSubmitTimeout(f.cfg.EndorseTimeout),
			client.WithCommitStatusTimeout(f.cfg.CommitTimeout),
		)
		if err != nil {
			return nil, fmt.Errorf("ref10: connect gateway for %s: %w", memberID, err)
		}
		f.gws[memberID] = gw
	}

	contract := gw.GetNetwork(f.cfg.Channel).GetContract(f.cfg.Chaincode)
	return &gatewaySession{member: memberID, contract: contract}, nil
}

// identityFor loads a member's certificate and signing key.
//
// Layout follows Fabric's cryptogen output:
//
//	<CryptoPath>/users/<memberID>@<org>/msp/signcerts/*.pem
//	<CryptoPath>/users/<memberID>@<org>/msp/keystore/*
func (f *gatewayFactory) identityFor(memberID string) (*identity.X509Identity, identity.Sign, error) {
	base := filepath.Join(f.cfg.CryptoPath, "users", memberID, "msp")

	certPath, err := firstFileIn(filepath.Join(base, "signcerts"))
	if err != nil {
		return nil, nil, fmt.Errorf("ref10: signing certificate for %s: %w", memberID, err)
	}
	cert, err := loadCertificate(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("ref10: certificate for %s: %w", memberID, err)
	}
	id, err := identity.NewX509Identity(f.cfg.MSPID, cert)
	if err != nil {
		return nil, nil, fmt.Errorf("ref10: identity for %s: %w", memberID, err)
	}

	keyPath, err := firstFileIn(filepath.Join(base, "keystore"))
	if err != nil {
		return nil, nil, fmt.Errorf("ref10: signing key for %s: %w", memberID, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("ref10: read signing key for %s: %w", memberID, err)
	}
	privateKey, err := identity.PrivateKeyFromPEM(keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("ref10: parse signing key for %s: %w", memberID, err)
	}
	sign, err := identity.NewPrivateKeySign(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("ref10: signer for %s: %w", memberID, err)
	}
	return id, sign, nil
}

// Close releases every gateway and the shared connection.
func (f *gatewayFactory) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	for _, gw := range f.gws {
		gw.Close()
	}
	f.gws = make(map[string]*client.Gateway)

	if f.conn != nil {
		return f.conn.Close()
	}
	return nil
}

// gatewaySession is one member's handle on the redaction contract.
type gatewaySession struct {
	member   string
	contract *client.Contract
}

// Evaluate runs a read-only function on the gateway peer. No ordering.
func (s *gatewaySession) Evaluate(ctx context.Context, fn string, args ...string) ([]byte, error) {
	out, err := s.contract.EvaluateWithContext(ctx, fn, client.WithArguments(args...))
	if err != nil {
		return nil, fmt.Errorf("ref10: evaluate %s as %s: %w", fn, s.member, err)
	}
	return out, nil
}

// Submit endorses, orders and waits for commit.
//
// This is where the network cost Exp 1 measures actually lives. It must never
// be routed through Evaluate as an optimisation: that would skip endorsement
// and ordering, and silently restore the in-process lower bound while still
// reporting the fabric transport in results.
func (s *gatewaySession) Submit(ctx context.Context, fn string, args ...string) ([]byte, error) {
	out, err := s.contract.SubmitWithContext(ctx, fn, client.WithArguments(args...))
	if err != nil {
		return nil, fmt.Errorf("ref10: submit %s as %s: %w", fn, s.member, err)
	}
	return out, nil
}

func (s *gatewaySession) Close() error { return nil } // gateways are closed by the factory

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func loadCertificate(path string) (*x509.Certificate, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return identity.CertificateFromPEM(pem)
}

// firstFileIn returns the single file in a directory.
//
// Fabric's crypto material puts exactly one certificate in signcerts and one
// key in keystore, under generated names. More than one means the material was
// regenerated without clearing the old files, and picking arbitrarily would
// produce an identity mismatch that surfaces as an authorization failure rather
// than a configuration error.
func firstFileIn(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	switch len(files) {
	case 0:
		return "", fmt.Errorf("no file in %s", dir)
	case 1:
		return files[0], nil
	default:
		return "", fmt.Errorf(
			"%d files in %s, expected exactly one; stale crypto material would bind "+
				"the wrong identity and fail as an authorization error", len(files), dir)
	}
}

// ErrGatewayUnconfigured reports a fabric transport requested without gateway
// settings.
var ErrGatewayUnconfigured = errors.New(
	"ref10: vote_transport is fabric but no gateway configuration was supplied")
