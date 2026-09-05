package ref10

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Registering the node set, and mapping harness members onto Fabric identities.
//
// Two things have to line up before a single networked vote can succeed, and
// neither fails in a way that names itself:
//
//   - The contract computes N_auth from a node set it holds. Without
//     RegisterNodes it has none, and Init fails with "no nodes registered" —
//     which reads as a chaincode problem rather than a missing setup step.
//
//   - The harness names members id-000000, id-000001, …; cryptogen names Fabric
//     identities User1@org1.example.com, User2@org1.example.com, …. A member
//     whose name does not resolve to crypto material fails at vote time with a
//     file-not-found, deep inside the SDK, on a path nobody configured.
//
// Both are handled here, at Setup, where the failure can still say what is
// wrong.

// identityMap resolves a harness member id to a Fabric identity directory.
type identityMap struct {
	// byMember maps id-000000 -> User1@org1.example.com
	byMember map[string]string
}

// buildIdentityMap pairs harness members with the Fabric identities on disk.
//
// The pairing is by sorted position, which is stable across runs given the same
// crypto material and the same dataset — the reproducibility rule applies to
// this as much as to anything else.
//
// Fails when there are fewer Fabric identities than members rather than mapping
// what it can. A partial map produces a network run in which some committees
// can vote and others cannot, and the difference shows up as a variable
// approval rate that looks like a property of the protocol.
func buildIdentityMap(cryptoPath string, memberIDs []string) (*identityMap, error) {
	usersDir := filepath.Join(cryptoPath, "users")
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		return nil, fmt.Errorf(
			"ref10: cannot read Fabric identities at %s: %w "+
				"(bring the network up first: network/scripts/network.sh up)",
			usersDir, err)
	}

	var users []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// Admin is the org administrator, not a voting member. Including it
		// would let an identity that is not in the node set cast a ballot.
		if strings.HasPrefix(e.Name(), "Admin@") {
			continue
		}
		users = append(users, e.Name())
	}
	sort.Strings(users)

	if len(users) < len(memberIDs) {
		return nil, fmt.Errorf(
			"ref10: %d Fabric identities in %s but the dataset has %d members; "+
				"raise Users.Count in network/crypto-config-*.yaml or lower "+
				"dataset.identities.count, because a partial mapping would let some "+
				"committees vote and others not",
			len(users), usersDir, len(memberIDs))
	}

	sorted := append([]string(nil), memberIDs...)
	sort.Strings(sorted)

	m := &identityMap{byMember: make(map[string]string, len(sorted))}
	for i, id := range sorted {
		m.byMember[id] = users[i]
	}
	return m, nil
}

// resolve returns the Fabric identity directory for a member.
func (m *identityMap) resolve(memberID string) (string, error) {
	if m == nil {
		return "", fmt.Errorf("ref10: no identity map; Setup did not build one")
	}
	name, ok := m.byMember[memberID]
	if !ok {
		return "", fmt.Errorf(
			"ref10: member %s has no Fabric identity; it was not in the set Setup mapped",
			memberID)
	}
	return name, nil
}

// registerNodes publishes the node set the contract needs to compute N_auth.
//
// Called once during Setup, which is not timed. The contract recomputes the
// committee from this set rather than trusting a client-supplied list, so this
// is what makes its membership check meaningful.
func registerNodes(ctx context.Context, t transport, members []*member) error {
	ft, ok := t.(*fabricTransport)
	if !ok {
		// The in-process transport keeps the node set in memory; there is
		// nothing to publish.
		return nil
	}
	if len(members) == 0 {
		return fmt.Errorf("ref10: cannot register an empty node set")
	}

	nodesJSON, err := encodeNodes(members, nil)
	if err != nil {
		return err
	}

	// Registered under the first member's identity. Any registered client may
	// do it; using a member keeps the call inside the same identity set the
	// rest of the protocol uses.
	sess, err := ft.session(members[0].Identity.ID)
	if err != nil {
		return err
	}
	if _, err := sess.Submit(ctx, "RegisterNodes", nodesJSON); err != nil {
		return fmt.Errorf("ref10: register node set: %w", err)
	}
	return nil
}
