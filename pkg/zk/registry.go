package zk

import (
	"fmt"
)

// Registry is the credential accumulator the circuit checks membership against.
//
// It is a Merkle tree over MiMC, NOT over the SHA-256 tree in pkg/merkle. The
// hash has to be the one the circuit can recompute cheaply: a SHA-256 tree
// would cost tens of thousands of constraints per level and put the circuit's
// size somewhere that has nothing to do with the scheme's design. pkg/merkle
// stays where an ordinary authenticated structure is wanted — the PAI in
// Phase 5 — and this stays where a circuit has to verify one.
type Registry struct {
	leaves [][]byte
	layers [][][]byte // layers[0] = leaves, last = single root
	index  map[string]int
	depth  int
}

// CredentialLeaf is H(rho ‖ A), matching the circuit's leaf computation.
//
// The attributes are bound into the leaf, which is what makes the policy check
// about a specific requester rather than about any satisfying assignment.
func CredentialLeaf(credSecret []byte, attrs [NumAttributes]uint64) []byte {
	in := make([][]byte, 0, NumAttributes+1)
	in = append(in, credSecret)
	for i := 0; i < NumAttributes; i++ {
		in = append(in, Uint64Bytes(attrs[i]))
	}
	return Hash(in...)
}

// NewRegistry builds a tree of the given depth over the supplied leaves.
//
// The depth is fixed by the compiled circuit, so it is an input rather than
// something derived from the leaf count: a tree that grew a level because one
// more identity was registered would no longer verify against the circuit, and
// the failure would look like an invalid credential.
func NewRegistry(leaves [][]byte, depth int) (*Registry, error) {
	if depth < 1 {
		return nil, fmt.Errorf("zk: registry depth must be >= 1, got %d", depth)
	}
	capacity := 1 << depth
	if len(leaves) > capacity {
		return nil, fmt.Errorf(
			"zk: %d credentials do not fit a depth-%d registry (capacity %d); "+
				"recompile the circuit for the dataset's identity count",
			len(leaves), depth, capacity)
	}

	// Pad to a full tree with a fixed filler. Padding with a repeat of the last
	// real leaf would make a duplicate credential verifiable.
	padded := make([][]byte, capacity)
	filler := Hash(Uint64Bytes(0))
	idx := make(map[string]int, len(leaves))
	for i := range padded {
		if i < len(leaves) {
			padded[i] = leaves[i]
			idx[string(leaves[i])] = i
		} else {
			padded[i] = filler
		}
	}

	layers := [][][]byte{padded}
	cur := padded
	for len(cur) > 1 {
		next := make([][]byte, len(cur)/2)
		for i := 0; i < len(next); i++ {
			next[i] = Hash(cur[2*i], cur[2*i+1])
		}
		layers = append(layers, next)
		cur = next
	}

	return &Registry{leaves: leaves, layers: layers, index: idx, depth: depth}, nil
}

// Root is the public anchor the circuit checks against.
func (r *Registry) Root() []byte { return r.layers[len(r.layers)-1][0] }

// Depth returns the tree depth.
func (r *Registry) Depth() int { return r.depth }

// Path returns the authentication path for a leaf.
//
// bits[i] is 1 when the sibling is on the LEFT, matching the circuit's
// api.Select ordering. Getting this backwards produces a root mismatch that
// reads as a forged credential rather than as an encoding error, so the
// convention is stated here and pinned by TestPathBitOrderMatchesCircuit.
func (r *Registry) Path(leaf []byte) (elements [][]byte, bits []uint64, err error) {
	i, ok := r.index[string(leaf)]
	if !ok {
		return nil, nil, fmt.Errorf("zk: leaf is not in the registry")
	}

	elements = make([][]byte, r.depth)
	bits = make([]uint64, r.depth)
	for level := 0; level < r.depth; level++ {
		sibling := i ^ 1
		elements[level] = r.layers[level][sibling]
		// i even -> sibling on the right -> bit 0.
		bits[level] = uint64(i & 1)
		i /= 2
	}
	return elements, bits, nil
}

// TreeDepthFor returns the smallest depth holding n credentials.
func TreeDepthFor(n int) int {
	d := 1
	for (1 << d) < n {
		d++
	}
	return d
}
