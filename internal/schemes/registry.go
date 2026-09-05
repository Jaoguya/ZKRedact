// Package schemes wires the systems under test into one registry.
//
// The registry exists so experiments select schemes by name from
// config/experiment.yaml rather than importing them directly. An experiment
// that hardcoded a scheme could quietly drift into treating one system
// differently from the rest, which is the failure this whole layer prevents.
package schemes

import (
	"fmt"
	"sort"

	"zkredact/internal/schemes/ref10"
	"zkredact/internal/schemes/ref13"
	"zkredact/internal/schemes/ref22"
	"zkredact/internal/schemes/zkredact"
	"zkredact/pkg/scheme"
)

// Constructor builds a fresh, unconfigured scheme instance.
type Constructor func() scheme.Scheme

// registry maps the config key of each system to its constructor. Keys must
// match the strings used in experiments.*.systems.
var registry = map[string]Constructor{
	"zkredact":   func() scheme.Scheme { return zkredact.New() },
	"ref10_emt":  func() scheme.Scheme { return ref10.New() },
	"ref13_vrbc": func() scheme.Scheme { return ref13.New() },
	"ref22_shen": func() scheme.Scheme { return ref22.New() },
}

// New constructs the named scheme.
func New(name string) (scheme.Scheme, error) {
	ctor, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown scheme %q (known: %v)", name, Names())
	}
	return ctor(), nil
}

// NewAll constructs every named scheme, preserving order.
//
// It fails on the first unknown name rather than skipping it. A comparison
// silently missing a system is worse than one that refuses to start.
func NewAll(names []string) ([]scheme.Scheme, error) {
	out := make([]scheme.Scheme, 0, len(names))
	for _, n := range names {
		s, err := New(n)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// Names lists registered scheme keys in sorted order.
func Names() []string {
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// CapabilityMatrix reports the capabilities of every named scheme.
//
// The paper's capability matrix is generated from this rather than written by
// hand, so it cannot drift from what the implementations actually provide. That
// matters most for Exp 1, where two baselines outperform ZK-Redact precisely
// because they do less — a table of timings without this context misrepresents
// every scheme in it.
func CapabilityMatrix(names []string) (map[string]scheme.Capabilities, error) {
	out := make(map[string]scheme.Capabilities, len(names))
	for _, n := range names {
		s, err := New(n)
		if err != nil {
			return nil, err
		}
		out[n] = s.Capabilities()
	}
	return out, nil
}
