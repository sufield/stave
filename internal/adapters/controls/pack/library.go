package pack

import (
	"github.com/sufield/stave/internal/app/contracts"
)

// Library wraps an *Index to satisfy the
// app/contracts.PolicyLibrary interface. Constructed via
// NewLibrary at the cmd composition layer and injected into
// app-layer types (app/capabilities.Manifest,
// app/artifacts.PolicyInspector) so they hold pack metadata
// through the contract instead of the concrete *Index type.
type Library struct {
	idx *Index
}

// NewLibrary loads the embedded policy-pack registry and returns
// a Library wrapper. Errors propagate the embedded-YAML parse
// failure path from NewEmbeddedRegistry; production callers
// typically Fatal on error since the index is built at compile
// time.
func NewLibrary() (*Library, error) {
	idx, err := NewEmbeddedRegistry()
	if err != nil {
		return nil, err
	}
	return &Library{idx: idx}, nil
}

// ListPacks returns every pack in stable order, projected into
// the contract's PolicyPack value type.
func (l *Library) ListPacks() ([]contracts.PolicyPack, error) {
	src, err := l.idx.ListPacks()
	if err != nil {
		return nil, err
	}
	out := make([]contracts.PolicyPack, len(src))
	for i, p := range src {
		out[i] = toContractPack(p)
	}
	return out, nil
}

// LookupPack returns the pack with the given name, projected.
func (l *Library) LookupPack(name string) (contracts.PolicyPack, bool) {
	p, ok := l.idx.LookupPack(name)
	if !ok {
		return contracts.PolicyPack{}, false
	}
	return toContractPack(p), true
}

// PackNames returns the sorted list of known pack names.
func (l *Library) PackNames() []string {
	return l.idx.PackNames()
}

func toContractPack(p Pack) contracts.PolicyPack {
	return contracts.PolicyPack{
		Name:        p.Name,
		Description: p.Description,
		Controls:    p.Controls,
	}
}
