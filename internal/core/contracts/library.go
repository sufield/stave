package contracts

import "github.com/sufield/stave/internal/core/kernel"

// PolicyPack describes a curated collection of pre-defined security
// controls. Mirrors the wire format of internal/builtin/pack.Pack
// but lives here so app code can hold pack values without importing
// the pack adapter directly.
type PolicyPack struct {
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Controls    []kernel.ControlID `json:"controls"`
}

// PolicyLibrary exposes the embedded policy-pack registry to app
// code via a vendor-neutral contract. The production
// implementation lives in internal/builtin/pack (an embedded
// YAML index); cmd composition wires the concrete adapter at
// startup. Decoupling the contract from the concrete type lets
// app/capabilities and app/artifacts hold pack metadata without
// importing internal/builtin.
type PolicyLibrary interface {
	// ListPacks returns every pack in the library, in stable
	// order. Errors signal an embedded-data invariant violation —
	// loaders typically panic at construction, so callers may
	// treat a non-nil error as a fatal bug.
	ListPacks() ([]PolicyPack, error)

	// LookupPack returns the pack with the given name. The bool
	// is false when the pack is not present.
	LookupPack(name string) (PolicyPack, bool)

	// PackNames returns the sorted list of known pack names.
	// Convenience for error messages enumerating available
	// options when LookupPack misses.
	PackNames() []string
}
