package controldef

import (
	"cmp"
	"slices"

	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
)

// Catalog provides indexed access to a set of control definitions.
// Controls are sorted by ID for deterministic iteration.
type Catalog struct {
	controls []ControlDefinition
}

// NewCatalog constructs a catalog from a slice of controls.
// Controls are sorted by ID for deterministic iteration.
func NewCatalog(controls []ControlDefinition) *Catalog {
	sorted := slices.Clone(controls)
	slices.SortFunc(sorted, func(a, b ControlDefinition) int {
		return cmp.Compare(a.ID, b.ID)
	})
	return &Catalog{controls: sorted}
}

// List returns all controls in sorted order.
func (c *Catalog) List() []ControlDefinition {
	if c == nil {
		return nil
	}
	return c.controls
}

// Len returns the number of controls.
func (c *Catalog) Len() int {
	if c == nil {
		return 0
	}
	return len(c.controls)
}

// PackHash returns a deterministic digest of the control IDs in this catalog.
func (c *Catalog) PackHash(h ports.Digester) kernel.Digest {
	if c == nil || len(c.controls) == 0 || h == nil {
		return ""
	}
	ids := make([]string, len(c.controls))
	for i := range c.controls {
		ids[i] = string(c.controls[i].ID)
	}
	// Controls are already sorted by ID, so no additional sort needed.
	return h.Digest(ids, '\n')
}
