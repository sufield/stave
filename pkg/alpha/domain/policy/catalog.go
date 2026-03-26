package policy

import (
	"cmp"
	"slices"

	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/ports"
)

// Catalog provides indexed access to a set of control definitions.
// Controls are sorted by ID for deterministic iteration.
type Catalog struct {
	controls []ControlDefinition
	byID     map[kernel.ControlID]*ControlDefinition
}

// NewCatalog constructs a catalog from a slice of controls.
// Controls are sorted by ID; duplicates are kept (last wins in lookup).
func NewCatalog(controls []ControlDefinition) *Catalog {
	sorted := slices.Clone(controls)
	slices.SortFunc(sorted, func(a, b ControlDefinition) int {
		return cmp.Compare(a.ID, b.ID)
	})

	byID := make(map[kernel.ControlID]*ControlDefinition, len(sorted))
	for i := range sorted {
		byID[sorted[i].ID] = &sorted[i]
	}

	return &Catalog{controls: sorted, byID: byID}
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

// Get retrieves a control by ID.
func (c *Catalog) Get(id kernel.ControlID) (*ControlDefinition, bool) {
	if c == nil {
		return nil, false
	}
	ctl, ok := c.byID[id]
	return ctl, ok
}

// FindByID retrieves a control by ID, returning nil if not found.
// Satisfies the evaluation.ControlProvider interface.
func (c *Catalog) FindByID(id kernel.ControlID) *ControlDefinition {
	ctl, _ := c.Get(id)
	return ctl
}

// Filter returns controls whose ScopeTags contain at least one of the given tags.
func (c *Catalog) Filter(tags ...string) []ControlDefinition {
	if c == nil || len(tags) == 0 {
		return nil
	}
	tagSet := make(map[string]bool, len(tags))
	for _, t := range tags {
		tagSet[t] = true
	}

	var out []ControlDefinition
	for _, ctl := range c.controls {
		for _, st := range ctl.ScopeTags {
			if tagSet[st] {
				out = append(out, ctl)
				break
			}
		}
	}
	return out
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
