package hipaa

import (
	"fmt"
	"slices"
)

// Registry holds controls indexed by their unique ID.
// It is not safe for concurrent use during registration; register
// all controls during init before concurrent Evaluate calls.
type Registry struct {
	controls map[string]Control
	order    []string // insertion order for deterministic iteration
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		controls: make(map[string]Control),
	}
}

// Register adds an control to the registry. Returns an error if an
// control with the same ID is already registered.
func (r *Registry) Register(inv Control) error {
	id := inv.ID()
	if _, exists := r.controls[id]; exists {
		return fmt.Errorf("control %q already registered", id)
	}
	r.controls[id] = inv
	r.order = append(r.order, id)
	return nil
}

// MustRegister calls Register and panics on error. Use during init.
func (r *Registry) MustRegister(inv Control) {
	if err := r.Register(inv); err != nil {
		panic(err)
	}
}

// Lookup returns the control with the given ID, or nil if not found.
func (r *Registry) Lookup(id string) Control {
	return r.controls[id]
}

// All returns all registered controls in registration order.
func (r *Registry) All() []Control {
	out := make([]Control, len(r.order))
	for i, id := range r.order {
		out[i] = r.controls[id]
	}
	return out
}

// ByProfile returns all controls that declare membership in the given
// compliance profile, in registration order.
func (r *Registry) ByProfile(profile string) []Control {
	var out []Control
	for _, id := range r.order {
		ctrl := r.controls[id]
		if slices.Contains(ctrl.ComplianceProfiles(), profile) {
			out = append(out, ctrl)
		}
	}
	return out
}

// Len returns the number of registered controls.
func (r *Registry) Len() int {
	return len(r.controls)
}

// ControlRegistry is the single registry for all HIPAA controls.
var ControlRegistry = NewRegistry()
