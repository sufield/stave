package compliance

import (
	"fmt"
	"slices"
	"sync"

	"github.com/sufield/stave/internal/core/kernel"
)

// ControlCatalog holds controls indexed by their unique ID.
// It is not safe for concurrent use during registration; register
// all controls during init before concurrent Evaluate calls.
type ControlCatalog struct {
	controls map[kernel.ControlID]Control
	order    []kernel.ControlID // insertion order for deterministic iteration
}

// NewRegistry returns an empty ControlCatalog.
func NewRegistry() *ControlCatalog {
	return &ControlCatalog{
		controls: make(map[kernel.ControlID]Control),
	}
}

// Register adds an control to the registry. Returns an error if an
// control with the same ID is already registered.
func (r *ControlCatalog) Register(ctl Control) error {
	id := ctl.Def().ID()
	if _, exists := r.controls[id]; exists {
		return fmt.Errorf("control %q already registered", id)
	}
	r.controls[id] = ctl
	r.order = append(r.order, id)
	return nil
}

// MustRegister calls Register and panics on error. Use during init.
func (r *ControlCatalog) MustRegister(ctl Control) {
	if err := r.Register(ctl); err != nil {
		panic(err)
	}
}

// Lookup returns the control with the given ID, or nil if not found.
func (r *ControlCatalog) Lookup(id kernel.ControlID) Control {
	return r.controls[id]
}

// All returns all registered controls in registration order.
func (r *ControlCatalog) All() []Control {
	out := make([]Control, len(r.order))
	for i, id := range r.order {
		out[i] = r.controls[id]
	}
	return out
}

// ByProfile returns all controls that declare membership in the given
// compliance profile, in registration order.
func (r *ControlCatalog) ByProfile(profile string) []Control {
	var out []Control
	for _, id := range r.order {
		ctrl := r.controls[id]
		if slices.Contains(ctrl.Def().ComplianceProfiles(), profile) {
			out = append(out, ctrl)
		}
	}
	return out
}

// Len returns the number of registered controls.
func (r *ControlCatalog) Len() int {
	return len(r.controls)
}

// controlRegistry is the default global registry, populated by init()
// functions in each control implementation file. Production code reaches it
// via GetControlRegistry() — the variable itself is unexported so a
// consumer cannot reseat it.
var (
	controlRegistry     = NewRegistry()
	controlRegistryOnce sync.Once
)

// GetControlRegistry returns the singleton control catalog. The first
// call ensures the catalog has had every package init() chance to
// register; the sync.Once is defensive only — register-on-init is
// already complete by the time main runs — but it documents the
// "initialise once" contract.
func GetControlRegistry() *ControlCatalog {
	controlRegistryOnce.Do(func() {
		// init() functions ran before main. The Once just locks
		// the entry-state contract.
	})
	return controlRegistry
}

// allControlConstructors holds factory functions for every built-in control.
// Populated by RegisterControl() calls in init() — the source of truth
// that both the global controlRegistry and NewTestCatalog() draw from.
var allControlConstructors []func() Control

// RegisterControl records a control factory and registers it in the global
// control registry. Called from init() in each control file.
func RegisterControl(factory func() Control) {
	allControlConstructors = append(allControlConstructors, factory)
	controlRegistry.MustRegister(factory())
}

// NewTestCatalog creates an isolated ControlCatalog with all built-in controls.
// Each call produces a fresh catalog — safe for parallel tests.
func NewTestCatalog() *ControlCatalog {
	cat := NewRegistry()
	for i := range allControlConstructors {
		cat.MustRegister(allControlConstructors[i]())
	}
	return cat
}

// NewCatalogWith creates a ControlCatalog containing only the specified controls.
// Use in tests that need a focused subset for isolated evaluation.
func NewCatalogWith(controls ...Control) *ControlCatalog {
	cat := NewRegistry()
	for _, ctl := range controls {
		cat.MustRegister(ctl)
	}
	return cat
}
