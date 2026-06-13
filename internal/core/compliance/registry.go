package compliance

import (
	"fmt"
	"slices"

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

// controlRegistrar is the package-level control-registration state: the live
// catalog plus the factory functions that populated it (replayed by
// NewTestCatalog to build isolated test catalogs). RegisterControl — called
// from each control file's init() — feeds both. Registration is init-time only
// and not concurrency-safe by contract, so no lock is needed.
type controlRegistrar struct {
	catalog      *ControlCatalog
	constructors []ControlFactory
}

// register records a factory and registers its product in the live catalog.
func (r *controlRegistrar) register(factory ControlFactory) {
	r.constructors = append(r.constructors, factory)
	r.catalog.MustRegister(factory())
}

// registrar is the process-wide control-registration state — one cohesive
// value replacing a singleton catalog, a parallel factory slice, and a
// defensive sync.Once whose Do body was empty.
var registrar = &controlRegistrar{catalog: NewRegistry()}

// GetControlRegistry returns the singleton control catalog. Every control
// package's init() has registered by the time main runs, so the catalog is
// fully populated; this simply returns it. The variable is unexported so a
// consumer cannot reseat it.
func GetControlRegistry() *ControlCatalog {
	return registrar.catalog
}

// ControlFactory constructs a fresh Control instance. Named so the
// factory-of-X pattern stays self-documenting at every call site —
// the prior anonymous func() Control type required a comment to
// explain what the function returned.
type ControlFactory func() Control

// RegisterControl records a control factory and registers its product in the
// global control catalog. Called from init() in each control file.
func RegisterControl(factory ControlFactory) {
	registrar.register(factory)
}

// NewTestCatalog creates an isolated ControlCatalog with all built-in controls.
// Each call produces a fresh catalog — safe for parallel tests.
func NewTestCatalog() *ControlCatalog {
	cat := NewRegistry()
	for i := range registrar.constructors {
		cat.MustRegister(registrar.constructors[i]())
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
