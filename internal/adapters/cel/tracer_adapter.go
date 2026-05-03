package cel

import (
	"errors"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/predicate"
)

// ErrTracerControlType is returned by Tracer.BuildTrace when the
// `any`-typed ctl parameter is not a *policy.ControlDefinition.
// The interface uses `any` because core/controldef already imports
// core/predicate — naming *ControlDefinition in the interface
// would create a controldef → predicate → controldef cycle. The
// type assertion is the implementation's responsibility.
var ErrTracerControlType = errors.New("cel.Tracer: ctl must be *controldef.ControlDefinition")

// Tracer adapts the package-level BuildTrace into the
// core/predicate.Tracer interface. Constructed as `cel.Tracer{}`
// at the cmd composition layer and injected into apptrace.Builder
// / diagnose/trace.PolicyTracer so the app layer never imports
// this package directly.
type Tracer struct{}

// BuildTrace runs the CEL trace builder and returns the renderer
// plus the boolean evaluation outcome. ctl must be a
// *controldef.ControlDefinition; other types yield
// ErrTracerControlType. When BuildTrace returns nil with no error
// (compiler-init failure under contract guard), this adapter
// returns (nil, false, nil) so callers can fall through to a
// synthetic trace. When BuildTrace returns nil with an error, the
// adapter wraps the error string in a minimal TraceResult so the
// trace surface still renders.
func (Tracer) BuildTrace(
	ctl any,
	a *asset.Asset,
	snap *asset.Snapshot,
) (predicate.Renderer, bool, error) {
	control, ok := ctl.(*policy.ControlDefinition)
	if !ok {
		return nil, false, ErrTracerControlType
	}
	tr, err := BuildTrace(control, a, snap)
	if tr != nil {
		// Propagate err alongside the partial trace — BuildTrace can
		// return a populated trace AND an evaluation error (e.g. a
		// soft-fail clause); swallowing it hides the failure from
		// callers that decide whether to gate on errors.
		return tr, tr.Result, err
	}
	if err != nil {
		return &TraceResult{Error: err.Error()}, false, err
	}
	return nil, false, nil
}
