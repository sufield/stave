package predicate

import (
	"io"

	"github.com/sufield/stave/internal/core/asset"
)

// Renderer is the rendering surface a predicate-trace value
// exposes to callers. Defined here (rather than in
// internal/core/evaluation) so adapters that implement Tracer
// stay leaf-imports — importing core/evaluation transitively
// pulls core/evaluation/risk, which would create a cycle when a
// risk-package test wires a real CEL evaluator.
//
// Any type satisfying this interface also satisfies
// internal/core/evaluation.TraceRenderer (Go interfaces are
// structural), so values produced via the contract assign cleanly
// into *evaluation.FindingTrace.Raw at the app boundary.
type Renderer interface {
	RenderText(io.Writer) error
	RenderJSON(io.Writer) error
}

// Tracer abstracts the predicate-trace step: given a control, a
// resolved asset, and the snapshot context, produce a renderable
// trace plus the boolean evaluation outcome. The CEL
// implementation lives in internal/adapters/cel.Tracer; future
// predicate engines implement the same contract.
//
// ctl is `any` rather than *controldef.ControlDefinition because
// core/controldef already imports core/predicate — using the
// concrete type here would create a controldef → predicate →
// controldef cycle. Implementations type-assert to the concrete
// control shape they expect.
type Tracer interface {
	BuildTrace(ctl any, a *asset.Asset, snap *asset.Snapshot) (renderer Renderer, passed bool, err error)
}
