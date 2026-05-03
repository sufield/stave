package trace

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/predicate"
)

// TraceRequest defines the context required to perform a logic audit on
// a specific security policy evaluation.
type TraceRequest struct {
	Control    policy.ControlDefinition
	Snapshot   *asset.Snapshot
	TargetID   string
	SourcePath string
}

// PolicyTracer provides deep explainability for security control
// evaluations. The Tracer field is the predicate-engine
// implementation that builds the underlying trace; cmd composition
// wires the cel adapter so this package never imports it.
type PolicyTracer struct {
	Tracer predicate.Tracer
}

// ErrTracerNotWired is returned when Trace is called on a
// PolicyTracer whose Tracer field is nil. Surfaces the missing
// wiring at the composition boundary instead of silently returning
// a nil result.
var ErrTracerNotWired = errors.New("trace: PolicyTracer.Tracer is nil; wire a contracts.Tracer at composition")

// Trace executes the logic audit for a single resource and returns
// the underlying trace renderer (text or JSON). Returning
// evaluation.TraceRenderer keeps the signature vendor-neutral —
// cmd-layer callers only need the rendering surface.
func (t *PolicyTracer) Trace(req *TraceRequest) (evaluation.TraceRenderer, error) {
	if t == nil || t.Tracer == nil {
		return nil, ErrTracerNotWired
	}
	resource, err := LocateResource(req.Snapshot, asset.ID(req.TargetID), req.SourcePath)
	if err != nil {
		return nil, err
	}

	renderer, _, err := t.Tracer.BuildTrace(&req.Control, resource, req.Snapshot)
	if err != nil {
		return nil, fmt.Errorf("trace: build trace for %s: %w", req.TargetID, err)
	}
	if renderer == nil {
		return nil, fmt.Errorf("trace: engine failed to produce a logic audit for %s", req.TargetID)
	}
	return renderer, nil
}

// LocateResource finds a cloud asset by its unique ID within an observation snapshot.
func LocateResource(snapshot *asset.Snapshot, id asset.ID, source string) (*asset.Asset, error) {
	for i := range snapshot.Assets {
		if snapshot.Assets[i].ID == id {
			return &snapshot.Assets[i], nil
		}
	}
	available := make([]string, 0, len(snapshot.Assets))
	for _, a := range snapshot.Assets {
		available = append(available, a.ID.String())
	}
	slices.Sort(available)
	return nil, fmt.Errorf("resource %q not found in observations %s\nAvailable IDs: %s",
		id, source, strings.Join(available, ", "))
}
