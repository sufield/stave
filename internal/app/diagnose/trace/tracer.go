package trace

import (
	"fmt"
	"slices"
	"strings"

	stavecel "github.com/sufield/stave/internal/cel"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// TraceRequest defines the context required to perform a logic audit on
// a specific security policy evaluation.
type TraceRequest struct {
	Control    policy.ControlDefinition
	Snapshot   *asset.Snapshot
	TargetID   string
	SourcePath string
}

// PolicyTracer provides deep explainability for security control evaluations.
type PolicyTracer struct{}

// Trace executes the logic audit for a single resource and returns
// a step-by-step breakdown of the evaluation logic.
func (t *PolicyTracer) Trace(req TraceRequest) (*stavecel.TraceResult, error) {
	resource, err := LocateResource(req.Snapshot, asset.ID(req.TargetID), req.SourcePath)
	if err != nil {
		return nil, err
	}

	result := stavecel.BuildTrace(&req.Control, resource, req.Snapshot)
	if result == nil {
		return nil, fmt.Errorf("trace: engine failed to produce a logic audit for %s", req.TargetID)
	}
	return result, nil
}

// LocateResource finds a cloud asset by its unique ID within an inventory snapshot.
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
	return nil, fmt.Errorf("resource %q not found in inventory %s\nAvailable IDs: %s",
		id, source, strings.Join(available, ", "))
}
