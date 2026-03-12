package trace

import (
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/policy"
)

// Builder implements evaluation.FindingTraceBuilder using the trace engine
// with an injected predicate parser.
type Builder struct {
	predicateParser func(any) (*policy.UnsafePredicate, error)
}

// NewFindingTraceBuilder creates a Builder that satisfies the
// evaluation.FindingTraceBuilder interface. Suitable for injection into
// the service layer from the cmd layer.
func NewFindingTraceBuilder(
	predicateParser func(any) (*policy.UnsafePredicate, error),
) *Builder {
	return &Builder{predicateParser: predicateParser}
}

// BuildTrace builds a predicate evaluation trace for the given request.
func (b *Builder) BuildTrace(req evaluation.TraceRequest) *evaluation.FindingTrace {
	if req.Control == nil {
		return nil
	}

	found, snapshot := findAssetInSnapshots(req.AssetID, req.Snapshots, req.TargetTime)
	if found == nil || snapshot == nil {
		return nil
	}

	ctx := policy.NewAssetEvalContext(*found, policy.ControlParams(req.Control.Params), snapshot.Identities...)
	ctx.PredicateParser = b.predicateParser
	root := TracePredicate(req.Control.UnsafePredicate, ctx)
	tr := &TraceResult{
		ControlID:   req.Control.ID,
		AssetID:     found.ID,
		Properties:  found.Properties,
		Params:      req.Control.Params,
		Root:        root,
		FinalResult: root.Result,
	}
	return &evaluation.FindingTrace{
		Raw:         tr,
		FinalResult: root.Result,
	}
}

// findAssetInSnapshots locates an asset in the loaded snapshots,
// preferring the snapshot at targetTime. Uses a single pass: returns
// immediately on an exact time match, otherwise keeps the first (fallback)
// asset found while scanning.
func findAssetInSnapshots(
	assetID asset.ID,
	snapshots []asset.Snapshot,
	targetTime time.Time,
) (*asset.Asset, *asset.Snapshot) {
	var fallbackAsset *asset.Asset
	var fallbackSnap *asset.Snapshot

	idStr := assetID.String()
	for i := range snapshots {
		found := snapshots[i].FindAsset(idStr)
		if found == nil {
			continue
		}
		if !targetTime.IsZero() && snapshots[i].CapturedAt.Equal(targetTime) {
			return found, &snapshots[i]
		}
		if fallbackAsset == nil {
			fallbackAsset = found
			fallbackSnap = &snapshots[i]
		}
	}
	return fallbackAsset, fallbackSnap
}
