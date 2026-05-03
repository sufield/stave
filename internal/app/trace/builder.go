package apptrace

import (
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/predicate"
)

// Builder implements evaluation.FindingTraceBuilder by delegating
// the predicate-trace step to an injected predicate.Tracer (the
// cel adapter in production). The asset-locating logic is
// vendor-neutral and stays here.
type Builder struct {
	Tracer predicate.Tracer
}

// BuildTrace builds a predicate-evaluation trace for the given
// request. Returns nil when the request is missing fields, when
// the asset cannot be located, or when no tracer is wired —
// callers fall through to a synthetic trace.
func (b *Builder) BuildTrace(req evaluation.TraceRequest) *evaluation.FindingTrace {
	if req.Control == nil || b == nil || b.Tracer == nil {
		return nil
	}

	found, snapshot := findAssetInSnapshots(req.AssetID, req.Snapshots, req.TargetTime)
	if found == nil {
		return nil
	}

	renderer, passed, _ := b.Tracer.BuildTrace(req.Control, found, snapshot)
	if renderer == nil {
		return nil
	}
	return &evaluation.FindingTrace{
		Raw:         renderer,
		FinalResult: passed,
	}
}

// findAssetInSnapshots locates an asset in the loaded snapshots,
// preferring the snapshot at targetTime.
func findAssetInSnapshots(
	assetID asset.ID,
	snapshots []asset.Snapshot,
	targetTime time.Time,
) (*asset.Asset, *asset.Snapshot) {
	var fallbackAsset *asset.Asset
	var fallbackSnap *asset.Snapshot

	idStr := assetID.String()
	for i := range snapshots {
		if found, ok := snapshots[i].FindAsset(idStr); ok {
			if !targetTime.IsZero() && snapshots[i].CapturedAt.Equal(targetTime) {
				return &found, &snapshots[i]
			}
			if fallbackAsset == nil {
				fb := found
				fallbackAsset = &fb
				fallbackSnap = &snapshots[i]
			}
		}
	}
	return fallbackAsset, fallbackSnap
}
