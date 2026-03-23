package apptrace

import (
	"time"

	stavecel "github.com/sufield/stave/internal/cel"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
)

// Builder implements evaluation.FindingTraceBuilder using the CEL engine.
type Builder struct{}

// BuildTrace builds a CEL-based predicate evaluation trace for the given request.
func (b *Builder) BuildTrace(req evaluation.TraceRequest) *evaluation.FindingTrace {
	if req.Control == nil {
		return nil
	}

	found, snapshot := findAssetInSnapshots(req.AssetID, req.Snapshots, req.TargetTime)
	if found == nil {
		return nil
	}

	tr := stavecel.BuildTrace(req.Control, found, snapshot)
	if tr == nil {
		return nil
	}
	return &evaluation.FindingTrace{
		Raw:         tr,
		FinalResult: tr.Result,
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
