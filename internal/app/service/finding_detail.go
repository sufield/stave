package service

import (
	"sort"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/trace"
)

// FindingDetailInput holds everything needed to build a FindingDetail.
type FindingDetailInput struct {
	ControlID       kernel.ControlID
	AssetID         asset.ID
	Controls        policy.ControlDefinitions
	Snapshots       []asset.Snapshot
	Result          *evaluation.Result
	PredicateParser func(any) (*policy.UnsafePredicate, error)
}

// BuildFindingDetail delegates to the Result aggregate, injecting the
// trace builder that depends on the infrastructure trace package.
func BuildFindingDetail(input FindingDetailInput) (*evaluation.FindingDetail, error) {
	traceBuilder := func(
		ctl *policy.ControlDefinition,
		assetID asset.ID,
		snapshots []asset.Snapshot,
		lastSeenUnsafeAt time.Time,
	) *evaluation.FindingTrace {
		return buildFindingTrace(ctl, assetID, snapshots, lastSeenUnsafeAt, input.PredicateParser)
	}
	return remediation.BuildFindingDetail(input.Result, evaluation.FindingDetailRequest{
		ControlID:    input.ControlID,
		AssetID:      input.AssetID,
		Controls:     input.Controls,
		Snapshots:    input.Snapshots,
		TraceBuilder: traceBuilder,
	})
}

func buildFindingTrace(
	ctl *policy.ControlDefinition,
	assetID asset.ID,
	snapshots []asset.Snapshot,
	lastSeenUnsafeAt time.Time,
	predicateParser func(any) (*policy.UnsafePredicate, error),
) *evaluation.FindingTrace {
	if ctl == nil {
		return nil
	}

	found, snapshot := findAssetInSnapshots(assetID, snapshots, lastSeenUnsafeAt)
	if found == nil || snapshot == nil {
		return nil
	}

	ctx := policy.NewAssetEvalContextWithIdentities(*found, policy.ControlParams(ctl.Params), snapshot.Identities)
	ctx.PredicateParser = predicateParser
	root := trace.TracePredicate(ctl.UnsafePredicate, ctx)
	tr := &trace.TraceResult{
		ControlID:   ctl.ID,
		AssetID:     found.ID,
		Properties:  found.Properties,
		Params:      ctl.Params,
		Root:        root,
		FinalResult: root.Result,
	}
	return &evaluation.FindingTrace{
		Raw:         tr,
		FinalResult: root.Result,
	}
}

// findAssetInSnapshots locates an asset in the loaded snapshots,
// preferring the snapshot closest to targetTime. Returns nil if not found.
func findAssetInSnapshots(
	assetID asset.ID,
	snapshots []asset.Snapshot,
	targetTime time.Time,
) (*asset.Asset, *asset.Snapshot) {
	if len(snapshots) == 0 {
		return nil, nil
	}

	// Sort by captured_at descending so we search most recent first.
	sorted := make([]asset.Snapshot, len(snapshots))
	copy(sorted, snapshots)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].CapturedAt.After(sorted[j].CapturedAt)
	})

	// If we have a target time, prefer the snapshot at that exact time.
	if !targetTime.IsZero() {
		for i := range sorted {
			if !sorted[i].CapturedAt.Equal(targetTime) {
				continue
			}
			found := sorted[i].FindAsset(assetID.String())
			if found != nil {
				return found, &sorted[i]
			}
		}
	}

	// Fall back: search all snapshots.
	for i := range sorted {
		found := sorted[i].FindAsset(assetID.String())
		if found != nil {
			return found, &sorted[i]
		}
	}

	return nil, nil
}
