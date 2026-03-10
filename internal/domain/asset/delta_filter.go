package asset

import (
	"strings"

	"github.com/samber/lo"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/pkg/fp"
)

// FilterOptions narrows an ObservationDelta by change/asset criteria.
type FilterOptions struct {
	ChangeTypes []ChangeType
	AssetTypes  []kernel.AssetType
	AssetID     string
}

// ApplyFilter returns a new ObservationDelta containing only matching changes.
func (d ObservationDelta) ApplyFilter(opt FilterOptions) ObservationDelta {
	filtered := filterAssetDiffs(d.Changes, opt)
	return ObservationDelta{
		SchemaVersion: d.SchemaVersion,
		Kind:          d.Kind,
		FromCaptured:  d.FromCaptured,
		ToCaptured:    d.ToCaptured,
		Changes:       filtered,
		Summary:       SummarizeDeltaChanges(filtered),
	}
}

func filterAssetDiffs(changes []AssetDiff, opt FilterOptions) []AssetDiff {
	if len(changes) == 0 {
		return nil
	}

	changeTypes := buildChangeTypeSet(opt.ChangeTypes)
	assetTypes := buildAssetTypeSet(opt.AssetTypes)
	assetID := strings.TrimSpace(opt.AssetID)

	return lo.Filter(changes, func(change AssetDiff, _ int) bool {
		return matchesChangeType(change.ChangeType, changeTypes) &&
			matchesAssetType(change, assetTypes) &&
			matchesID(change, assetID)
	})
}

func buildChangeTypeSet(types []ChangeType) map[ChangeType]struct{} {
	return fp.ToSet(lo.Filter(types, func(ct ChangeType, _ int) bool { return ct != "" }))
}

func buildAssetTypeSet(types []kernel.AssetType) map[kernel.AssetType]struct{} {
	m := make(map[kernel.AssetType]struct{}, len(types))
	for _, rt := range types {
		if clean := kernel.AssetType(strings.TrimSpace(string(rt))); clean != "" {
			m[clean] = struct{}{}
		}
	}
	return m
}

func matchesChangeType(ct ChangeType, filter map[ChangeType]struct{}) bool {
	if len(filter) == 0 {
		return true
	}
	_, ok := filter[ct]
	return ok
}

func matchesAssetType(change AssetDiff, filter map[kernel.AssetType]struct{}) bool {
	if len(filter) == 0 {
		return true
	}
	_, ok := filter[effectiveAssetType(change)]
	return ok
}

func matchesID(change AssetDiff, substr string) bool {
	if substr == "" {
		return true
	}
	return strings.Contains(change.AssetID.String(), substr)
}

func effectiveAssetType(change AssetDiff) kernel.AssetType {
	if change.ToType != "" {
		return change.ToType
	}
	return change.FromType
}
