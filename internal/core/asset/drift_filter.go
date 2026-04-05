package asset

import (
	"strings"

	"github.com/sufield/stave/internal/core/kernel"
)

// FilterOptions narrows an InfrastructureDrift by change/asset criteria.
type FilterOptions struct {
	ChangeTypes []DriftType
	AssetTypes  []kernel.AssetType
	AssetID     string
}

// ApplyFilter returns a new InfrastructureDrift containing only matching changes.
func (d InfrastructureDrift) ApplyFilter(opt FilterOptions) InfrastructureDrift {
	filtered := filterAssetDiffs(d.Changes, opt)
	return InfrastructureDrift{
		SchemaVersion: d.SchemaVersion,
		Kind:          d.Kind,
		StartTime:     d.StartTime,
		EndTime:       d.EndTime,
		Changes:       filtered,
		Summary:       SummarizeDrift(filtered),
	}
}

func filterAssetDiffs(changes []AssetChange, opt FilterOptions) []AssetChange {
	if len(changes) == 0 {
		return nil
	}

	changeTypes := buildChangeTypeSet(opt.ChangeTypes)
	assetTypes := buildAssetTypeSet(opt.AssetTypes)
	assetID := strings.TrimSpace(opt.AssetID)

	filteredChanges := make([]AssetChange, 0, len(changes))
	for _, change := range changes {
		if matchesChangeType(change.Action, changeTypes) &&
			matchesAssetType(change, assetTypes) &&
			matchesID(change, assetID) {
			filteredChanges = append(filteredChanges, change)
		}
	}
	return filteredChanges
}

func buildChangeTypeSet(types []DriftType) map[DriftType]struct{} {
	m := make(map[DriftType]struct{}, len(types))
	for _, ct := range types {
		if ct != "" {
			m[ct] = struct{}{}
		}
	}
	return m
}

func buildAssetTypeSet(types []kernel.AssetType) map[kernel.AssetType]struct{} {
	m := make(map[kernel.AssetType]struct{}, len(types))
	for _, rt := range types {
		if rt != "" {
			m[rt] = struct{}{}
		}
	}
	return m
}

func matchesChangeType(ct DriftType, filter map[DriftType]struct{}) bool {
	if len(filter) == 0 {
		return true
	}
	_, ok := filter[ct]
	return ok
}

func matchesAssetType(change AssetChange, filter map[kernel.AssetType]struct{}) bool {
	if len(filter) == 0 {
		return true
	}
	_, ok := filter[effectiveAssetType(change)]
	return ok
}

func matchesID(change AssetChange, substr string) bool {
	if substr == "" {
		return true
	}
	return strings.Contains(change.AssetID.String(), substr)
}

func effectiveAssetType(change AssetChange) kernel.AssetType {
	if change.CurrentType != "" {
		return change.CurrentType
	}
	return change.PreviousType
}
