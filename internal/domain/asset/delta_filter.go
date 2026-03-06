package asset

import "strings"

// FilterOptions narrows an ObservationDelta by change/asset criteria.
type FilterOptions struct {
	ChangeTypes []ChangeType
	AssetTypes  []string
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

	out := make([]AssetDiff, 0, len(changes))
	for _, change := range changes {
		if !matchesChangeType(change.ChangeType, changeTypes) {
			continue
		}
		if !matchesAssetType(change, assetTypes) {
			continue
		}
		if !matchesID(change, assetID) {
			continue
		}
		out = append(out, change)
	}
	return out
}

func buildChangeTypeSet(types []ChangeType) map[ChangeType]struct{} {
	m := make(map[ChangeType]struct{}, len(types))
	for _, ct := range types {
		if ct != "" {
			m[ct] = struct{}{}
		}
	}
	return m
}

func buildAssetTypeSet(types []string) map[string]struct{} {
	m := make(map[string]struct{}, len(types))
	for _, rt := range types {
		if clean := strings.TrimSpace(rt); clean != "" {
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

func matchesAssetType(change AssetDiff, filter map[string]struct{}) bool {
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

func effectiveAssetType(change AssetDiff) string {
	if change.ToType != "" {
		return change.ToType
	}
	return change.FromType
}
