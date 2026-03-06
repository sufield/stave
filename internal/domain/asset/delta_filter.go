package asset

import "strings"

// FilterOptions narrows an ObservationDelta by change/resource criteria.
type FilterOptions struct {
	ChangeTypes []ChangeType
	AssetTypes  []string
	AssetID     string
}

// ApplyFilter returns a new ObservationDelta containing only matching changes.
func (d ObservationDelta) ApplyFilter(opt FilterOptions) ObservationDelta {
	filtered := filterResourceDiffs(d.Changes, opt)
	return ObservationDelta{
		SchemaVersion: d.SchemaVersion,
		Kind:          d.Kind,
		FromCaptured:  d.FromCaptured,
		ToCaptured:    d.ToCaptured,
		Changes:       filtered,
		Summary:       SummarizeDeltaChanges(filtered),
	}
}

func filterResourceDiffs(changes []ResourceDiff, opt FilterOptions) []ResourceDiff {
	if len(changes) == 0 {
		return nil
	}

	changeTypes := buildChangeTypeSet(opt.ChangeTypes)
	resourceTypes := buildAssetTypeSet(opt.AssetTypes)
	assetID := strings.TrimSpace(opt.AssetID)

	out := make([]ResourceDiff, 0, len(changes))
	for _, change := range changes {
		if !matchesChangeType(change.ChangeType, changeTypes) {
			continue
		}
		if !matchesResourceType(change, resourceTypes) {
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

func matchesResourceType(change ResourceDiff, filter map[string]struct{}) bool {
	if len(filter) == 0 {
		return true
	}
	_, ok := filter[effectiveResourceType(change)]
	return ok
}

func matchesID(change ResourceDiff, substr string) bool {
	if substr == "" {
		return true
	}
	return strings.Contains(change.AssetID.String(), substr)
}

func effectiveResourceType(change ResourceDiff) string {
	if change.ToType != "" {
		return change.ToType
	}
	return change.FromType
}
