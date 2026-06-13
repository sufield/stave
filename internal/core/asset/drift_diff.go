package asset

import (
	"cmp"
	"maps"
	"slices"
	"strings"
)

type assetDiffInput struct {
	ID          string
	Prev        Asset
	HasPrevious bool
	Curr        Asset
	HasCurrent  bool
}

func diffAsset(in assetDiffInput) *AssetChange {
	switch {
	case !in.HasPrevious && in.HasCurrent:
		return &AssetChange{
			AssetID:     ID(in.ID),
			Action:      DriftProvisioned,
			CurrentType: in.Curr.Type,
		}
	case in.HasPrevious && !in.HasCurrent:
		return &AssetChange{
			AssetID:      ID(in.ID),
			Action:       DriftDecommissioned,
			PreviousType: in.Prev.Type,
		}
	default:
		// TELL: Let the asset identify its own property-level differences.
		propChanges := DiffAssets(in.Prev, in.Curr)
		if len(propChanges) == 0 {
			return nil
		}
		return &AssetChange{
			AssetID:      ID(in.ID),
			Action:       DriftReconfigured,
			PreviousType: in.Prev.Type,
			CurrentType:  in.Curr.Type,
			Drifts:       propChanges,
		}
	}
}

// DiffAssets compares two assets and returns property-level changes.
func DiffAssets(prev, curr Asset) []ConfigurationDrift {
	var changes []ConfigurationDrift
	if prev.Type != curr.Type {
		changes = append(changes, ConfigurationDrift{Attribute: "_meta.type", OldValue: prev.Type.String(), NewValue: curr.Type.String()})
	}
	if prev.Vendor != curr.Vendor {
		changes = append(changes, ConfigurationDrift{Attribute: "_meta.vendor", OldValue: prev.Vendor.String(), NewValue: curr.Vendor.String()})
	}
	changes = append(changes, diffDeep("properties", prev.Properties, curr.Properties)...)
	// POSTCONDITION: Output is deterministically sorted by Path to ensure stable diffs.
	slices.SortFunc(changes, func(a, b ConfigurationDrift) int { return cmp.Compare(a.Attribute, b.Attribute) })
	return changes
}

// CONTRACT: Property paths are dot-separated breadcrumbs (e.g., "properties.cpu.cores").
// diffDeep recursively compares two values and returns property changes.
func diffDeep(path string, from, to any) []ConfigurationDrift {
	// PRECONDITION: If types differ at the same path, record as a change and stop recursion.
	if hasTypeMismatch(from, to) {
		return []ConfigurationDrift{{Attribute: path, OldValue: from, NewValue: to}}
	}

	fromMap, fromIsMap := from.(map[string]any)
	toMap, toIsMap := to.(map[string]any)
	if fromIsMap && toIsMap {
		keys := uniqueSortedKeys(fromMap, toMap)

		var changes []ConfigurationDrift
		for _, k := range keys {
			changes = append(changes, diffDeep(appendPropertyPath(path, k), fromMap[k], toMap[k])...)
		}
		return changes
	}
	if !jsonEqual(from, to) {
		return []ConfigurationDrift{{Attribute: path, OldValue: from, NewValue: to}}
	}
	return nil
}

// appendPropertyPath joins path segments with dots. Segments that contain
// dots themselves (common in cloud tags like "aws:s3.bucket") are wrapped
// in brackets to keep the breadcrumb unambiguous.
func appendPropertyPath(base, segment string) string {
	if strings.Contains(segment, ".") {
		segment = "[" + segment + "]"
	}
	if base == "" {
		return segment
	}
	return base + "." + segment
}

func assetMap(resources []Asset) map[string]Asset {
	m := make(map[string]Asset, len(resources))
	for _, r := range resources {
		m[r.ID.String()] = r
	}
	return m
}

func uniqueSortedKeys[V any](a, b map[string]V) []string {
	keySet := make(map[string]struct{}, len(a)+len(b))
	for k := range a {
		keySet[k] = struct{}{}
	}
	for k := range b {
		keySet[k] = struct{}{}
	}

	if len(keySet) == 0 {
		return nil
	}
	return slices.Sorted(maps.Keys(keySet))
}

func jsonEqual(a, b any) bool {
	switch va := a.(type) {
	case string:
		vb, ok := b.(string)
		return ok && va == vb
	case float64:
		vb, ok := b.(float64)
		return ok && va == vb
	case bool:
		vb, ok := b.(bool)
		return ok && va == vb
	case []any:
		vb, ok := b.([]any)
		if !ok || len(va) != len(vb) {
			return false
		}
		for i := range va {
			if !jsonEqual(va[i], vb[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		vb, ok := b.(map[string]any)
		if !ok || len(va) != len(vb) {
			return false
		}
		for k, v1 := range va {
			v2, exists := vb[k]
			if !exists || !jsonEqual(v1, v2) {
				return false
			}
		}
		return true
	case nil:
		return b == nil
	default:
		return a == b
	}
}

func hasTypeMismatch(a, b any) bool {
	if a == nil || b == nil {
		return (a == nil) != (b == nil)
	}
	switch a.(type) {
	case string:
		_, ok := b.(string)
		return !ok
	case float64:
		_, ok := b.(float64)
		return !ok
	case bool:
		_, ok := b.(bool)
		return !ok
	case []any:
		_, ok := b.([]any)
		return !ok
	case map[string]any:
		_, ok := b.(map[string]any)
		return !ok
	default:
		return false
	}
}
