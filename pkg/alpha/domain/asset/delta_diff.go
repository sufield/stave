package asset

import (
	"maps"
	"reflect"
	"slices"
	"sort"
	"strings"
)

type assetDiffInput struct {
	ID          string
	Prev        Asset
	HasPrevious bool
	Curr        Asset
	HasCurrent  bool
}

func diffAsset(in assetDiffInput) *AssetDiff {
	switch {
	case !in.HasPrevious && in.HasCurrent:
		return &AssetDiff{
			AssetID:    ID(in.ID),
			ChangeType: ChangeAdded,
			ToType:     in.Curr.Type,
		}
	case in.HasPrevious && !in.HasCurrent:
		return &AssetDiff{
			AssetID:    ID(in.ID),
			ChangeType: ChangeRemoved,
			FromType:   in.Prev.Type,
		}
	default:
		// TELL: Let the asset identify its own property-level differences.
		propChanges := DiffAssets(in.Prev, in.Curr)
		if len(propChanges) == 0 {
			return nil
		}
		return &AssetDiff{
			AssetID:         ID(in.ID),
			ChangeType:      ChangeModified,
			FromType:        in.Prev.Type,
			ToType:          in.Curr.Type,
			PropertyChanges: propChanges,
		}
	}
}

// DiffAssets compares two assets and returns property-level changes.
func DiffAssets(prev, curr Asset) []PropertyChange {
	var changes []PropertyChange
	if prev.Type != curr.Type {
		changes = append(changes, PropertyChange{Path: "_meta.type", From: prev.Type.String(), To: curr.Type.String()})
	}
	if prev.Vendor != curr.Vendor {
		changes = append(changes, PropertyChange{Path: "_meta.vendor", From: prev.Vendor.String(), To: curr.Vendor.String()})
	}
	changes = append(changes, diffDeep("properties", prev.Properties, curr.Properties)...)
	// POSTCONDITION: Output is deterministically sorted by Path to ensure stable diffs.
	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	return changes
}

// CONTRACT: Property paths are dot-separated breadcrumbs (e.g., "properties.cpu.cores").
// diffDeep recursively compares two values and returns property changes.
func diffDeep(path string, from, to any) []PropertyChange {
	// PRECONDITION: If types differ at the same path, record as a change and stop recursion.
	if reflect.TypeOf(from) != reflect.TypeOf(to) {
		return []PropertyChange{{Path: path, From: from, To: to}}
	}

	fromMap, fromIsMap := from.(map[string]any)
	toMap, toIsMap := to.(map[string]any)
	if fromIsMap && toIsMap {
		keys := uniqueSortedKeys(fromMap, toMap)

		var changes []PropertyChange
		for _, k := range keys {
			changes = append(changes, diffDeep(appendPropertyPath(path, k), fromMap[k], toMap[k])...)
		}
		return changes
	}
	// PERFORMANCE: Using reflect.DeepEqual is the idiomatic way to compare arbitrary JSON values.
	if !reflect.DeepEqual(from, to) {
		return []PropertyChange{{Path: path, From: from, To: to}}
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
