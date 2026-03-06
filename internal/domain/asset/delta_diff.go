package asset

import (
	"reflect"
	"sort"

	"github.com/sufield/stave/internal/pkg/fp"
)

type resourceDiffInput struct {
	ID      string
	Prev    Asset
	HasPrev bool
	Curr    Asset
	HasCurr bool
}

func diffResource(in resourceDiffInput) *ResourceDiff {
	switch {
	case !in.HasPrev && in.HasCurr:
		return &ResourceDiff{
			AssetID:    ID(in.ID),
			ChangeType: ChangeAdded,
			ToType:     in.Curr.Type.String(),
		}
	case in.HasPrev && !in.HasCurr:
		return &ResourceDiff{
			AssetID:    ID(in.ID),
			ChangeType: ChangeRemoved,
			FromType:   in.Prev.Type.String(),
		}
	default:
		// TELL: Let the resource identify its own property-level differences.
		propChanges := DiffResources(in.Prev, in.Curr)
		if len(propChanges) == 0 {
			return nil
		}
		return &ResourceDiff{
			AssetID:         ID(in.ID),
			ChangeType:      ChangeModified,
			FromType:        in.Prev.Type.String(),
			ToType:          in.Curr.Type.String(),
			PropertyChanges: propChanges,
		}
	}
}

// DiffResources compares two resources and returns property-level changes.
func DiffResources(prev, curr Asset) []PropertyChange {
	changes := make([]PropertyChange, 0)
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
		keys := uniqueSortedAnyKeys(fromMap, toMap)

		changes := make([]PropertyChange, 0)
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

func appendPropertyPath(base, segment string) string {
	if base == "" {
		return segment
	}
	return base + "." + segment
}

func resourceMap(resources []Asset) map[string]Asset {
	return fp.ToMap(resources, func(r Asset) string { return r.ID.String() })
}

func uniqueSortedResourceKeys(a, b map[string]Asset) []string {
	keySet := make(map[string]struct{}, len(a)+len(b))
	for k := range a {
		keySet[k] = struct{}{}
	}
	for k := range b {
		keySet[k] = struct{}{}
	}

	keys := make([]string, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func uniqueSortedAnyKeys(a, b map[string]any) []string {
	keySet := make(map[string]struct{}, len(a)+len(b))
	for k := range a {
		keySet[k] = struct{}{}
	}
	for k := range b {
		keySet[k] = struct{}{}
	}

	keys := make([]string, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
