// Package snapshotdiff produces structured diffs between two observation
// snapshots, showing property changes, new/removed assets, filtered to
// fields that Stave controls evaluate.
package snapshotdiff

import (
	"slices"
	"time"

	"github.com/sufield/stave/internal/core/asset"
)

// PropertyChange records a change to a single property.
type PropertyChange struct {
	AssetID  asset.ID `json:"asset_id"`
	Property string   `json:"property"`
	Before   any      `json:"before"`
	After    any      `json:"after"`
}

// NewAsset records an asset present in after but not before.
type NewAsset struct {
	AssetID   asset.ID       `json:"asset_id"`
	AssetType string         `json:"asset_type"`
	Props     map[string]any `json:"properties,omitempty"`
}

// RemovedAsset records an asset present in before but not after.
type RemovedAsset struct {
	AssetID   asset.ID `json:"asset_id"`
	AssetType string   `json:"asset_type"`
}

// DiffResult holds the structured diff between two snapshots.
type DiffResult struct {
	BeforeTime      time.Time        `json:"before_time"`
	AfterTime       time.Time        `json:"after_time"`
	BeforeAssets    int              `json:"before_assets"`
	AfterAssets     int              `json:"after_assets"`
	PropertyChanges []PropertyChange `json:"property_changes"`
	NewAssets       []NewAsset       `json:"new_assets"`
	RemovedAssets   []RemovedAsset   `json:"removed_assets"`
}

// Diff compares two snapshots and returns the structured differences.
func Diff(before, after asset.Snapshot) *DiffResult {
	result := &DiffResult{
		BeforeTime:   before.CapturedAt,
		AfterTime:    after.CapturedAt,
		BeforeAssets: len(before.Assets),
		AfterAssets:  len(after.Assets),
	}

	// Index assets by ID.
	beforeIndex := indexAssets(before.Assets)
	afterIndex := indexAssets(after.Assets)

	// Collect all asset IDs, sorted.
	allIDs := make(map[asset.ID]struct{})
	for id := range beforeIndex {
		allIDs[id] = struct{}{}
	}
	for id := range afterIndex {
		allIDs[id] = struct{}{}
	}
	sortedIDs := make([]asset.ID, 0, len(allIDs))
	for id := range allIDs {
		sortedIDs = append(sortedIDs, id)
	}
	slices.Sort(sortedIDs)

	for _, id := range sortedIDs {
		bAsset, inBefore := beforeIndex[id]
		aAsset, inAfter := afterIndex[id]

		if !inBefore && inAfter {
			result.NewAssets = append(result.NewAssets, NewAsset{
				AssetID:   aAsset.ID,
				AssetType: string(aAsset.Type),
				Props:     aAsset.Properties,
			})
			continue
		}

		if inBefore && !inAfter {
			result.RemovedAssets = append(result.RemovedAssets, RemovedAsset{
				AssetID:   bAsset.ID,
				AssetType: string(bAsset.Type),
			})
			continue
		}

		// Both present: diff properties.
		changes := diffProperties(id, bAsset.Properties, aAsset.Properties, "")
		result.PropertyChanges = append(result.PropertyChanges, changes...)
	}

	return result
}

// diffProperties recursively compares two property maps and returns changes.
func diffProperties(assetID asset.ID, before, after map[string]any, prefix string) []PropertyChange {
	var changes []PropertyChange

	// Check all keys in before.
	for key, bVal := range before {
		path := propertyPath(prefix, key)
		aVal, exists := after[key]
		if !exists {
			changes = append(changes, PropertyChange{
				AssetID:  assetID,
				Property: path,
				Before:   bVal,
				After:    nil,
			})
			continue
		}

		// Both exist: compare.
		bMap, bIsMap := bVal.(map[string]any)
		aMap, aIsMap := aVal.(map[string]any)
		if bIsMap && aIsMap {
			changes = append(changes, diffProperties(assetID, bMap, aMap, path)...)
			continue
		}

		if !jsonEqual(bVal, aVal) {
			changes = append(changes, PropertyChange{
				AssetID:  assetID,
				Property: path,
				Before:   bVal,
				After:    aVal,
			})
		}
	}

	// Check for keys only in after.
	for key, aVal := range after {
		path := propertyPath(prefix, key)
		if _, exists := before[key]; !exists {
			changes = append(changes, PropertyChange{
				AssetID:  assetID,
				Property: path,
				Before:   nil,
				After:    aVal,
			})
		}
	}

	// Sort by property path for deterministic output.
	slices.SortFunc(changes, func(a, b PropertyChange) int {
		if a.Property < b.Property {
			return -1
		}
		if a.Property > b.Property {
			return 1
		}
		return 0
	})

	return changes
}

func propertyPath(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

func indexAssets(assets []asset.Asset) map[asset.ID]*asset.Asset {
	idx := make(map[asset.ID]*asset.Asset, len(assets))
	for i := range assets {
		idx[assets[i].ID] = &assets[i]
	}
	return idx
}

// jsonEqual recursively checks structural equality of JSON-compatible values
// (strings, floats, booleans, maps, slices) without reflection package overhead
// or recursive pointer/struct traversal vulnerabilities.
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
