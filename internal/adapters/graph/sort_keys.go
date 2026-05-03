package graph

import "sort"

// sortedPropKeys returns the keys of props in sorted order. Centralizes
// the make+for-range+sort pattern that the JSON-LD and GraphML
// exporters need every time they emit a property bag deterministically.
//
// The byte-determinism of these formats depends on this exact ordering;
// any future replacement (e.g. a stable but different ordering) must
// be a single change here, not a hunt across two exporters.
func sortedPropKeys(props map[string]any) []string {
	keys := make([]string, 0, len(props))
	for k := range props {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
