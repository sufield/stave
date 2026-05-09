package risk

import (
	"strconv"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
)

// NewScopeResolverFromSnapshots returns a [ScopeResolver] backed by
// the asset properties found in the given snapshots. The resolver
// looks up an asset by ID across every snapshot's Assets and
// Identities lists and walks the dotted property path returning the
// scalar value as a string. The leading "properties." segment is
// optional and stripped — chain authors can use the same path format
// the predicate vocabulary uses (e.g.
// "properties.identity.cognito.user_pool_id"), or skip the prefix.
//
// The resolver returns false when:
//   - the asset.ID is unknown across every snapshot
//   - any path segment misses or is non-scalar (map / slice)
//   - the resolved value renders to the empty string
//
// On a duplicate asset.ID across snapshots (the snapshot type
// permits this — see asset.Snapshot doc), the resolver wins on the
// last writer; chain output is grouping-only and not expected to
// reflect transient differences. Callers that need first-write-wins
// can pre-deduplicate the snapshot list.
func NewScopeResolverFromSnapshots(snapshots []asset.Snapshot) ScopeResolver {
	props := make(map[asset.ID]map[string]any)
	for s := range snapshots {
		snap := &snapshots[s]
		for i := range snap.Assets {
			a := &snap.Assets[i]
			if a.Properties != nil {
				props[a.ID] = a.Properties
			}
		}
		for i := range snap.Identities {
			id := &snap.Identities[i]
			if id.Properties != nil {
				props[id.ID] = id.Properties
			}
		}
	}
	return func(id asset.ID, path string) (string, bool) {
		m, ok := props[id]
		if !ok {
			return "", false
		}
		return resolveScalarPath(m, path)
	}
}

// resolveScalarPath walks dotted segments through nested map[string]any
// and returns the leaf value as a string. The "properties." prefix is
// stripped so callers can write paths in the catalog's natural form.
//
// Booleans render as "true"/"false"; numerics render via strconv with
// the smallest representation that round-trips. Nested maps and
// slices fail (return false) — scope keys must be scalar.
func resolveScalarPath(root map[string]any, path string) (string, bool) {
	path = strings.TrimPrefix(path, "properties.")
	if path == "" {
		return "", false
	}
	var cur any = root
	for _, seg := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		next, exists := m[seg]
		if !exists || next == nil {
			return "", false
		}
		cur = next
	}
	switch v := cur.(type) {
	case string:
		if v == "" {
			return "", false
		}
		return v, true
	case bool:
		if v {
			return "true", true
		}
		return "false", true
	case int:
		return strconv.Itoa(v), true
	case int64:
		return strconv.FormatInt(v, 10), true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	}
	return "", false
}
