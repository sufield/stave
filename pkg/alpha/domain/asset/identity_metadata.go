package asset

import (
	"math"

	"github.com/sufield/stave/pkg/alpha/domain/maps"
)

// Metadata provides a typed view over identity properties.
func (id CloudIdentity) Metadata() maps.Value {
	return maps.ParseMap(id.Map())
}

// Owner returns the identity owner value when present.
func (id CloudIdentity) Owner() (string, bool) {
	return identityStringProperty(id.Map(), "owner")
}

// Purpose returns the identity purpose value when present.
func (id CloudIdentity) Purpose() (string, bool) {
	return identityStringProperty(id.Map(), "purpose")
}

// HasWildcard returns whether grants.has_wildcard is set and the grants parent exists.
func (id CloudIdentity) HasWildcard() (bool, bool) {
	return identityNestedBoolProperty(id.Map(), "grants", "has_wildcard")
}

// DistinctSystems returns scope.distinct_systems and whether scope exists.
func (id CloudIdentity) DistinctSystems() (int, bool) {
	return identityNestedIntProperty(id.Map(), "scope", "distinct_systems")
}

// DistinctResourceGroups returns scope.distinct_resource_groups and whether scope exists.
func (id CloudIdentity) DistinctResourceGroups() (int, bool) {
	return identityNestedIntProperty(id.Map(), "scope", "distinct_resource_groups")
}

func identityStringProperty(props map[string]any, key string) (string, bool) {
	raw, ok := props[key]
	if !ok {
		return "", false
	}
	value, ok := raw.(string)
	if !ok {
		return "", false
	}
	return value, true
}

func identityNestedBoolProperty(props map[string]any, parent, key string) (bool, bool) {
	rawParent, ok := props[parent]
	if !ok {
		return false, false
	}
	parentMap, ok := rawParent.(map[string]any)
	if !ok {
		return false, true
	}
	raw, ok := parentMap[key]
	if !ok {
		return false, true
	}
	value, ok := raw.(bool)
	if !ok {
		return false, true
	}
	return value, true
}

func identityNestedIntProperty(props map[string]any, parent, key string) (int, bool) {
	rawParent, ok := props[parent]
	if !ok {
		return 0, false
	}
	parentMap, ok := rawParent.(map[string]any)
	if !ok {
		return 0, true
	}
	raw, ok := parentMap[key]
	if !ok {
		return 0, true
	}
	value, ok := toIdentityInt(raw)
	if !ok {
		return 0, true
	}
	return value, true
}

// toIdentityInt converts an arbitrary numeric value to int.
// JSON decoding produces float64; other sources may use concrete int types.
func toIdentityInt(value any) (int, bool) {
	switch v := value.(type) {
	// Signed integers.
	case int:
		return v, true
	case int8:
		return int(v), true
	case int16:
		return int(v), true
	case int32:
		return int(v), true
	case int64:
		if v < math.MinInt || v > math.MaxInt {
			return 0, false
		}
		return int(v), true
	// Unsigned integers.
	case uint:
		if v > math.MaxInt {
			return 0, false
		}
		return int(v), true
	case uint8:
		return int(v), true
	case uint16:
		return int(v), true
	case uint32:
		return int(v), true
	case uint64:
		if v > math.MaxInt {
			return 0, false
		}
		return int(v), true
	// Floats (encoding/json decodes numbers as float64).
	case float32:
		return int(v), true
	case float64:
		return int(v), true
	default:
		return 0, false
	}
}
