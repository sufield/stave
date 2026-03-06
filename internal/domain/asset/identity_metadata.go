package asset

import (
	"math"
	"reflect"

	"github.com/sufield/stave/internal/pkg/maps"
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

func toIdentityInt(value any) (int, bool) {
	if n, ok := signedIdentityInt(value); ok {
		return n, true
	}
	if n, ok := unsignedIdentityInt(value); ok {
		return n, true
	}
	if n, ok := floatIdentityInt(value); ok {
		return n, true
	}
	return 0, false
}

func signedIdentityInt(value any) (int, bool) {
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n := rv.Int()
		if n < int64(-math.MaxInt-1) || n > int64(math.MaxInt) {
			return 0, false
		}
		return int(n), true
	default:
		return 0, false
	}
}

func unsignedIdentityInt(value any) (int, bool) {
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n := rv.Uint()
		if n > uint64(math.MaxInt) {
			return 0, false
		}
		return int(n), true
	default:
		return 0, false
	}
}

func floatIdentityInt(value any) (int, bool) {
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Float32, reflect.Float64:
		return int(rv.Float()), true
	default:
		return 0, false
	}
}
