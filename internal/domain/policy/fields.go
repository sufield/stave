package policy

import (
	"strings"

	"github.com/sufield/stave/internal/domain/asset"
)

// Field namespaces used during predicate resolution.
const (
	nsIdentities = "identities"
	nsIdentity   = "identity"
	nsParams     = "params"
	nsProperties = "properties"
)

func getFieldValueByParts(ctx EvalContext, parts []string) (any, bool) {
	if len(parts) == 0 {
		return nil, false
	}

	head := parts[0]
	tail := parts[1:]

	switch head {
	case nsIdentities:
		// Returns the full slice for "any_match" / "all_match" operations.
		return ctx.Identities, ctx.Identities != nil

	case nsIdentity:
		if ctx.CloudIdentity == nil {
			return nil, false
		}
		return getIdentityField(ctx.CloudIdentity, tail)

	case nsParams:
		if len(tail) == 0 {
			return nil, false
		}
		// Params are assumed to be a flat map.
		return ctx.Param(tail[0])

	case nsProperties:
		// "properties" is the default namespace; we strip the prefix if present.
		return getNestedValue(ctx.Properties, tail)

	default:
		// If no namespace is matched, treat the whole path as a property lookup.
		return getNestedValue(ctx.Properties, parts)
	}
}

// getIdentityField maps string paths to asset.CloudIdentity methods.
func getIdentityField(id *asset.CloudIdentity, parts []string) (any, bool) {
	if len(parts) == 0 {
		return nil, false
	}

	path := strings.Join(parts, ".")
	switch path {
	case "owner":
		return id.Owner()
	case "purpose":
		return id.Purpose()
	case "grants.has_wildcard":
		return id.HasWildcard()
	case "scope.distinct_systems":
		return id.DistinctSystems()
	case "scope.distinct_resource_groups":
		return id.DistinctResourceGroups()
	default:
		return nil, false
	}
}

// getNestedValue performs a recursive lookup in nested maps.
func getNestedValue(props map[string]any, parts []string) (any, bool) {
	if props == nil || len(parts) == 0 {
		return nil, false
	}

	var current any = props
	for _, part := range parts {
		switch m := current.(type) {
		case map[string]any:
			val, ok := m[part]
			if !ok {
				return nil, false
			}
			current = val
		case map[string]string:
			val, ok := m[part]
			if !ok {
				return nil, false
			}
			current = val
		default:
			// Reached a leaf node before consuming all parts of the path.
			return nil, false
		}
	}
	return current, true
}
