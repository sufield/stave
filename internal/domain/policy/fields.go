package policy

import (
	"strings"

	"github.com/sufield/stave/internal/domain/asset"
)

// Field namespaces and identity subfields used by predicate resolution.
const (
	fieldNamespaceIdentities = "identities"
	fieldNamespaceIdentity   = "identity"
	fieldNamespaceParams     = "params"
	fieldNamespaceProperties = "properties"

	identityFieldOwner                  = "owner"
	identityFieldPurpose                = "purpose"
	identityFieldGrants                 = "grants"
	identityFieldScope                  = "scope"
	identityGrantHasWildcard            = "has_wildcard"
	identityScopeDistinctSystems        = "distinct_systems"
	identityScopeDistinctResourceGroups = "distinct_resource_groups"
)

type identityExtractor func(*asset.CloudIdentity) (any, bool)

var identityRootExtractors = map[string]identityExtractor{
	identityFieldOwner:   identityOwnerValue,
	identityFieldPurpose: identityPurposeValue,
}

var identityGrantExtractors = map[string]identityExtractor{
	identityGrantHasWildcard: identityGrantHasWildcardValue,
}

var identityScopeExtractors = map[string]identityExtractor{
	identityScopeDistinctSystems:        identityScopeDistinctSystemsValue,
	identityScopeDistinctResourceGroups: identityScopeDistinctResourceGroupsValue,
}

// GetFieldValueWithContext is the exported form for use by the trace package.
func GetFieldValueWithContext(ctx EvalContext, field string) (any, bool) {
	return getFieldValueWithContext(ctx, field)
}

func getFieldValueWithContext(ctx EvalContext, field string) (any, bool) {
	return getFieldValueWithParts(ctx, strings.Split(field, "."))
}

// getFieldValueWithParts retrieves a field value from the evaluation context.
// Returns (value, exists).
func getFieldValueWithParts(ctx EvalContext, parts []string) (any, bool) {
	// Handle "identities" field (returns slice for any_match)
	if len(parts) == 1 && parts[0] == fieldNamespaceIdentities {
		return ctx.Identities, ctx.Identities != nil
	}

	if len(parts) == 0 {
		return nil, false
	}

	// Handle identity.* fields
	if parts[0] == fieldNamespaceIdentity && ctx.CloudIdentity != nil {
		return getIdentityFieldValue(ctx.CloudIdentity, parts[1:])
	}

	// Handle params.* fields
	if parts[0] == fieldNamespaceParams && ctx.Params != nil {
		if len(parts) < 2 {
			return nil, false
		}
		v, ok := ctx.Params[parts[1]]
		return v, ok
	}

	// Handle properties.* fields (for assets)
	if parts[0] == fieldNamespaceProperties {
		parts = parts[1:]
	}

	return getNestedValue(ctx.Properties, parts)
}

// getIdentityFieldValue extracts a value from an CloudIdentity struct.
func getIdentityFieldValue(id *asset.CloudIdentity, parts []string) (any, bool) {
	if len(parts) == 0 || id == nil {
		return nil, false
	}

	if extractor, ok := identityRootExtractors[parts[0]]; ok {
		return extractor(id)
	}

	if len(parts) < 2 {
		return nil, false
	}

	switch parts[0] {
	case identityFieldGrants:
		_, exists := id.HasWildcard()
		return extractIdentityNestedField(id, exists, parts[1], identityGrantExtractors)
	case identityFieldScope:
		_, exists := id.DistinctSystems()
		return extractIdentityNestedField(id, exists, parts[1], identityScopeExtractors)
	}
	return nil, false
}

func identityOwnerValue(id *asset.CloudIdentity) (any, bool) {
	return id.Owner()
}

func identityPurposeValue(id *asset.CloudIdentity) (any, bool) {
	return id.Purpose()
}

func identityGrantHasWildcardValue(id *asset.CloudIdentity) (any, bool) {
	return id.HasWildcard()
}

func identityScopeDistinctSystemsValue(id *asset.CloudIdentity) (any, bool) {
	return id.DistinctSystems()
}

func identityScopeDistinctResourceGroupsValue(id *asset.CloudIdentity) (any, bool) {
	return id.DistinctResourceGroups()
}

func extractIdentityNestedField(
	id *asset.CloudIdentity,
	parentExists bool,
	field string,
	extractors map[string]identityExtractor,
) (any, bool) {
	if !parentExists {
		return nil, false
	}
	extractor, ok := extractors[field]
	if !ok {
		return nil, false
	}
	return extractor(id)
}

// getNestedValue retrieves a nested value from a map using path parts.
func getNestedValue(props map[string]any, parts []string) (any, bool) {
	if props == nil || len(parts) == 0 {
		return nil, false
	}

	var current any = props
	for _, part := range parts {
		switch m := current.(type) {
		case map[string]any:
			v, exists := m[part]
			if !exists {
				return nil, false
			}
			current = v
		case map[string]string:
			v, exists := m[part]
			if !exists {
				return nil, false
			}
			current = v
		default:
			return nil, false
		}
	}
	return current, true
}
