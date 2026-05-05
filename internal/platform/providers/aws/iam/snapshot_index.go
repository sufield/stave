package iam

import (
	"strings"

	"github.com/sufield/stave/internal/core/asset"
)

// BuildResolutionInput extracts IAM policy data from a snapshot
// CloudIdentity and assembles the input for Resolve(). The
// extraction follows the wire shape stave's collectors emit:
// nested maps under identity.policies_json, identity.scp_json,
// identity.boundary_json, identity.has_permissions_boundary,
// identity.trust_policy_json. Malformed individual layers are
// silently dropped (matching the legacy fail-soft contract every
// caller relied on); the caller can branch on the returned
// ResolutionInput's flags (SCPPresent, BoundaryPresent) to detect
// "field absent" vs. "field present but unparseable".
//
// Centralised here (rather than duplicated in cmd/nep and
// internal/app/sirbridge) so the IAM resolution boundary lives
// inside the IAM package — the natural seam, since the function
// already imports nothing the package didn't import already.
func BuildResolutionInput(id *asset.CloudIdentity) ResolutionInput {
	input := ResolutionInput{
		PrincipalARN: string(id.ID),
	}

	policiesJSON := stringProperty(id.Properties, "identity", "policies_json")
	if policiesJSON != "" {
		if doc, err := ParsePolicyDocument(policiesJSON); err == nil {
			input.IdentityPolicies = []PolicyDocument{doc}
		}
	}

	scpJSON := stringProperty(id.Properties, "identity", "scp_json")
	if scpJSON != "" {
		input.SCPPresent = true
		if doc, err := ParsePolicyDocument(scpJSON); err == nil {
			input.SCPHierarchy = []PolicyDocument{doc}
		}
	}

	boundaryJSON := stringProperty(id.Properties, "identity", "boundary_json")
	if boolProperty(id.Properties, "identity", "has_permissions_boundary") {
		input.BoundaryPresent = true
		if boundaryJSON != "" {
			if doc, err := ParsePolicyDocument(boundaryJSON); err == nil {
				input.BoundaryPolicy = &doc
			}
		}
	}

	return input
}

// ResolveAllPrincipals walks every CloudIdentity in the snapshot,
// runs Resolve() against the assembled inputs, and returns two
// maps keyed by principal ARN: the resolved permissions per
// principal, and the trust policy (if any) per principal. The
// trust-policy map feeds ResolveChains alongside the resolved
// index; the two maps are returned together because every caller
// today needs both.
func ResolveAllPrincipals(snap *asset.Snapshot) (
	map[string]*ResolvedPermissions,
	map[string]*PolicyDocument,
) {
	if snap == nil {
		return map[string]*ResolvedPermissions{}, map[string]*PolicyDocument{}
	}
	resolved := make(map[string]*ResolvedPermissions, len(snap.Identities))
	trusts := make(map[string]*PolicyDocument, len(snap.Identities))
	for i := range snap.Identities {
		id := &snap.Identities[i]
		input := BuildResolutionInput(id)
		result := Resolve(input)
		resolved[string(id.ID)] = &result

		trustJSON := stringProperty(id.Properties, "identity", "trust_policy_json")
		if trustJSON != "" {
			if doc, err := ParsePolicyDocument(trustJSON); err == nil {
				trusts[string(id.ID)] = &doc
			}
		}
	}
	return resolved, trusts
}

// ExtractAccountIDFromARN returns the account-ID segment of an
// ARN, or an empty string when the ARN is malformed. Accepts both
// the canonical 6-segment ARN form and the 5-segment trust-root
// form ("arn:aws:iam::<account>:root") that ResolveChains expects.
func ExtractAccountIDFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}

// stringProperty walks a nested map[string]any using the supplied
// keys and returns the leaf as a string. Returns "" when any key
// is missing or any intermediate node is not a map. Variadic for
// readability at call sites — three keys deep is the deepest path
// stave's collectors emit (identity.policies_json shape).
func stringProperty(props map[string]any, keys ...string) string {
	v, ok := walkProperty(props, keys)
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

// boolProperty mirrors stringProperty for boolean leaves. Used by
// BuildResolutionInput to detect identity.has_permissions_boundary.
func boolProperty(props map[string]any, keys ...string) bool {
	v, ok := walkProperty(props, keys)
	if !ok {
		return false
	}
	b, _ := v.(bool)
	return b
}

func walkProperty(props map[string]any, keys []string) (any, bool) {
	var current any = props
	for _, key := range keys {
		m, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = m[key]
		if !ok {
			return nil, false
		}
	}
	return current, true
}
