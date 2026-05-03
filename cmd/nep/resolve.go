package nep

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/adapters/observations"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/platform/providers/aws/iam"
)

// loadSnapshots loads snapshots from a file, supporting both bundle format
// ({"snapshots": [...]}) and single snapshot format ({"schema_version": "obs.v0.1", ...}).
func loadSnapshots(path string) ([]asset.Snapshot, error) {
	snaps, err := observations.LoadBundle(path)
	if err == nil && len(snaps) > 0 {
		return snaps, nil
	}
	// Fall back: try parsing as a single snapshot.
	data, readErr := fsutil.ReadFileLimited(path)
	if readErr != nil {
		return nil, fmt.Errorf("read %s: %w", path, readErr)
	}
	var single asset.Snapshot
	if jsonErr := json.Unmarshal(data, &single); jsonErr != nil {
		return nil, fmt.Errorf("parse snapshot %s: %w", path, jsonErr)
	}
	if len(single.Assets) > 0 || len(single.Identities) > 0 {
		return []asset.Snapshot{single}, nil
	}
	return nil, fmt.Errorf("no snapshot data in %s", path)
}

// buildResolutionInput extracts IAM policy data from a snapshot identity
// and builds the input for iam.Resolve().
func buildResolutionInput(id *asset.CloudIdentity) iam.ResolutionInput {
	input := iam.ResolutionInput{
		PrincipalARN: string(id.ID),
	}

	// Layer 4: identity-based policies.
	policiesJSON := resolveStringProperty(id.Properties, []string{"identity", "policies_json"})
	if policiesJSON != "" {
		doc, err := iam.ParsePolicyDocument(policiesJSON)
		if err == nil {
			input.IdentityPolicies = []iam.PolicyDocument{doc}
		}
	}

	// Layer 2: SCP hierarchy.
	scpJSON := resolveStringProperty(id.Properties, []string{"identity", "scp_json"})
	if scpJSON != "" {
		input.SCPPresent = true
		doc, err := iam.ParsePolicyDocument(scpJSON)
		if err == nil {
			input.SCPHierarchy = []iam.PolicyDocument{doc}
		}
	}

	// Layer 3: permission boundary.
	boundaryJSON := resolveStringProperty(id.Properties, []string{"identity", "boundary_json"})
	hasBoundary := resolveBoolProperty(id.Properties, []string{"identity", "has_permissions_boundary"})
	if hasBoundary {
		input.BoundaryPresent = true
		if boundaryJSON != "" {
			doc, err := iam.ParsePolicyDocument(boundaryJSON)
			if err == nil {
				input.BoundaryPolicy = &doc
			}
		}
	}

	return input
}

// resolveAllPrincipals resolves all identities in the snapshot and returns
// a map of principal ARN → ResolvedPermissions, plus trust policies for
// chain resolution.
func resolveAllPrincipals(snap *asset.Snapshot) (
	map[string]*iam.ResolvedPermissions,
	map[string]*iam.PolicyDocument,
) {
	resolved := make(map[string]*iam.ResolvedPermissions, len(snap.Identities))
	trustPolicies := make(map[string]*iam.PolicyDocument, len(snap.Identities))

	for i := range snap.Identities {
		id := &snap.Identities[i]
		input := buildResolutionInput(id)
		result := iam.Resolve(input)
		resolved[string(id.ID)] = &result

		// Extract trust policy for chain resolution.
		trustJSON := resolveStringProperty(id.Properties, []string{"identity", "trust_policy_json"})
		if trustJSON != "" {
			doc, err := iam.ParsePolicyDocument(trustJSON)
			if err == nil {
				trustPolicies[string(id.ID)] = &doc
			}
		}
	}

	return resolved, trustPolicies
}

// resolveBoolProperty navigates nested map properties and returns a bool.
func resolveBoolProperty(props map[string]any, path []string) bool {
	var current any = props
	for _, key := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return false
		}
		current, ok = m[key]
		if !ok {
			return false
		}
	}
	b, ok := current.(bool)
	return ok && b
}

// extractAccountID extracts account ID from an ARN.
func extractAccountIDFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}
