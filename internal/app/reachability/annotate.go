// Package reachability annotates findings with IAM reachability context
// from the NEP resource access index.
package reachability

import (
	"math"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/iam"
)

// AnnotateFindings enriches violation findings with reachability context.
// Only annotates findings that are violations (all findings in the array).
// No-ops on resources not present in the access index.
func AnnotateFindings(findings []remediation.Finding, idx *iam.ResourceAccessIndex) {
	if idx == nil {
		return
	}
	for i := range findings {
		f := &findings[i]
		entries := idx.EntriesFor(string(f.AssetID))
		if len(entries) == 0 {
			continue
		}
		f.Reachability = buildContext(entries)
	}
}

func buildContext(entries []iam.ResourceAccessEntry) *evaluation.ReachabilityContext {
	ctx := &evaluation.ReachabilityContext{
		TotalReachablePrincipals: len(entries),
	}

	var highestScore float64
	for i := range entries {
		e := &entries[i]

		if e.IsPublic || e.IsCrossAccount {
			ctx.ExternalPrincipalReachable = true
		}

		if isPrivileged(e) {
			ctx.PrivilegedPrincipalCount++
		}

		score := principalScore(e)
		if score > highestScore {
			highestScore = score
			ctx.HighestPrivilegePrincipal = e.PrincipalARN
		}
	}

	// BlastRadiusScore formula — simple and auditable.
	ctx.BlastRadiusScore = math.Min(100, float64(
		ctx.PrivilegedPrincipalCount*20+
			ctx.TotalReachablePrincipals*2+
			boolInt(ctx.ExternalPrincipalReachable)*30,
	))

	return ctx
}

// isPrivileged checks if a principal has admin-level or wildcard permissions.
func isPrivileged(e *iam.ResourceAccessEntry) bool {
	for _, action := range e.Actions {
		if action == "*" {
			return true
		}
		// Admin-like actions.
		lower := strings.ToLower(action)
		if strings.HasSuffix(lower, ":*") ||
			strings.Contains(lower, "admin") ||
			strings.Contains(lower, "fullaccess") {
			return true
		}
	}
	return false
}

func principalScore(e *iam.ResourceAccessEntry) float64 {
	score := 1.0
	if e.IsPublic {
		score += 50
	}
	if e.IsCrossAccount {
		score += 20
	}
	if isPrivileged(e) {
		score += 30
	}
	return score
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// resourcePolicyPaths lists known property paths that contain resource-based
// policy JSON documents. Shared with cmd/nep/resource.go.
var resourcePolicyPaths = [][]string{
	{"storage", "policy_json"},
	{"encryption", "key_policy_json"},
	{"compute", "resource_policy_json"},
	{"messaging", "policy_json"},
	{"secret", "resource_policy_json"},
}

// BuildIndexFromSnapshot builds a ResourceAccessIndex from a snapshot's
// resource-based policies. Returns nil if no IAM data is present.
func BuildIndexFromSnapshot(snap *asset.Snapshot) *iam.ResourceAccessIndex {
	if snap == nil || len(snap.Assets) == 0 {
		return nil
	}

	idx := iam.NewResourceAccessIndex()
	found := false

	for i := range snap.Assets {
		a := &snap.Assets[i]
		accountID := extractAccountID(string(a.ID))
		for _, path := range resourcePolicyPaths {
			policyJSON := resolveStringProperty(a.Properties, path)
			if policyJSON == "" {
				continue
			}
			found = true
			_ = idx.AddResourcePolicy(string(a.ID), policyJSON, accountID)
		}
	}

	if !found {
		return nil // no IAM data in snapshot
	}
	return idx
}

func extractAccountID(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}

func resolveStringProperty(props map[string]any, path []string) string {
	var current any = props
	for _, key := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = m[key]
	}
	s, _ := current.(string)
	return s
}
