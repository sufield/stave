// Package reachability annotates findings with reachability context
// from a vendor-neutral resource-access index. The index itself is
// produced by a provider package (e.g. providers/aws/iam) and
// passed in — this package owns the annotation logic only, so it
// has no AWS dependency.
package reachability

import (
	"math"
	"strings"

	"github.com/sufield/stave/internal/core/access"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

// AnnotateFindings enriches violation findings with reachability context.
// Only annotates findings that are violations (all findings in the array).
// No-ops on resources not present in the access index.
func AnnotateFindings(findings []remediation.Finding, idx *access.ResourceAccessIndex) {
	if idx == nil {
		return
	}
	for i := range findings {
		f := &findings[i]
		entries := idx.EntriesFor(string(f.AssetID))
		if len(entries) == 0 {
			continue
		}
		f.Reachability = BuildContext(entries)
	}
}

// BuildContext computes the per-finding reachability context from
// the access entries that point at a single asset. Exported so
// callers (notably pkg/stave) can annotate plain
// []evaluation.Finding slices without round-tripping through
// []remediation.Finding.
func BuildContext(entries []access.ResourceAccessEntry) *evaluation.ReachabilityContext {
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
			ctx.HighestPrivilegePrincipal = kernel.PrincipalRef(e.PrincipalARN)
		}
	}

	// BlastRadiusScore formula — simple and auditable.
	ctx.BlastRadiusScore = kernel.BlastRadius(math.Min(100, float64(
		ctx.PrivilegedPrincipalCount*20+
			ctx.TotalReachablePrincipals*2+
			boolInt(ctx.ExternalPrincipalReachable)*30,
	)))

	return ctx
}

// isPrivileged checks if a principal has admin-level or wildcard permissions.
func isPrivileged(e *access.ResourceAccessEntry) bool {
	for _, action := range e.Actions {
		if action == "*" {
			return true
		}
		// Admin-like actions.
		if strings.HasSuffix(action, ":*") ||
			containsFold(action, "admin") ||
			containsFold(action, "fullaccess") {
			return true
		}
	}
	return false
}

func containsFold(s, substrLower string) bool {
	if substrLower == "" {
		return true
	}
	if len(s) < len(substrLower) {
		return false
	}
	for i := 0; i <= len(s)-len(substrLower); i++ {
		match := true
		for j := 0; j < len(substrLower); j++ {
			c1 := s[i+j]
			c2 := substrLower[j]
			if c1 != c2 {
				if c1 >= 'A' && c1 <= 'Z' {
					c1 += 'a' - 'A'
				}
				if c1 != c2 {
					match = false
					break
				}
			}
		}
		if match {
			return true
		}
	}
	return false
}

func principalScore(e *access.ResourceAccessEntry) float64 {
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
