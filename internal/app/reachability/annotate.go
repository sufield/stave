// Package reachability annotates findings with reachability context
// from a vendor-neutral resource-access index. The index itself is
// produced by a provider package (e.g. providers/aws/iam) and
// passed in — this package owns the annotation logic only, so it
// has no AWS dependency.
package reachability

import (
	"math"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/util/strutil"

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
		entries := idx.EntriesFor(f.AssetID)
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
	// Deduplicate entries by PrincipalARN.
	merged := make(map[string]*access.ResourceAccessEntry)
	for i := range entries {
		e := &entries[i]
		m, ok := merged[e.PrincipalARN]
		if !ok {
			m = &access.ResourceAccessEntry{
				PrincipalARN: e.PrincipalARN,
			}
			merged[e.PrincipalARN] = m
		}
		if e.IsPublic {
			m.IsPublic = true
		}
		if e.IsCrossAccount {
			m.IsCrossAccount = true
		}
		m.Actions = append(m.Actions, e.Actions...)
	}

	uniqueEntries := make([]access.ResourceAccessEntry, 0, len(merged))
	for _, m := range merged {
		uniqueEntries = append(uniqueEntries, *m)
	}
	slices.SortFunc(uniqueEntries, func(a, b access.ResourceAccessEntry) int {
		return strings.Compare(a.PrincipalARN, b.PrincipalARN)
	})

	ctx := &evaluation.ReachabilityContext{
		TotalReachablePrincipals: len(uniqueEntries),
	}

	var highestScore float64
	for i := range uniqueEntries {
		e := &uniqueEntries[i]

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
			strutil.ContainsFold(action, "admin") ||
			strutil.ContainsFold(action, "fullaccess") {
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
