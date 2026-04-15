package rank

import (
	"slices"
	"sort"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/iam"
	"github.com/sufield/stave/internal/core/kernel"
)

// IdentityRiskEntry represents a single identity and its transitive risk.
type IdentityRiskEntry struct {
	IdentityARN    string `json:"identity_arn"`
	IdentityType   string `json:"identity_type"`
	PrivilegeLevel string `json:"privilege_level"`

	DirectFindingIDs []string `json:"direct_finding_ids"`
	DirectSeverity   string   `json:"direct_severity"`

	ReachableResources []ReachableResource `json:"reachable_resources"`
	ReachableCount     int                 `json:"reachable_count"`

	TransitiveFindingIDs []string `json:"transitive_finding_ids"`
	TransitiveSeverity   string   `json:"transitive_severity"`

	RiskReductionPercent float64 `json:"risk_reduction_percent"`
	RiskReductionScore   float64 `json:"risk_reduction_score"`

	RemediationActions []string `json:"remediation_actions"`
	Rank               int      `json:"rank"`
}

// ReachableResource represents a resource reachable by an identity.
type ReachableResource struct {
	ResourceARN  string   `json:"resource_arn"`
	ResourceType string   `json:"resource_type"`
	FindingIDs   []string `json:"finding_ids"`
	MaxSeverity  string   `json:"max_severity"`
	AccessPath   string   `json:"access_path"`
}

// IdentityRanking is the output of BuildIdentityRanking.
type IdentityRanking struct {
	TotalPortfolioRisk  float64             `json:"total_portfolio_risk_score"`
	IdentitiesEvaluated int                 `json:"identities_evaluated"`
	Entries             []IdentityRiskEntry `json:"identity_ranking"`
}

// identityAssetTypes identifies asset types that represent IAM identities.
var identityAssetTypes = map[kernel.AssetType]string{
	"aws_iam_role":       "role",
	"aws_iam_user":       "user",
	"aws_iam_access_key": "access_key",
}

// BuildIdentityRanking produces an identity-centric risk ranking from
// assessment findings and snapshot data. Each identity is ranked by its
// risk reduction potential — the fraction of total portfolio risk that
// would be addressed by remediating this identity.
func BuildIdentityRanking(
	findings []remediation.Finding,
	topExposures []risk.ExposureRank,
	snapshots []asset.Snapshot,
	topN int,
) IdentityRanking {
	if len(findings) == 0 {
		return IdentityRanking{}
	}

	// Compute per-finding risk scores using the same formula as BuildRoadmap.
	findingScores := computeFindingScores(findings, topExposures)
	totalRisk := 0.0
	for _, s := range findingScores {
		totalRisk += s
	}

	// Build finding lookup by asset ID.
	findingsByAsset := make(map[string][]int) // asset_id → finding indices
	for i := range findings {
		aid := string(findings[i].AssetID)
		findingsByAsset[aid] = append(findingsByAsset[aid], i)
	}

	// Build identity → reachable resources from snapshots.
	reachMap := buildReachabilityMap(snapshots, findings)

	// Identify all identities: from findings and from snapshots.
	type identityInfo struct {
		arn            string
		assetType      string
		identityType   string
		privilegeLevel string
	}
	identities := make(map[string]*identityInfo)

	// Identities from findings (IAM-type assets).
	for i := range findings {
		f := &findings[i]
		if itype, ok := identityAssetTypes[f.AssetType]; ok {
			arn := string(f.AssetID)
			if identities[arn] == nil {
				identities[arn] = &identityInfo{
					arn:          arn,
					assetType:    string(f.AssetType),
					identityType: itype,
				}
			}
		}
	}

	// Identities from snapshots.
	for si := range snapshots {
		snap := &snapshots[si]
		for ai := range snap.Assets {
			a := &snap.Assets[ai]
			if itype, ok := identityAssetTypes[a.Type]; ok {
				arn := string(a.ID)
				if identities[arn] == nil {
					identities[arn] = &identityInfo{
						arn:          arn,
						assetType:    string(a.Type),
						identityType: itype,
					}
				}
				identities[arn].privilegeLevel = resolvePrivilegeLevel(a.Properties)
			}
		}
	}

	// Build entries.
	entries := make([]IdentityRiskEntry, 0, len(identities))
	for arn, info := range identities {
		entry := IdentityRiskEntry{
			IdentityARN:    arn,
			IdentityType:   info.identityType,
			PrivilegeLevel: info.privilegeLevel,
		}

		// Direct findings on this identity.
		var directScore float64
		var directMaxSev policy.Severity
		for _, idx := range findingsByAsset[arn] {
			entry.DirectFindingIDs = append(entry.DirectFindingIDs, findings[idx].FindingID)
			directScore += findingScores[idx]
			if findings[idx].ControlSeverity > directMaxSev {
				directMaxSev = findings[idx].ControlSeverity
			}
			if act := findings[idx].RemediationSpec.Action; act != "" {
				entry.RemediationActions = appendUnique(entry.RemediationActions, strings.TrimSpace(act))
			}
		}
		entry.DirectSeverity = directMaxSev.String()

		// Reachable resources and transitive findings.
		var transitiveScore float64
		var transitiveMaxSev policy.Severity
		seenTransitive := make(map[string]bool)

		for _, reach := range reachMap[arn] {
			rr := ReachableResource{
				ResourceARN:  reach.resourceARN,
				ResourceType: reach.resourceType,
				AccessPath:   reach.accessPath,
			}
			var maxSev policy.Severity
			for _, idx := range findingsByAsset[reach.resourceARN] {
				fid := findings[idx].FindingID
				rr.FindingIDs = append(rr.FindingIDs, fid)
				if !seenTransitive[fid] {
					seenTransitive[fid] = true
					transitiveScore += findingScores[idx]
					entry.TransitiveFindingIDs = append(entry.TransitiveFindingIDs, fid)
				}
				if findings[idx].ControlSeverity > maxSev {
					maxSev = findings[idx].ControlSeverity
				}
				if findings[idx].ControlSeverity > transitiveMaxSev {
					transitiveMaxSev = findings[idx].ControlSeverity
				}
			}
			rr.MaxSeverity = maxSev.String()
			entry.ReachableResources = append(entry.ReachableResources, rr)
		}
		entry.ReachableCount = len(entry.ReachableResources)
		entry.TransitiveSeverity = transitiveMaxSev.String()

		entry.RiskReductionScore = directScore + transitiveScore
		if totalRisk > 0 {
			entry.RiskReductionPercent = (entry.RiskReductionScore / totalRisk) * 100
		}

		// Skip identities with zero risk contribution.
		if entry.RiskReductionScore == 0 && len(entry.DirectFindingIDs) == 0 {
			continue
		}

		entries = append(entries, entry)
	}

	// Sort by risk reduction (descending).
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].RiskReductionScore != entries[j].RiskReductionScore {
			return entries[i].RiskReductionScore > entries[j].RiskReductionScore
		}
		return entries[i].IdentityARN < entries[j].IdentityARN
	})

	for i := range entries {
		entries[i].Rank = i + 1
	}

	if topN > 0 && topN < len(entries) {
		entries = entries[:topN]
	}

	return IdentityRanking{
		TotalPortfolioRisk:  totalRisk,
		IdentitiesEvaluated: len(identities),
		Entries:             entries,
	}
}

// computeFindingScores computes the risk score for each finding using
// the same formula as BuildRoadmap: base × duration × blast × exposure × SLA.
func computeFindingScores(findings []remediation.Finding, topExposures []risk.ExposureRank) []float64 {
	exposureByKey := make(map[string]risk.ExposureRank, len(topExposures))
	for _, te := range topExposures {
		key := string(te.ControlID) + ":" + string(te.AssetID)
		exposureByKey[key] = te
	}

	scores := make([]float64, len(findings))
	for i := range findings {
		f := &findings[i]
		key := string(f.ControlID) + ":" + string(f.AssetID)

		var score float64
		if er, ok := exposureByKey[key]; ok {
			score = er.ExposureScore
		} else {
			base := risk.SeverityToWeight(f.ControlSeverity)
			durFactor := risk.DurationFactor(f.Evidence.UnsafeDurationHours)
			score = float64(base) * durFactor
		}

		if f.Evidence.ThresholdHours > 0 {
			remainingHours := f.Evidence.ThresholdHours - f.Evidence.UnsafeDurationHours
			isOverdue := f.Evidence.UnsafeDurationHours > f.Evidence.ThresholdHours
			score *= SLAUrgencyMultiplier(remainingHours, isOverdue)
		}
		scores[i] = score
	}
	return scores
}

type reachEntry struct {
	resourceARN  string
	resourceType string
	accessPath   string
}

// buildReachabilityMap builds identity → reachable resources from snapshots.
// It uses two signals:
//   - Resource policies (via ResourceAccessIndex) — resource → principal mapping inverted
//   - Execution role links — compute assets pointing to IAM roles
func buildReachabilityMap(snapshots []asset.Snapshot, findings []remediation.Finding) map[string][]reachEntry {
	reach := make(map[string][]reachEntry)

	// Build a set of resource ARNs that have findings.
	resourcesWithFindings := make(map[string]bool)
	for i := range findings {
		resourcesWithFindings[string(findings[i].AssetID)] = true
	}

	for si := range snapshots {
		snap := &snapshots[si]

		// 1. Resource policy grants: build ResourceAccessIndex, then invert.
		idx := buildResourceAccessIndex(snap)
		for resourceARN, entries := range invertResourceIndex(idx, snap) {
			for _, e := range entries {
				reach[e.PrincipalARN] = append(reach[e.PrincipalARN], reachEntry{
					resourceARN:  resourceARN,
					resourceType: e.ResourceType,
					accessPath:   "resource_policy",
				})
			}
		}

		// 2. Execution role links: Lambda/compute → IAM role.
		for ai := range snap.Assets {
			a := &snap.Assets[ai]
			roleARN := resolveProperty(a.Properties, []string{"compute", "execution_role", "role_arn"})
			if roleARN == "" {
				continue
			}
			reach[roleARN] = append(reach[roleARN], reachEntry{
				resourceARN:  string(a.ID),
				resourceType: string(a.Type),
				accessPath:   "execution_role",
			})
		}
	}

	return reach
}

type invertedEntry struct {
	PrincipalARN string
	ResourceType string
}

// invertResourceIndex inverts a ResourceAccessIndex: for each
// (resource, principal) pair, return a map of resource → principal entries.
func invertResourceIndex(idx *iam.ResourceAccessIndex, snap *asset.Snapshot) map[string][]invertedEntry {
	result := make(map[string][]invertedEntry)

	// Build asset type lookup.
	assetTypes := make(map[string]kernel.AssetType)
	for i := range snap.Assets {
		assetTypes[string(snap.Assets[i].ID)] = snap.Assets[i].Type
	}

	// Iterate all resources in the snapshot and check if they have access entries.
	for i := range snap.Assets {
		resourceARN := string(snap.Assets[i].ID)
		entries := idx.EntriesFor(resourceARN)
		for _, e := range entries {
			if e.IsPublic {
				continue // public access isn't attributable to a specific identity
			}
			result[resourceARN] = append(result[resourceARN], invertedEntry{
				PrincipalARN: e.PrincipalARN,
				ResourceType: string(assetTypes[resourceARN]),
			})
		}
	}

	return result
}

// buildResourceAccessIndex builds a ResourceAccessIndex from a snapshot.
// Replicates the logic from cmd/nep/resource.go.
func buildResourceAccessIndex(snap *asset.Snapshot) *iam.ResourceAccessIndex {
	idx := iam.NewResourceAccessIndex()
	for i := range snap.Assets {
		a := &snap.Assets[i]
		accountID := extractAccountID(string(a.ID))
		for _, path := range resourcePolicyPaths {
			policyJSON := resolveProperty(a.Properties, path)
			if policyJSON == "" {
				continue
			}
			_ = idx.AddResourcePolicy(string(a.ID), policyJSON, accountID)
		}
	}
	return idx
}

var resourcePolicyPaths = [][]string{
	{"storage", "policy_json"},
	{"encryption", "key_policy_json"},
	{"compute", "resource_policy_json"},
	{"messaging", "policy_json"},
	{"secret", "resource_policy_json"},
}

// resolveProperty navigates nested map[string]any properties.
func resolveProperty(props map[string]any, path []string) string {
	var current any = props
	for _, key := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current, ok = m[key]
		if !ok {
			return ""
		}
	}
	s, ok := current.(string)
	if !ok {
		return ""
	}
	return s
}

// resolvePrivilegeLevel extracts the privilege level from identity properties.
func resolvePrivilegeLevel(props map[string]any) string {
	level := resolveProperty(props, []string{"identity", "nep", "privilege_level"})
	if level != "" {
		return level
	}
	// Check for admin indicator.
	if resolveBool(props, []string{"identity", "nep", "is_admin"}) {
		return "admin"
	}
	if resolveBool(props, []string{"identity", "nep", "has_escalation_path"}) {
		return "elevated"
	}
	return "standard"
}

func resolveBool(props map[string]any, path []string) bool {
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

func extractAccountID(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}

func appendUnique(ss []string, s string) []string {
	if slices.Contains(ss, s) {
		return ss
	}
	return append(ss, s)
}
