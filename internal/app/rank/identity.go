package rank

import (
	"log/slog"
	"slices"
	"sort"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/iam"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/util/props"
)

// IdentityRiskEntry represents a single identity and its transitive risk.
type IdentityRiskEntry struct {
	IdentityARN    IdentityARN `json:"identity_arn"`
	IdentityType   string      `json:"identity_type"`
	PrivilegeLevel string      `json:"privilege_level"`

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
	ResourceARN  ResourceARN `json:"resource_arn"`
	ResourceType string      `json:"resource_type"`
	FindingIDs   []string    `json:"finding_ids"`
	MaxSeverity  string      `json:"max_severity"`
	AccessPath   string      `json:"access_path"`
}

// IdentityRanking is the output of BuildIdentityRanking.
type IdentityRanking struct {
	TotalPortfolioRisk  float64             `json:"total_portfolio_risk_score"`
	IdentitiesEvaluated int                 `json:"identities_evaluated"`
	Entries             []IdentityRiskEntry `json:"identity_ranking"`
}

// BuildIdentityRanking produces an identity-centric risk ranking from
// assessment findings and snapshot data. Each identity is ranked by its
// risk reduction potential — the fraction of total portfolio risk that
// would be addressed by remediating this identity.
// IdentityRankingConfig holds parameters for BuildIdentityRanking.
type IdentityRankingConfig struct {
	Findings     []remediation.Finding
	TopExposures []risk.ExposureRank
	Snapshots    []asset.Snapshot
	TopN         int
}

// BuildIdentityRanking orchestrates identity risk ranking in three phases:
// index construction, entry building with transitive risk, and final ranking.
func BuildIdentityRanking(cfg IdentityRankingConfig) IdentityRanking {
	if len(cfg.Findings) == 0 {
		return IdentityRanking{}
	}

	findingScores := computeFindingScores(cfg.Findings, cfg.TopExposures)
	index := buildIdentityIndex(cfg.Findings, cfg.Snapshots)
	entries, totalRisk := buildIdentityEntries(cfg.Findings, findingScores, index, cfg.Snapshots)
	return rankIdentities(entries, totalRisk, len(index), cfg.TopN)
}

// identityInfo holds identity metadata during index construction.
type identityInfo struct {
	arn            string
	assetType      string
	identityType   string
	privilegeLevel string
}

// buildIdentityIndex collects all identities from findings and snapshots.
func buildIdentityIndex(
	findings []remediation.Finding,
	snapshots []asset.Snapshot,
) map[string]*identityInfo {
	identities := make(map[string]*identityInfo)

	for i := range findings {
		f := &findings[i]
		if !asset.IsIdentityAssetType(f.AssetType) {
			continue
		}
		arn := string(f.AssetID)
		if identities[arn] == nil {
			identities[arn] = &identityInfo{
				arn:          arn,
				assetType:    string(f.AssetType),
				identityType: asset.IdentityClassificationFor(f.AssetType),
			}
		}
	}

	for si := range snapshots {
		snap := &snapshots[si]
		for ai := range snap.Assets {
			a := &snap.Assets[ai]
			if !a.IsIdentityAsset() {
				continue
			}
			arn := string(a.ID)
			if identities[arn] == nil {
				identities[arn] = &identityInfo{
					arn:          arn,
					assetType:    string(a.Type),
					identityType: a.IdentityClassification(),
				}
			}
			identities[arn].privilegeLevel = resolvePrivilegeLevel(a.Properties)
		}
	}

	return identities
}

// buildIdentityEntries constructs risk entries for each identity,
// including direct and transitive risk from reachable resources.
func buildIdentityEntries(
	findings []remediation.Finding,
	findingScores []float64,
	identities map[string]*identityInfo,
	snapshots []asset.Snapshot,
) ([]IdentityRiskEntry, float64) {
	totalRisk := 0.0
	for _, s := range findingScores {
		totalRisk += s
	}

	findingsByAsset := make(map[string][]int)
	for i := range findings {
		aid := string(findings[i].AssetID)
		findingsByAsset[aid] = append(findingsByAsset[aid], i)
	}

	reachMap := buildReachabilityMap(snapshots, findings)

	entries := make([]IdentityRiskEntry, 0, len(identities))
	for arn, info := range identities {
		entry := IdentityRiskEntry{
			IdentityARN:    IdentityARN(arn),
			IdentityType:   info.identityType,
			PrivilegeLevel: info.privilegeLevel,
		}

		var directScore float64
		var directMaxSev policy.Severity
		for _, idx := range findingsByAsset[arn] {
			entry.DirectFindingIDs = append(entry.DirectFindingIDs, string(findings[idx].FindingID))
			directScore += findingScores[idx]
			directMaxSev = findings[idx].MaxSeverityWith(directMaxSev)
			if act := findings[idx].RemediationSpec.Action; act != "" {
				entry.RemediationActions = appendUnique(entry.RemediationActions, strings.TrimSpace(act))
			}
		}
		entry.DirectSeverity = directMaxSev.String()

		var transitiveScore float64
		var transitiveMaxSev policy.Severity
		seenTransitive := make(map[string]bool)

		for _, reach := range reachMap[arn] {
			rr := ReachableResource{
				ResourceARN:  ResourceARN(reach.resourceARN),
				ResourceType: reach.resourceType,
				AccessPath:   reach.accessPath,
			}
			var maxSev policy.Severity
			for _, idx := range findingsByAsset[reach.resourceARN] {
				fid := string(findings[idx].FindingID)
				rr.FindingIDs = append(rr.FindingIDs, fid)
				if !seenTransitive[fid] {
					seenTransitive[fid] = true
					transitiveScore += findingScores[idx]
					entry.TransitiveFindingIDs = append(entry.TransitiveFindingIDs, fid)
				}
				maxSev = findings[idx].MaxSeverityWith(maxSev)
				transitiveMaxSev = findings[idx].MaxSeverityWith(transitiveMaxSev)
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

		if entry.RiskReductionScore == 0 && len(entry.DirectFindingIDs) == 0 {
			continue
		}

		entries = append(entries, entry)
	}

	return entries, totalRisk
}

// rankIdentities sorts entries by risk reduction and applies topN limit.
func rankIdentities(entries []IdentityRiskEntry, totalRisk float64, identitiesEvaluated, topN int) IdentityRanking {
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
		IdentitiesEvaluated: identitiesEvaluated,
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
			score = er.ExposureScore.Value()
		} else {
			base := f.ControlSeverity.Weight()
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
			roleARN := props.GetString(a.Properties, []string{"compute", "execution_role", "role_arn"})
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
			policyJSON := props.GetString(a.Properties, path)
			if policyJSON == "" {
				continue
			}
			// Non-fatal: malformed policy JSON skips annotation, but a
			// silent skip masks the operator's bad input. Surface the
			// reason at Debug — the rank index is already lossy when a
			// policy fails to parse, and the operator needs a trail.
			if addErr := idx.AddResourcePolicy(string(a.ID), policyJSON, accountID); addErr != nil {
				slog.Debug("rank: skip resource policy annotation",
					"asset", a.ID, "path", strings.Join(path, "."), "err", addErr)
			}
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

// resolvePrivilegeLevel extracts the privilege level from identity properties.
func resolvePrivilegeLevel(p map[string]any) string {
	level := props.GetString(p, []string{"identity", "nep", "privilege_level"})
	if level != "" {
		return level
	}
	if props.GetBool(p, []string{"identity", "nep", "is_admin"}) {
		return "admin"
	}
	if props.GetBool(p, []string{"identity", "nep", "has_escalation_path"}) {
		return "elevated"
	}
	return "standard"
}

func extractAccountID(arn string) string {
	return iam.ExtractAccountID(arn)
}

func appendUnique(ss []string, s string) []string {
	if slices.Contains(ss, s) {
		return ss
	}
	return append(ss, s)
}
