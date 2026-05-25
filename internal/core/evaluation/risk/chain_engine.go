package risk

import (
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	findingsdata "github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
)

// FailingControl is a (control, asset) pair for a detected violation.
// Used as input to chain and attack-stage analysis to preserve asset context.
// Stays in risk/ as a chain-engine input type — it isn't carried on
// report.Assessment, so it doesn't migrate to findings/.
type FailingControl struct {
	ControlID kernel.ControlID
	AssetID   asset.ID
}

// ScopeResolver returns the value at the given property path on the
// asset identified by assetID. The second return is false when the
// asset is unknown or the path resolves to an empty / non-scalar
// value. The chain engine treats false the same as ScopeField unset
// for that one (asset, chain) pair: the failing control falls back to
// asset.ID grouping.
type ScopeResolver func(assetID asset.ID, path string) (string, bool)

// DetectChains checks each chain definition: a chain fires only when
// enough of its member controls fail within a single grouping bucket.
// The grouping bucket is asset.ID by default; when the chain declares
// ScopeField, it is the resolved value of that property path on each
// failing asset (e.g. user_pool_id reuniting per-trigger Cognito
// ghost findings that surface on distinct asset.IDs).
//
// failures is the set of (control, asset) pairs with active violations.
// chains is the catalog of chain definitions to check.
// controlLookup maps control IDs to their definitions (attack stage,
// blast multiplier).
// scopeResolver may be nil; when nil, every chain falls back to
// asset.ID grouping regardless of ScopeField.
func DetectChains(
	failures []FailingControl,
	chains []policy.ChainDefinition,
	controlLookup map[kernel.ControlID]*policy.ControlDefinition,
	scopeResolver ScopeResolver,
) []findingsdata.CompoundFinding {
	var findings []findingsdata.CompoundFinding

	for i := range chains {
		chain := &chains[i]

		// chainMembers is a set of the chain's member control IDs so we
		// can ignore failures of unrelated controls when bucketing.
		chainMembers := make(map[kernel.ControlID]bool, len(chain.ControlIDs))
		for _, cid := range chain.ControlIDs {
			chainMembers[cid] = true
		}

		// Group failing controls by either asset.ID (default) or the
		// resolved scope value. The chain-local map mirrors the legacy
		// per-asset map, plus a parallel map of scope -> contributing
		// asset IDs so the compound finding can surface every asset
		// that fed the chain. resolvedByScope tracks whether AT LEAST
		// one member of a bucket resolved via scope_field — used at
		// emission to decide whether to populate ScopeID/ScopeField on
		// the output. A bucket where every member fell back to asset.ID
		// is a pure asset.ID bucket (legacy semantics) even when
		// chain.ScopeField is set.
		//
		// Only failures whose ControlID is one of the chain's members
		// participate. A user-pool client with RESOURCESRV failing in
		// the same scope as IDCHAIN's user-pool-side findings would
		// otherwise inflate contributing_assets with an asset that
		// fired no chain control — surface noise that misrepresents
		// what the chain actually saw.
		byScope := make(map[string]map[kernel.ControlID]bool)
		assetsByScope := make(map[string]map[asset.ID]bool)
		resolvedByScope := make(map[string]bool)
		for j := range failures {
			f := &failures[j]
			if !chainMembers[f.ControlID] {
				continue
			}
			scope, resolved := groupingKey(chain, f.AssetID, scopeResolver)
			if byScope[scope] == nil {
				byScope[scope] = make(map[kernel.ControlID]bool)
				assetsByScope[scope] = make(map[asset.ID]bool)
			}
			byScope[scope][f.ControlID] = true
			assetsByScope[scope][f.AssetID] = true
			if resolved {
				resolvedByScope[scope] = true
			}
		}

		for scope, scopeFailing := range byScope {
			var failing []kernel.ControlID
			var holding []kernel.ControlID
			for _, cid := range chain.ControlIDs {
				if scopeFailing[cid] {
					failing = append(failing, cid)
				} else {
					holding = append(holding, cid)
				}
			}

			if len(failing) < chain.EscalationThreshold {
				continue
			}

			// Collect attack stages and compute scope-aware blast multiplier.
			stageSet := make(map[kernel.AttackStage]bool)
			maxBlast := 1.0
			for _, cid := range failing {
				if ctl, ok := controlLookup[cid]; ok {
					if stage := ctl.AttackStage(); stage != "" {
						stageSet[stage] = true
					}
					mult := scopeAdjustedBlast(ctl)
					if mult > maxBlast {
						maxBlast = mult
					}
				}
			}

			stages := make([]kernel.AttackStage, 0, len(stageSet))
			for s := range stageSet {
				stages = append(stages, s)
			}
			slices.SortFunc(stages, func(a, b kernel.AttackStage) int {
				return strings.Compare(string(a), string(b))
			})

			escalation := ChainEscalation(len(failing))
			// Derive base score from the highest severity among failing
			// member controls rather than a hardcoded default.
			base := baseScoreFromMembers(failing, controlLookup)
			score := Compound(base, escalation, maxBlast)
			if score > float64(ScoreCatastrophic) {
				score = float64(ScoreCatastrophic)
			}

			narrative := buildNarrative(chain, failing)

			contributing := sortedAssetIDs(assetsByScope[scope])
			finding := findingsdata.CompoundFinding{
				ChainID:           chain.ID,
				AssetID:           contributing[0], // representative; deterministic via sort
				Description:       chain.Description,
				ControlsFailing:   failing,
				MissingSafeguards: holding,
				CompoundScore:     score,
				Severity:          chain.CompoundSeverity,
				Narrative:         narrative,
				AttackStages:      stages,
			}
			// ContributingAssets and ScopeID/ScopeField surface only on
			// scope-grouped chains. For legacy asset.ID-grouped chains
			// every contributing asset.ID equals AssetID, so the slice
			// would duplicate the existing field — and adding it
			// unconditionally would churn every chain golden in the
			// repo. Emit only when scope_field actually drove grouping.
			if chain.ScopeField != "" && resolvedByScope[scope] {
				finding.ScopeID = scope
				finding.ScopeField = chain.ScopeField
				finding.ContributingAssets = contributing
			}
			findings = append(findings, finding)
		}
	}

	// Sort by (chain id, scope id, asset id) so the output is deterministic
	// across runs. The inner loop above iterates a map keyed by scope, and
	// Go randomizes map iteration order — without a final sort, two runs
	// on identical input produce different chain_findings orderings, which
	// surfaces as fixture flakes.
	slices.SortFunc(findings, func(a, b findingsdata.CompoundFinding) int {
		if c := strings.Compare(string(a.ChainID), string(b.ChainID)); c != 0 {
			return c
		}
		if c := strings.Compare(a.ScopeID, b.ScopeID); c != 0 {
			return c
		}
		return strings.Compare(string(a.AssetID), string(b.AssetID))
	})

	return findings
}

// groupingKey returns the scope value to use when bucketing one failing
// control under a chain, plus a flag indicating whether the value came
// from the resolver (true) or from the asset.ID fallback (false). When
// the chain declares ScopeField and the resolver returns a non-empty
// value, that value is the key and resolved=true; otherwise the
// asset.ID is used and resolved=false. The asset.ID fallback also
// applies when the resolver is nil — defensive for tests and any caller
// that has no asset properties at hand.
func groupingKey(chain *policy.ChainDefinition, assetID asset.ID, resolver ScopeResolver) (string, bool) {
	if chain.ScopeField == "" || resolver == nil {
		return string(assetID), false
	}
	if v, ok := resolver(assetID, chain.ScopeField); ok && v != "" {
		return v, true
	}
	return string(assetID), false
}

// sortedAssetIDs returns the keys of the set in lexical order so chain
// findings are deterministic across runs.
func sortedAssetIDs(set map[asset.ID]bool) []asset.ID {
	out := make([]asset.ID, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	slices.SortFunc(out, func(a, b asset.ID) int {
		return strings.Compare(string(a), string(b))
	})
	return out
}

// baseScoreFromMembers derives the chain base score from the highest
// severity among its failing member controls.
func baseScoreFromMembers(
	failing []kernel.ControlID,
	controlLookup map[kernel.ControlID]*policy.ControlDefinition,
) float64 {
	maxSev := policy.SeverityLow
	for _, cid := range failing {
		if ctl, ok := controlLookup[cid]; ok {
			if ctl.Severity > maxSev {
				maxSev = ctl.Severity
			}
		}
	}
	switch maxSev {
	case policy.SeverityCritical:
		return float64(ScoreCritical) // 90
	case policy.SeverityHigh:
		return 75
	case policy.SeverityMedium:
		return 50
	default:
		return float64(ScoreInfo)
	}
}

// scopeAdjustedBlast computes the effective blast multiplier based on
// the control's declared scope. Account-scoped controls (CloudTrail)
// apply their full multiplier because they blind the entire account.
// Network-scoped controls (VPC Flow Logs) are attenuated because the
// chain may span resources outside that network. Resource-scoped
// controls (S3 logging) are further attenuated because the detection
// gap is local to one resource.
//
// This prevents a single disabled S3 access log from inflating scores
// across unrelated resources — the multiplier is proportional to the
// blast radius scope.
//
// Attenuation model rationale:
//
//	account (1.00x): No attenuation — account-scoped controls affect
//	  every resource. A disabled CloudTrail blinds the entire account.
//
//	network (0.75x of excess): Network access controls (VPC, SGs, NACLs)
//	  provide a partial barrier. A misconfigured resource behind a
//	  network control is 75% as impactful because the network layer
//	  adds friction for an attacker.
//
//	resource (0.50x of excess): A resource-level control (bucket policy,
//	  KMS key policy) provides a stronger barrier than network controls.
//	  Misconfiguration requires both a network path AND a resource
//	  policy bypass — 50% as impactful as direct exposure.
//
// These values are intentional defaults derived from defense-in-depth
// layering. Organizations with different network posture assumptions
// can override blast multipliers per control definition.
func scopeAdjustedBlast(ctl *policy.ControlDefinition) float64 {
	mult := ctl.BlastMultiplier()
	if mult <= 1.0 {
		return 1.0
	}

	scope := ctl.BlastScope()
	switch scope {
	case kernel.BlastScopeAccount:
		return mult // Full multiplier — blinds everything
	case kernel.BlastScopeNetwork:
		// Attenuate: network scope may not cover all chain resources.
		// Apply 75% of the excess above 1.0.
		return 1.0 + (mult-1.0)*0.75
	case kernel.BlastScopeResource:
		// Attenuate further: local detection gap.
		// Apply 50% of the excess above 1.0.
		return 1.0 + (mult-1.0)*0.50
	default:
		return mult
	}
}

func buildNarrative(chain *policy.ChainDefinition, failing []kernel.ControlID) string {
	ids := make([]string, len(failing))
	for i, id := range failing {
		ids[i] = string(id)
	}
	return chain.Description + " Failing: " + strings.Join(ids, ", ") + "."
}
