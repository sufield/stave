package risk

import (
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// FailingControl is a (control, asset) pair for a detected violation.
// Used as input to chain and attack-stage analysis to preserve asset context.
type FailingControl struct {
	ControlID kernel.ControlID
	AssetID   asset.ID
}

// CompoundFinding represents a chain-detected compound risk — multiple
// co-failing controls that together create a risk greater than their sum.
type CompoundFinding struct {
	ChainID           kernel.ChainID     `json:"chain"`
	AssetID           asset.ID           `json:"asset_id,omitempty"`
	Description       string             `json:"description,omitempty"`
	ControlsFailing   []kernel.ControlID `json:"controls_failing"`
	MissingSafeguards []kernel.ControlID `json:"missing_safeguards,omitempty"`
	CompoundScore     float64            `json:"compound_score"`
	Severity          policy.Severity    `json:"severity"`
	Narrative         string             `json:"narrative"`
	AttackStages      []string           `json:"attack_stages,omitempty"`
}

// DetectChains checks each chain definition per asset: a chain fires only
// when a single asset has enough of the chain's controls failing. This
// prevents a control failing on asset A from triggering compound risk for
// an unrelated asset B.
//
// failures is the set of (control, asset) pairs with active violations.
// chains is the catalog of chain definitions to check.
// controlLookup maps control IDs to their definitions (for attack stage).
func DetectChains(
	failures []FailingControl,
	chains []policy.ChainDefinition,
	controlLookup map[kernel.ControlID]*policy.ControlDefinition,
) []CompoundFinding {
	// Group failing control IDs by asset.
	byAsset := make(map[asset.ID]map[kernel.ControlID]bool)
	for i := range failures {
		f := &failures[i]
		if byAsset[f.AssetID] == nil {
			byAsset[f.AssetID] = make(map[kernel.ControlID]bool)
		}
		byAsset[f.AssetID][f.ControlID] = true
	}

	var findings []CompoundFinding

	for i := range chains {
		chain := &chains[i]
		for assetID, assetFailing := range byAsset {
			var failing []kernel.ControlID
			var holding []kernel.ControlID
			for _, cid := range chain.ControlIDs {
				if assetFailing[cid] {
					failing = append(failing, cid)
				} else {
					holding = append(holding, cid)
				}
			}

			if len(failing) < chain.EscalationThreshold {
				continue
			}

			// Collect attack stages and compute scope-aware blast multiplier.
			stageSet := make(map[string]bool)
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

			var stages []string
			for s := range stageSet {
				stages = append(stages, s)
			}
			slices.Sort(stages)

			escalation := ChainEscalation(len(failing))
			// Derive base score from the highest severity among failing
			// member controls rather than a hardcoded default.
			base := baseScoreFromMembers(failing, controlLookup)
			score := Compound(base, escalation, maxBlast)
			if score > float64(ScoreCatastrophic) {
				score = float64(ScoreCatastrophic)
			}

			narrative := buildNarrative(chain, failing)

			findings = append(findings, CompoundFinding{
				ChainID:           chain.ID,
				AssetID:           assetID,
				Description:       chain.Description,
				ControlsFailing:   failing,
				MissingSafeguards: holding,
				CompoundScore:     score,
				Severity:          chain.CompoundSeverity,
				Narrative:         narrative,
				AttackStages:      stages,
			})
		}
	}

	// Sort by (chain id, asset id) so the output is deterministic across
	// runs. The inner loop above iterates a map keyed by asset.ID, and Go
	// randomizes map iteration order — without a final sort, two runs on
	// identical input produce different chain_findings orderings, which
	// surfaces as fixture flakes (e.g. etcd-dev-01 vs etcd-staging-01
	// swapping positions in k8s-cis-level1's golden).
	slices.SortFunc(findings, func(a, b CompoundFinding) int {
		if c := strings.Compare(string(a.ChainID), string(b.ChainID)); c != 0 {
			return c
		}
		return strings.Compare(string(a.AssetID), string(b.AssetID))
	})

	return findings
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
	case "account":
		return mult // Full multiplier — blinds everything
	case "network":
		// Attenuate: network scope may not cover all chain resources.
		// Apply 75% of the excess above 1.0.
		return 1.0 + (mult-1.0)*0.75
	case "resource":
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
