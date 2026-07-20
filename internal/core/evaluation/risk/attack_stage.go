package risk

import (
	"cmp"
	"slices"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// allAttackStages lists the MITRE ATT&CK-aligned stages that Stave recognizes.
// Access via AttackStages() so the slice cannot be mutated by callers.
var allAttackStages = []kernel.AttackStage{
	kernel.AttackStageInitialAccess,
	kernel.AttackStageExecution,
	kernel.AttackStageCredentialAccess,
	kernel.AttackStagePersistence,
	kernel.AttackStagePrivilegeEscalation,
	kernel.AttackStageLateralMovement,
	kernel.AttackStageDiscovery,
	kernel.AttackStageCollection,
	kernel.AttackStageExfiltration,
	kernel.AttackStageDetectionEvasion,
	kernel.AttackStageImpact,
	kernel.AttackStageResilience,
}

// AttackStages returns a defensive copy of the recognised attack
// stages. Callers that need a stable list use this instead of touching
// the (now unexported) backing slice directly so a misbehaving
// consumer cannot mutate the catalog.
func AttackStages() []kernel.AttackStage {
	out := make([]kernel.AttackStage, len(allAttackStages))
	copy(out, allAttackStages)
	return out
}

// BuildAttackStageSummary maps each attack stage to the worst severity
// found across all findings. Stages with no findings are marked "PASS".
//
// failures is the slice of (control, asset) pairs with active violations.
// lookup maps control IDs to their definitions for attack_stage metadata.
func BuildAttackStageSummary(
	failures []FailingControl,
	lookup map[kernel.ControlID]*policy.ControlDefinition,
) map[kernel.AttackStage]string {
	// Track worst severity per stage, and which stages have any active
	// failure at all. Presence is tracked separately from the worst
	// severity because a failing control may carry SeverityNone (0),
	// which is the zero value of the severity map and would otherwise be
	// indistinguishable from "no failure here."
	worstPerStage := make(map[kernel.AttackStage]policy.Severity)
	failedStages := make(map[kernel.AttackStage]struct{})

	for i := range failures {
		cid := failures[i].ControlID
		ctl, ok := lookup[cid]
		if !ok {
			continue
		}
		stage := ctl.AttackStage()
		if stage == "" {
			continue
		}
		failedStages[stage] = struct{}{}
		sev := ctl.Severity
		if sev > worstPerStage[stage] {
			worstPerStage[stage] = sev
		}
	}

	// Build summary with all known stages.
	summary := make(map[kernel.AttackStage]string, len(allAttackStages))
	for _, stage := range allAttackStages {
		if _, ok := failedStages[stage]; !ok {
			summary[stage] = "PASS"
			continue
		}
		// Stage has an active failure: never report PASS. severityLabel
		// returns "PASS" for SeverityNone, so floor the displayed
		// severity at INFO to keep an active failure distinguishable
		// from a clean stage.
		sev := worstPerStage[stage]
		if !sev.IsSet() {
			sev = policy.SeverityInfo
		}
		summary[stage] = severityLabel(sev)
	}

	return summary
}

// killChainOrder defines the MITRE ATT&CK-aligned kill chain
// ordering. Lower index = earlier in the chain. Unrecognized stages
// sort after all known stages.
var killChainOrder = map[kernel.AttackStage]int{
	kernel.AttackStageInitialAccess:       0,
	kernel.AttackStageExecution:           1,
	kernel.AttackStageCredentialAccess:    2,
	kernel.AttackStagePersistence:         3,
	kernel.AttackStagePrivilegeEscalation: 4,
	kernel.AttackStageDiscovery:           5,
	kernel.AttackStageLateralMovement:     6,
	kernel.AttackStageCollection:          7,
	kernel.AttackStageExfiltration:        8,
	kernel.AttackStageDetectionEvasion:    9,
	kernel.AttackStageImpact:              10,
	kernel.AttackStageResilience:          11,
}

// SortStagesByKillChain returns a copy of stages sorted by kill chain
// order (earliest stage first).
func SortStagesByKillChain(stages []kernel.AttackStage) []kernel.AttackStage {
	out := slices.Clone(stages)
	slices.SortFunc(out, func(a, b kernel.AttackStage) int {
		oa, oka := killChainOrder[a]
		ob, okb := killChainOrder[b]
		if !oka {
			oa = 999
		}
		if !okb {
			ob = 999
		}
		return cmp.Compare(oa, ob)
	})
	return out
}

func severityLabel(s policy.Severity) string {
	switch s {
	case policy.SeverityCritical:
		return "CRITICAL"
	case policy.SeverityHigh:
		return "HIGH"
	case policy.SeverityMedium:
		return "MEDIUM"
	case policy.SeverityLow:
		return "LOW"
	case policy.SeverityInfo:
		return "INFO"
	default:
		return "PASS"
	}
}
