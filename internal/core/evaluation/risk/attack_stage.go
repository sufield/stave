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
	"initial_access",
	"execution",
	"credential_access",
	"persistence",
	"privilege_escalation",
	"lateral_movement",
	"discovery",
	"collection",
	"exfiltration",
	"detection_evasion",
	"impact",
	"resilience",
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
	// Track worst severity per stage.
	worstPerStage := make(map[kernel.AttackStage]policy.Severity)

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
		sev := ctl.Severity
		if sev > worstPerStage[stage] {
			worstPerStage[stage] = sev
		}
	}

	// Build summary with all known stages.
	summary := make(map[kernel.AttackStage]string, len(allAttackStages))
	for _, stage := range allAttackStages {
		if sev, ok := worstPerStage[stage]; ok {
			summary[stage] = severityLabel(sev)
		} else {
			summary[stage] = "PASS"
		}
	}

	return summary
}

// AttackStagesFromFindings extracts the unique, sorted attack stages
// from a set of compound findings.
func AttackStagesFromFindings(findings []CompoundFinding) []kernel.AttackStage {
	seen := make(map[kernel.AttackStage]bool)
	for i := range findings {
		for _, s := range findings[i].AttackStages {
			seen[s] = true
		}
	}
	stages := make([]kernel.AttackStage, 0, len(seen))
	for s := range seen {
		stages = append(stages, s)
	}
	slices.SortFunc(stages, func(a, b kernel.AttackStage) int {
		return cmp.Compare(string(a), string(b))
	})
	return stages
}

// killChainOrder defines the MITRE ATT&CK-aligned kill chain
// ordering. Lower index = earlier in the chain. Unrecognized stages
// sort after all known stages.
var killChainOrder = map[kernel.AttackStage]int{
	"initial_access":       0,
	"execution":            1,
	"credential_access":    2,
	"persistence":          3,
	"privilege_escalation": 4,
	"discovery":            5,
	"lateral_movement":     6,
	"collection":           7,
	"exfiltration":         8,
	"detection_evasion":    9,
	"impact":               10,
	"resilience":           11,
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
