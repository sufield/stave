package risk

import (
	"sort"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// AllAttackStages lists the MITRE ATT&CK-aligned stages that Stave recognizes.
var AllAttackStages = []string{
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

// BuildAttackStageSummary maps each attack stage to the worst severity
// found across all findings. Stages with no findings are marked "PASS".
//
// failingControlIDs is the set of control IDs that have violations.
// lookup maps control IDs to their definitions for attack_stage metadata.
func BuildAttackStageSummary(
	failingControlIDs map[kernel.ControlID]bool,
	lookup map[kernel.ControlID]*policy.ControlDefinition,
) map[string]string {
	// Track worst severity per stage.
	worstPerStage := make(map[string]policy.Severity)

	for cid := range failingControlIDs {
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
	summary := make(map[string]string, len(AllAttackStages))
	for _, stage := range AllAttackStages {
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
func AttackStagesFromFindings(findings []CompoundFinding) []string {
	seen := make(map[string]bool)
	for i := range findings {
		for _, s := range findings[i].AttackStages {
			seen[s] = true
		}
	}
	var stages []string
	for s := range seen {
		stages = append(stages, s)
	}
	sort.Strings(stages)
	return stages
}

// killChainOrder defines the MITRE ATT&CK-aligned kill chain
// ordering. Lower index = earlier in the chain. Unrecognized stages
// sort after all known stages.
var killChainOrder = map[string]int{
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
func SortStagesByKillChain(stages []string) []string {
	out := make([]string, len(stages))
	copy(out, stages)
	sort.Slice(out, func(i, j int) bool {
		oi, oki := killChainOrder[out[i]]
		oj, okj := killChainOrder[out[j]]
		if !oki {
			oi = 999
		}
		if !okj {
			oj = 999
		}
		return oi < oj
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
