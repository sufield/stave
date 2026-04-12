package risk

import (
	"sort"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// AllAttackStages lists the MITRE ATT&CK-aligned stages that Stave recognizes.
var AllAttackStages = []string{
	"initial_access",
	"credential_access",
	"persistence",
	"exfiltration",
	"detection_evasion",
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
