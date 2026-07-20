// Package attack defines vendor-neutral mappings between Stave
// attack-stage names and external taxonomies (ATT&CK tactics, STIX
// kill-chain phases). Pure lookup data — no graph-export semantics —
// so consumers in core/app and the graph adapter can both import it
// without pulling the wider graph package.
package attack

import "github.com/sufield/stave/internal/core/kernel"

// attackStageToTactic maps Stave attack stage strings to ATT&CK tactic IDs.
// Source: docs/ontology/attack-stages.json
var attackStageToTactic = map[kernel.AttackStage]string{
	kernel.AttackStageInitialAccess:       "TA0001",
	kernel.AttackStageExecution:           "TA0002",
	kernel.AttackStagePersistence:         "TA0003",
	kernel.AttackStagePrivilegeEscalation: "TA0004",
	kernel.AttackStageDetectionEvasion:    "TA0005",
	kernel.AttackStageCredentialAccess:    "TA0006",
	kernel.AttackStageDiscovery:           "TA0007",
	kernel.AttackStageLateralMovement:     "TA0008",
	kernel.AttackStageCollection:          "TA0009",
	kernel.AttackStageExfiltration:        "TA0010",
	kernel.AttackStageImpact:              "TA0040",
	kernel.AttackStageResilience:          "x_stave_resilience",
}

// ToATTCKTacticID translates a Stave attack stage to an ATT&CK tactic ID.
func ToATTCKTacticID(staveStage kernel.AttackStage) string {
	if id, ok := attackStageToTactic[staveStage]; ok {
		return id
	}
	return ""
}

// TranslateStages converts a slice of Stave stages to ATT&CK tactic IDs.
func TranslateStages(stages []kernel.AttackStage) []string {
	out := make([]string, 0, len(stages))
	for _, s := range stages {
		if id := ToATTCKTacticID(s); id != "" {
			out = append(out, id)
		}
	}
	return out
}

// ToKillChainPhases produces STIX 2.1 kill_chain_phases from Stave stages.
func ToKillChainPhases(stages []kernel.AttackStage) []map[string]string {
	out := make([]map[string]string, 0, len(stages))
	for _, s := range stages {
		phase := staveToKillChainPhase(s)
		if phase != "" {
			out = append(out, map[string]string{
				"kill_chain_name": "mitre-attack",
				"phase_name":      phase,
			})
		}
	}
	return out
}

// staveToKillChainPhases maps a Stave attack stage to its STIX 2.1
// kill_chain_phase phase_name. Hoisted to package level so each call
// to staveToKillChainPhase does not re-allocate the table — on a
// large export with hundreds of chain findings this map was being
// rebuilt thousands of times per call to ToKillChainPhases.
var staveToKillChainPhases = map[kernel.AttackStage]string{ //nolint:gosec // G101: not credentials — ATT&CK tactic names
	kernel.AttackStageInitialAccess:       "initial-access",
	kernel.AttackStageExecution:           "execution",
	kernel.AttackStagePersistence:         "persistence",
	kernel.AttackStagePrivilegeEscalation: "privilege-escalation",
	kernel.AttackStageDetectionEvasion:    "defense-evasion",
	kernel.AttackStageCredentialAccess:    "credential-access",
	kernel.AttackStageDiscovery:           "discovery",
	kernel.AttackStageLateralMovement:     "lateral-movement",
	kernel.AttackStageCollection:          "collection",
	kernel.AttackStageExfiltration:        "exfiltration",
	kernel.AttackStageImpact:              "impact",
}

func staveToKillChainPhase(stage kernel.AttackStage) string {
	return staveToKillChainPhases[stage]
}
