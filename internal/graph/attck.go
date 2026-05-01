// Package graph provides the graph-json export builder.
package graph

import "github.com/sufield/stave/internal/core/kernel"

// attackStageToTactic maps Stave attack stage strings to ATT&CK tactic IDs.
// Source: docs/ontology/attack-stages.json
var attackStageToTactic = map[kernel.AttackStage]string{
	"initial_access":       "TA0001",
	"execution":            "TA0002",
	"persistence":          "TA0003",
	"privilege_escalation": "TA0004",
	"detection_evasion":    "TA0005",
	"credential_access":    "TA0006",
	"discovery":            "TA0007",
	"lateral_movement":     "TA0008",
	"collection":           "TA0009",
	"exfiltration":         "TA0010",
	"impact":               "TA0040",
	"resilience":           "x_stave_resilience",
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
	"initial_access":       "initial-access",
	"execution":            "execution",
	"persistence":          "persistence",
	"privilege_escalation": "privilege-escalation",
	"detection_evasion":    "defense-evasion",
	"credential_access":    "credential-access",
	"discovery":            "discovery",
	"lateral_movement":     "lateral-movement",
	"collection":           "collection",
	"exfiltration":         "exfiltration",
	"impact":               "impact",
}

func staveToKillChainPhase(stage kernel.AttackStage) string {
	return staveToKillChainPhases[stage]
}
