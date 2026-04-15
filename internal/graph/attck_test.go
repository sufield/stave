package graph

import "testing"

func TestToATTCKTacticID_AllStages(t *testing.T) {
	tests := []struct {
		stage string
		want  string
	}{
		{"initial_access", "TA0001"},
		{"execution", "TA0002"},
		{"persistence", "TA0003"},
		{"privilege_escalation", "TA0004"},
		{"detection_evasion", "TA0005"},
		{"credential_access", "TA0006"},
		{"discovery", "TA0007"},
		{"lateral_movement", "TA0008"},
		{"collection", "TA0009"},
		{"exfiltration", "TA0010"},
		{"impact", "TA0040"},
		{"resilience", "x_stave_resilience"},
	}
	for _, tt := range tests {
		got := ToATTCKTacticID(tt.stage)
		if got != tt.want {
			t.Errorf("ToATTCKTacticID(%q) = %q, want %q", tt.stage, got, tt.want)
		}
	}
}

func TestToATTCKTacticID_Unknown(t *testing.T) {
	got := ToATTCKTacticID("nonexistent")
	if got != "" {
		t.Errorf("unknown stage should return empty, got %q", got)
	}
}

func TestTranslateStages(t *testing.T) {
	got := TranslateStages([]string{"initial_access", "exfiltration"})
	if len(got) != 2 || got[0] != "TA0001" || got[1] != "TA0010" {
		t.Errorf("TranslateStages = %v, want [TA0001, TA0010]", got)
	}
}

func TestToKillChainPhases(t *testing.T) {
	got := ToKillChainPhases([]string{"initial_access", "exfiltration"})
	if len(got) != 2 {
		t.Fatalf("expected 2 phases, got %d", len(got))
	}
	if got[0]["kill_chain_name"] != "mitre-attack" || got[0]["phase_name"] != "initial-access" {
		t.Errorf("phase 0 = %v", got[0])
	}
	if got[1]["phase_name"] != "exfiltration" {
		t.Errorf("phase 1 = %v", got[1])
	}
}

func TestToKillChainPhases_Resilience(t *testing.T) {
	// Resilience has no kill chain phase — should be excluded.
	got := ToKillChainPhases([]string{"resilience"})
	if len(got) != 0 {
		t.Errorf("resilience should produce no kill chain phases, got %v", got)
	}
}
