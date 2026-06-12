package apply

import (
	"strings"
	"testing"
)

func TestApplyNextSteps(t *testing.T) {
	steps := applyNextSteps("stave diagnose --controls ctl")
	if len(steps) != 3 {
		t.Fatalf("expected 3 next steps, got %d", len(steps))
	}
	if !strings.Contains(steps[0], "stave diagnose --controls ctl") {
		t.Fatalf("first step should embed the diagnose command, got: %q", steps[0])
	}
}

func TestBuildDiagnoseHint(t *testing.T) {
	tests := []struct {
		name     string
		ctlDir   string
		obsDir   string
		expected string
	}{
		{"both dirs", "ctl", "obs", "stave diagnose --controls ctl --observations obs"},
		{"controls only", "ctl", "", "stave diagnose --controls ctl"},
		{"observations only", "", "obs", "stave diagnose --observations obs"},
		{"no dirs", "", "", "stave diagnose"},
		{"whitespace trimmed", "  ctl  ", "  obs  ", "stave diagnose --controls ctl --observations obs"},
		{"path with spaces", "my controls", "my obs", "stave diagnose --controls 'my controls' --observations 'my obs'"},
		{"path with single quote", "it's", "obs", "stave diagnose --controls 'it'\\''s' --observations obs"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildDiagnoseHint(tt.ctlDir, tt.obsDir)
			if got != tt.expected {
				t.Fatalf("BuildDiagnoseHint(%q, %q) = %q, want %q", tt.ctlDir, tt.obsDir, got, tt.expected)
			}
		})
	}
}
