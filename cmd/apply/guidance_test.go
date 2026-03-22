package apply

import (
	"testing"

	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
)

func TestBuildEvaluateResult_Safe(t *testing.T) {
	res := BuildEvaluateResult(evaluation.StatusSafe, "controls/s3", "observations")
	if res.SafetyStatus != evaluation.StatusSafe {
		t.Fatalf("expected StatusSafe, got %s", res.SafetyStatus)
	}
	if res.DiagnoseCommand != "" {
		t.Fatalf("expected empty DiagnoseCommand for safe status, got %q", res.DiagnoseCommand)
	}
	if res.NextSteps != nil {
		t.Fatalf("expected nil next steps for safe status, got %v", res.NextSteps)
	}
}

func TestBuildEvaluateResult_Unsafe(t *testing.T) {
	res := BuildEvaluateResult(evaluation.StatusUnsafe, "controls/s3", "observations")
	if res.SafetyStatus != evaluation.StatusUnsafe {
		t.Fatalf("expected StatusUnsafe, got %s", res.SafetyStatus)
	}
	if res.DiagnoseCommand == "" {
		t.Fatal("expected non-empty DiagnoseCommand for unsafe status")
	}
	if len(res.NextSteps) != 3 {
		t.Fatalf("expected 3 next steps, got %d", len(res.NextSteps))
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
