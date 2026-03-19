package apply

import (
	"testing"

	"github.com/sufield/stave/internal/domain/evaluation"
)

func TestBuildEvaluateResult_Safe(t *testing.T) {
	res := BuildEvaluateResult(evaluation.StatusSafe, "controls/s3", "observations")
	if res.SafetyStatus != evaluation.StatusSafe {
		t.Fatalf("expected StatusSafe, got %s", res.SafetyStatus)
	}
	if res.DiagnoseHint != "" {
		t.Fatalf("expected empty DiagnoseHint for safe status, got %q", res.DiagnoseHint)
	}
	if len(res.NextSteps) != 0 {
		t.Fatalf("expected no next steps for safe status, got %v", res.NextSteps)
	}
}

func TestBuildEvaluateResult_Unsafe(t *testing.T) {
	res := BuildEvaluateResult(evaluation.StatusUnsafe, "controls/s3", "observations")
	if res.SafetyStatus != evaluation.StatusUnsafe {
		t.Fatalf("expected StatusUnsafe, got %s", res.SafetyStatus)
	}
	if res.DiagnoseHint == "" {
		t.Fatal("expected non-empty DiagnoseHint for unsafe status")
	}
	if len(res.NextSteps) == 0 {
		t.Fatal("expected next steps for unsafe status")
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

func TestResolveContextName(t *testing.T) {
	tests := []struct {
		name     string
		root     string
		selected string
		expected string
	}{
		{"explicit context", "/path/to/project", "my-ctx", "my-ctx"},
		{"from root", "/path/to/project", "", "project"},
		{"empty root", "", "", "default"},
		{"dot root", ".", "", "default"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveContextName(tt.root, tt.selected)
			if got != tt.expected {
				t.Fatalf("ResolveContextName(%q, %q) = %q, want %q", tt.root, tt.selected, got, tt.expected)
			}
		})
	}
}
