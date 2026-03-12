package apply

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/domain/evaluation"
)

// EvaluateResult provides structured execution outcomes for CLI orchestration.
type EvaluateResult struct {
	SafetyStatus evaluation.SafetyStatus
	DiagnoseHint string
	NextSteps    []string
}

// BuildEvaluateResult converts a safety status into user guidance.
func BuildEvaluateResult(status evaluation.SafetyStatus, controlsDir, observationsDir string) EvaluateResult {
	result := EvaluateResult{
		SafetyStatus: status,
		NextSteps:    []string{},
	}
	if status == evaluation.StatusSafe {
		return result
	}

	result.DiagnoseHint = buildDiagnoseHint(controlsDir, observationsDir)
	result.NextSteps = []string{
		fmt.Sprintf("Identify the root cause: `%s`", result.DiagnoseHint),
		"View a summary: `stave apply --format text`",
		"Export findings for S3: `stave apply --format json > findings.json`",
	}
	return result
}

func buildDiagnoseHint(controlsDir, observationsDir string) string {
	var parts []string
	if controlsDir = strings.TrimSpace(controlsDir); controlsDir != "" {
		parts = append(parts, "--controls "+controlsDir)
	}
	if observationsDir = strings.TrimSpace(observationsDir); observationsDir != "" {
		parts = append(parts, "--observations "+observationsDir)
	}
	if len(parts) == 0 {
		return "stave diagnose"
	}
	return "stave diagnose " + strings.Join(parts, " ")
}
