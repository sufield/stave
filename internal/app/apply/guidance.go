package apply

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/domain/evaluation"
)

// EvaluateResult provides structured execution outcomes and user guidance.
type EvaluateResult struct {
	SafetyStatus evaluation.SafetyStatus
	DiagnoseHint string
	NextSteps    []string
}

// BuildEvaluateResult maps a domain safety status into actionable CLI guidance.
func BuildEvaluateResult(status evaluation.SafetyStatus, controlsDir, observationsDir string) EvaluateResult {
	res := EvaluateResult{
		SafetyStatus: status,
		NextSteps:    []string{},
	}

	if status == evaluation.StatusSafe {
		return res
	}

	res.DiagnoseHint = BuildDiagnoseHint(controlsDir, observationsDir)
	res.NextSteps = []string{
		fmt.Sprintf("Identify the root cause: `%s`", res.DiagnoseHint),
		"View a summary: `stave apply --format text`",
		"Export findings to a file: `stave apply --format json > findings.json`",
	}

	return res
}

// BuildDiagnoseHint constructs a CLI command string with the appropriate flags.
func BuildDiagnoseHint(controlsDir, observationsDir string) string {
	const base = "stave diagnose"

	args := make([]string, 0, 4)

	if c := strings.TrimSpace(controlsDir); c != "" {
		args = append(args, "--controls", c)
	}

	if o := strings.TrimSpace(observationsDir); o != "" {
		args = append(args, "--observations", o)
	}

	if len(args) == 0 {
		return base
	}

	return base + " " + strings.Join(args, " ")
}
