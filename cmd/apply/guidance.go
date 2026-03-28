package apply

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/core/evaluation"
)

// Next-step templates. Centralized so flag/command renames update in one place.
const (
	stepDiagnose = "Identify the root cause: `%s`"
	stepText     = "View a summary: `stave apply --format text`"
	stepExport   = "Export findings to a file: `stave apply --format json > findings.json`"
)

// EvaluateResult provides structured execution outcomes and CLI guidance.
type EvaluateResult struct {
	SafetyStatus    evaluation.SafetyStatus
	DiagnoseCommand string   // full CLI command for copy-paste
	NextSteps       []string // nil when safe
}

// BuildEvaluateResult maps a domain safety status into actionable CLI guidance.
// This lives in the cmd layer because it produces CLI-specific strings
// (command names, flag suggestions) that the app layer must not know about.
func BuildEvaluateResult(status evaluation.SafetyStatus, controlsDir, observationsDir string) EvaluateResult {
	if status == evaluation.StatusSafe {
		return EvaluateResult{SafetyStatus: status}
	}

	hint := BuildDiagnoseHint(controlsDir, observationsDir)
	return EvaluateResult{
		SafetyStatus:    status,
		DiagnoseCommand: hint,
		NextSteps: []string{
			fmt.Sprintf(stepDiagnose, hint),
			stepText,
			stepExport,
		},
	}
}

// BuildDiagnoseHint constructs a CLI command string with the appropriate flags.
// Arguments containing spaces are single-quoted for safe copy-paste.
func BuildDiagnoseHint(controlsDir, observationsDir string) string {
	const base = "stave diagnose"

	var args []string

	if c := strings.TrimSpace(controlsDir); c != "" {
		args = append(args, "--controls", quoteArg(c))
	}

	if o := strings.TrimSpace(observationsDir); o != "" {
		args = append(args, "--observations", quoteArg(o))
	}

	if len(args) == 0 {
		return base
	}

	return base + " " + strings.Join(args, " ")
}

// quoteArg wraps a CLI argument in single quotes if it contains spaces or
// shell-sensitive characters. Single quotes inside the value are escaped.
func quoteArg(s string) string {
	if !strings.ContainsAny(s, " \t'\"\\$`!#&|;(){}[]<>?*~") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
