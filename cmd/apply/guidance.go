package apply

import (
	"fmt"
	"strings"
)

// Next-step templates. Centralized so flag/command renames update in one place.
const (
	stepDiagnose = "Identify the root cause: `%s`"
	stepText     = "View a summary: `stave apply --format text`"
	stepExport   = "Export findings to a file: `stave apply --format json > findings.json`"
)

// applyNextSteps builds the next-step hints shown on a blocking
// (non-compliant) outcome, from the diagnose command. Replaces the
// NextSteps field that the former EvaluateResult carried.
func applyNextSteps(diagnose string) []string {
	return []string{
		fmt.Sprintf(stepDiagnose, diagnose),
		stepText,
		stepExport,
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
