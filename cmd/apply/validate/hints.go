package validate

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sufield/stave/internal/core/diag"
)

// hintContext provides values used to format remediation hints.
type hintContext struct {
	ControlsDir     string
	ObservationsDir string
}

type hintFunc func(issue diag.Finding, ctx hintContext) string

// hintByCode maps diagnostic codes to functions that suggest a fix command.
// Immutable after init — do not modify at runtime.
var hintByCode = map[diag.RuleID]hintFunc{
	diag.RuleControlLoadFailed:       hintGenerateControl,
	diag.RuleNoControls:              hintGenerateControl,
	diag.RuleObservationLoadFailed:   hintCreateObservations,
	diag.RuleNoSnapshots:             hintCreateObservations,
	diag.RuleSingleSnapshot:          hintCreateObservations,
	diag.RuleSnapshotsUnsorted:       hintDiagnoseObservations,
	diag.RuleDuplicateTimestamp:      hintDiagnoseObservations,
	diag.RuleSpanLessThanMaxUnsafe:   hintValidateCoverage,
	diag.RuleControlUndefinedParam:   hintExplainControl,
	diag.RuleControlBadDurationParam: hintExplainControl,
}

// collectHints derives unique command hints for a diagnostic result.
// Hints are sorted for deterministic output.
func collectHints(result *diag.Assessment, ctx hintContext) []string {
	if result == nil || len(result.Findings) == 0 {
		return nil
	}

	seen := make(map[string]struct{})
	var hints []string

	for _, issue := range result.Findings {
		var h string

		// Priority 1: use the explicit command embedded in the issue
		if issue.FixCommand != "" {
			h = issue.FixCommand
		} else {
			// Priority 2: use the registry-based builder
			h = hintForIssue(issue, ctx)
		}

		if h != "" {
			if _, exists := seen[h]; !exists {
				seen[h] = struct{}{}
				hints = append(hints, h)
			}
		}
	}

	sort.Strings(hints)
	return hints
}

func hintForIssue(issue diag.Finding, ctx hintContext) string {
	if builder, ok := hintByCode[issue.RuleID]; ok {
		return builder(issue, ctx)
	}

	// Fallback: if it's an unknown error but has a path, explain the control
	if _, ok := issue.Resource.Get("path"); ok {
		return hintExplainControl(issue, ctx)
	}

	return ""
}

// --- Specific Hint Builders ---

func hintGenerateControl(issue diag.Finding, ctx hintContext) string {
	if ctx.ControlsDir == "" {
		return ""
	}
	id := issue.Resource.Sanitized("control_id")
	if id == "" {
		id = "EXAMPLE.CONTROL.ID"
	}
	// Sanitize ID for use as filename — replace path separators
	safeID := strings.ReplaceAll(strings.ReplaceAll(id, "/", "_"), "..", "_")
	filename := fmt.Sprintf("%s.yaml", safeID)
	return fmt.Sprintf("stave generate control --id %s --out %s",
		shellQuote(id),
		shellQuote(filepath.Join(ctx.ControlsDir, filename)),
	)
}

func hintCreateObservations(_ diag.Finding, _ hintContext) string {
	return "Place observation JSON files in the observations directory. See 'stave explain' for required fields."
}

func hintDiagnoseObservations(_ diag.Finding, ctx hintContext) string {
	if ctx.ControlsDir == "" || ctx.ObservationsDir == "" {
		return "stave diagnose"
	}
	return fmt.Sprintf("stave diagnose --controls %s --observations %s",
		shellQuote(ctx.ControlsDir),
		shellQuote(ctx.ObservationsDir),
	)
}

func hintValidateCoverage(_ diag.Finding, ctx hintContext) string {
	if ctx.ControlsDir == "" || ctx.ObservationsDir == "" {
		return "stave validate"
	}
	return fmt.Sprintf("stave validate --controls %s --observations %s --max-unsafe 24h",
		shellQuote(ctx.ControlsDir),
		shellQuote(ctx.ObservationsDir),
	)
}

func hintExplainControl(issue diag.Finding, ctx hintContext) string {
	controlID := issue.Resource.Sanitized("control_id")
	if controlID == "" {
		if path, ok := issue.Resource.Get("path"); ok {
			controlID = filepath.Base(path)
		}
	}
	if controlID == "" {
		return ""
	}
	if ctx.ControlsDir == "" {
		return fmt.Sprintf("stave explain %s", shellQuote(controlID))
	}
	return fmt.Sprintf("stave explain %s --controls %s",
		shellQuote(controlID),
		shellQuote(ctx.ControlsDir),
	)
}

// shellQuote wraps a CLI argument in single quotes if it contains spaces or
// shell-sensitive characters. Single quotes inside the value are escaped.
func shellQuote(s string) string {
	if !strings.ContainsAny(s, " \t'\"\\$`!#&|;(){}[]<>?*~") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
