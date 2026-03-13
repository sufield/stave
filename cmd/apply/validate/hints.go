package validate

import (
	"fmt"
	"path/filepath"

	"github.com/sufield/stave/internal/domain/diag"
)

// hintContext provides values used to format remediation hints.
type hintContext struct {
	ControlsDir     string
	ObservationsDir string
}

type hintBuilder func(issue diag.Issue, ctx hintContext) string

// issueHintRegistry maps diagnostic codes to logic that suggests a fix.
var issueHintRegistry = map[diag.Code]hintBuilder{
	diag.CodeControlLoadFailed:       hintGenerateControl,
	diag.CodeNoControls:              hintGenerateControl,
	diag.CodeObservationLoadFailed:   hintIngestObservations,
	diag.CodeNoSnapshots:             hintIngestObservations,
	diag.CodeSingleSnapshot:          hintIngestObservations,
	diag.CodeSnapshotsUnsorted:       hintDiagnoseObservations,
	diag.CodeDuplicateTimestamp:      hintDiagnoseObservations,
	diag.CodeSpanLessThanMaxUnsafe:   hintValidateCoverage,
	diag.CodeControlUndefinedParam:   hintExplainControl,
	diag.CodeControlBadDurationParam: hintExplainControl,
}

// collectHints derives unique command hints for a diagnostic result.
func collectHints(result *diag.Result, ctx hintContext) []string {
	if result == nil || len(result.Issues) == 0 {
		return nil
	}

	seen := make(map[string]struct{})
	var hints []string

	for _, issue := range result.Issues {
		var h string

		// Priority 1: Use the explicit command embedded in the issue if present
		if issue.Command != "" {
			h = issue.Command
		} else {
			// Priority 2: Use the registry-based builder
			h = hintForIssue(issue, ctx)
		}

		if h != "" {
			if _, exists := seen[h]; !exists {
				seen[h] = struct{}{}
				hints = append(hints, h)
			}
		}
	}

	return hints
}

func hintForIssue(issue diag.Issue, ctx hintContext) string {
	if builder, ok := issueHintRegistry[issue.Code]; ok {
		return builder(issue, ctx)
	}

	// Fallback: If it's an unknown error but has a path, explain the control
	if _, ok := issue.Evidence.Get("path"); ok {
		return hintExplainControl(issue, ctx)
	}

	return ""
}

// --- Specific Hint Builders ---

func hintGenerateControl(issue diag.Issue, ctx hintContext) string {
	id := issue.Evidence.Sanitized("control_id")
	if id == "" {
		id = "EXAMPLE.CONTROL.ID"
	}

	filename := fmt.Sprintf("%s.yaml", id)
	return fmt.Sprintf("stave generate control --id %s --out %s",
		id,
		filepath.Join(ctx.ControlsDir, filename),
	)
}

func hintIngestObservations(_ diag.Issue, _ hintContext) string {
	return "stave ingest --profile aws-s3 --input ./snapshots/raw/aws-s3 --out ./observations"
}

func hintDiagnoseObservations(_ diag.Issue, ctx hintContext) string {
	return fmt.Sprintf("stave diagnose --controls %s --observations %s",
		ctx.ControlsDir,
		ctx.ObservationsDir,
	)
}

func hintValidateCoverage(_ diag.Issue, ctx hintContext) string {
	return fmt.Sprintf("stave validate --controls %s --observations %s --max-unsafe 24h",
		ctx.ControlsDir,
		ctx.ObservationsDir,
	)
}

func hintExplainControl(issue diag.Issue, ctx hintContext) string {
	controlID := issue.Evidence.Sanitized("control_id")
	if controlID == "" {
		// Fallback to checking the filename if control_id isn't in evidence
		if path, ok := issue.Evidence.Get("path"); ok {
			controlID = filepath.Base(path)
		}
	}

	if controlID == "" {
		return ""
	}

	return fmt.Sprintf("stave explain %s --controls %s", controlID, ctx.ControlsDir)
}
