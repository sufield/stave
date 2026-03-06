package validate

import (
	"fmt"
	"path/filepath"

	"github.com/sufield/stave/internal/domain/diag"
)

// hintContext provides CLI-specific values used to format remediation hints.
type hintContext struct {
	ControlsDir     string
	ObservationsDir string
}

type hintBuilder func(issue diag.Issue, ctx hintContext) string

var issueHintBuilders = map[string]hintBuilder{
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

	seen := map[string]bool{}
	hints := make([]string, 0, len(result.Issues))
	add := func(hint string) {
		if hint == "" || seen[hint] {
			return
		}
		seen[hint] = true
		hints = append(hints, hint)
	}

	for _, issue := range result.Issues {
		if issue.Command != "" {
			add(issue.Command)
			continue
		}
		add(hintForIssue(issue, ctx))
	}

	return hints
}

func hintForIssue(issue diag.Issue, ctx hintContext) string {
	if builder, ok := issueHintBuilders[issue.Code]; ok {
		return builder(issue, ctx)
	}
	if issueHasPath(issue) {
		return hintExplainControl(issue, ctx)
	}
	return ""
}

func hintGenerateControl(_ diag.Issue, ctx hintContext) string {
	return fmt.Sprintf("stave generate control --id CTL.S3.PUBLIC.901 --out %s", filepath.Join(ctx.ControlsDir, "CTL.S3.PUBLIC.901.yaml"))
}

func hintIngestObservations(_ diag.Issue, _ hintContext) string {
	return "stave ingest --profile mvp1-s3 --input ./snapshots/raw/aws-s3 --out ./observations"
}

func hintDiagnoseObservations(_ diag.Issue, ctx hintContext) string {
	return fmt.Sprintf("stave diagnose --controls %s --observations %s", ctx.ControlsDir, ctx.ObservationsDir)
}

func hintValidateCoverage(_ diag.Issue, ctx hintContext) string {
	return fmt.Sprintf("stave validate --controls %s --observations %s --max-unsafe 24h", ctx.ControlsDir, ctx.ObservationsDir)
}

func hintExplainControl(issue diag.Issue, ctx hintContext) string {
	controlID := issue.Evidence.Sanitized("control_id")
	if controlID == "" {
		return ""
	}
	return fmt.Sprintf("stave explain %s --controls %s", controlID, ctx.ControlsDir)
}

func issueHasPath(issue diag.Issue) bool {
	path, hasPath := issue.Evidence.Get("path")
	return hasPath && path != ""
}
