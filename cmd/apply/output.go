package apply

import (
	"fmt"
	"io"
	"strings"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/validation"
)

// Reporter handles the visual presentation of results to the user.
type Reporter struct {
	Stdout  io.Writer
	Stderr  io.Writer
	Runtime *ui.Runtime
	Quiet   bool
}

// ReportApply prints the outcome of an evaluation.
// Returns ui.ErrViolationsFound if the status is Unsafe.
func (r *Reporter) ReportApply(res EvaluateResult) error {
	if res.SafetyStatus == evaluation.StatusSafe {
		if !r.Quiet {
			fmt.Fprintln(r.Stderr, "Evaluation complete. No violations found.")
		}
		return nil
	}

	if !r.Quiet {
		ui.WriteHint(r.Stderr, res.DiagnoseHint)
		r.Runtime.PrintNextSteps(res.NextSteps...)
	}

	return ui.ErrViolationsFound
}

// ReportPlan prints the readiness report (used by apply --dry-run).
func (r *Reporter) ReportPlan(report validation.ReadinessReport) error {
	if r.Quiet {
		return nil
	}

	fmt.Fprintf(r.Stdout, "Plan Summary\n------------\n")
	fmt.Fprintf(r.Stdout, "Ready:        %t\n", report.Ready)
	fmt.Fprintf(r.Stdout, "Controls:     %s\n", report.ControlsDir)
	fmt.Fprintf(r.Stdout, "Observations: %s\n", report.ObservationsDir)
	fmt.Fprintf(r.Stdout, "Checked:      %d controls, %d snapshots, %d asset observations\n",
		report.Summary.ControlsChecked,
		report.Summary.SnapshotsChecked,
		report.Summary.AssetObservationsChecked)

	issues := report.Issues()
	if len(issues) > 0 {
		fmt.Fprintln(r.Stdout, "\nIssues:")
		for _, issue := range issues {
			r.printReadinessIssue(issue)
		}
	}

	fmt.Fprintf(r.Stdout, "\nNext: %s\n", report.NextCommand)
	return nil
}

func (r *Reporter) printReadinessIssue(issue validation.Issue) {
	fmt.Fprintf(r.Stdout, "  [%s] %s: %s\n", issue.Status.Label(), issue.Name, issue.Message)

	if fix := strings.TrimSpace(issue.Fix); fix != "" {
		fmt.Fprintf(r.Stdout, "    Fix: %s\n", fix)
	}

	if cmd := strings.TrimSpace(issue.Command); cmd != "" {
		fmt.Fprintf(r.Stdout, "    Command: %s\n", cmd)
	}
}
