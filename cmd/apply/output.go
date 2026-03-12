package apply

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/validation"
)

func handleApplyResult(cmd *cobra.Command, result EvaluateResult) error {
	if result.SafetyStatus != evaluation.StatusSafe {
		if !cmdutil.QuietEnabled(cmd) {
			ui.WriteHint(cmd.ErrOrStderr(), result.DiagnoseHint)
			rt := cmdutil.NewRuntime(cmd)
			rt.PrintNextSteps(result.NextSteps...)
		}
		return ui.ErrViolationsFound
	}
	if !cmdutil.QuietEnabled(cmd) {
		fmt.Fprintln(cmd.ErrOrStderr(), "Evaluation complete. No violations found.")
	}
	return nil
}

func outputResults(cmd *cobra.Command, results EvaluateResult) error {
	return handleApplyResult(cmd, results)
}

func writeReadinessText(w io.Writer, report validation.ReadinessReport) error {
	if err := writeReadinessSummary(w, report); err != nil {
		return err
	}
	if err := writeReadinessIssues(w, report.Issues()); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "\nNext: %s\n", report.NextCommand)
	return err
}

func writeReadinessSummary(w io.Writer, report validation.ReadinessReport) error {
	var err error
	writef := func(format string, args ...any) {
		if err != nil {
			return
		}
		_, err = fmt.Fprintf(w, format, args...)
	}

	writef("Plan Summary\n------------\n")
	writef("Ready: %t\n", report.Ready)
	writef("Controls: %s\n", report.ControlsDir)
	writef("Observations: %s\n", report.ObservationsDir)
	writef("Checked: %d controls, %d snapshots, %d asset observations\n",
		report.Summary.ControlsChecked,
		report.Summary.SnapshotsChecked,
		report.Summary.AssetObservationsChecked)
	return err
}

func writeReadinessIssues(w io.Writer, issues []validation.Issue) error {
	if len(issues) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(w, "\nIssues:"); err != nil {
		return err
	}
	for _, issue := range issues {
		if err := writeReadinessIssue(w, issue); err != nil {
			return err
		}
	}
	return nil
}

func writeReadinessIssue(w io.Writer, issue validation.Issue) error {
	var err error
	writef := func(format string, args ...any) {
		if err != nil {
			return
		}
		_, err = fmt.Fprintf(w, format, args...)
	}

	writef("  [%s] %s: %s\n", strings.ToUpper(string(issue.Status)), issue.Name, issue.Message)
	if strings.TrimSpace(issue.Fix) != "" {
		writef("    Fix: %s\n", issue.Fix)
	}
	if strings.TrimSpace(issue.Command) != "" {
		writef("    Command: %s\n", issue.Command)
	}
	return err
}
