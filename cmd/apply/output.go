package apply

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/validation"
)

func handleApplyResult(cmd *cobra.Command, result EvaluateResult) error {
	globalQuiet := cmdutil.QuietEnabled(cmd)
	if result.SafetyStatus != evaluation.SafetyStatusSafe {
		if ui.ShouldEmitOutput(applyFlags.quietMode, globalQuiet) {
			fmt.Fprintf(os.Stderr, "Hint:\n  %s\n", result.DiagnoseHint)
			rt := ui.NewRuntime(os.Stdout, os.Stderr)
			rt.Quiet = globalQuiet
			rt.PrintNextSteps(result.NextSteps...)
		}
		return ui.ErrViolationsFound
	}
	if ui.ShouldEmitOutput(applyFlags.quietMode, globalQuiet) {
		fmt.Fprintln(os.Stderr, "Evaluation complete. No violations found.")
	}
	return nil
}

func outputResults(cmd *cobra.Command, results EvaluateResult, _ ui.OutputFormat) error {
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
	if _, err := fmt.Fprintf(w, "Plan Summary\n------------\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Ready: %t\n", report.Ready); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Controls: %s\n", report.ControlsDir); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Observations: %s\n", report.ObservationsDir); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "Checked: %d controls, %d snapshots, %d asset observations\n",
		report.Summary.ControlsChecked,
		report.Summary.SnapshotsChecked,
		report.Summary.AssetObservationsChecked,
	)
	return err
}

func writeReadinessIssues(w io.Writer, issues []validation.ReadinessIssue) error {
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

func writeReadinessIssue(w io.Writer, issue validation.ReadinessIssue) error {
	if _, err := fmt.Fprintf(w, "  [%s] %s: %s\n", strings.ToUpper(string(issue.Status)), issue.Name, issue.Message); err != nil {
		return err
	}
	if strings.TrimSpace(issue.Fix) != "" {
		if _, err := fmt.Fprintf(w, "    Fix: %s\n", issue.Fix); err != nil {
			return err
		}
	}
	if strings.TrimSpace(issue.Command) == "" {
		return nil
	}
	if _, err := fmt.Fprintf(w, "    Command: %s\n", issue.Command); err != nil {
		return err
	}
	return nil
}
