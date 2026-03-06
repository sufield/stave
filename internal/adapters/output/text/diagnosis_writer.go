package text

import (
	"fmt"
	"io"

	"github.com/sufield/stave/internal/domain/evaluation/diagnosis"
	"github.com/sufield/stave/internal/pkg/timeutil"
)

// LabelFunc formats a severity label for display.
// level is a severity keyword (e.g. "success", "warning") and message
// is the text to label. Terminal detection should happen once at the
// call site, not per-label invocation.
type LabelFunc func(level, message string) string

// WriteDiagnosisReport writes a human-readable diagnostics report.
// labelFn formats severity labels for output lines.
func WriteDiagnosisReport(w io.Writer, report *diagnosis.Report, labelFn LabelFunc) error {
	if err := writeDiagnosisSummary(w, report); err != nil {
		return err
	}
	if len(report.Entries) == 0 {
		return writeNoDiagnosisIssues(w, labelFn)
	}
	return writeDiagnosesList(w, report.Entries, labelFn)
}

func writeDiagnosisSummary(w io.Writer, report *diagnosis.Report) error {
	if _, err := fmt.Fprintln(w, "Summary"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "-------"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  Snapshots:        %d\n", report.Summary.TotalSnapshots); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  Resources:        %d\n", report.Summary.TotalResources); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  Controls:         %d\n", report.Summary.TotalControls); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  Time span:        %s\n", timeutil.FormatDurationHuman(report.Summary.TimeSpan.Std())); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  Threshold:        %s\n", timeutil.FormatDurationHuman(report.Summary.MaxUnsafeThreshold.Std())); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  Violations:       %d\n", report.Summary.ViolationsFound); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  Attack surface resources: %d\n", report.Summary.AttackSurface); err != nil {
		return err
	}
	return nil
}

func writeNoDiagnosisIssues(w io.Writer, labelFn LabelFunc) error {
	line := labelFn("success", "No diagnostic issues detected.")
	if _, err := fmt.Fprintf(w, "\n%s\n", line); err != nil {
		return err
	}
	_, err := fmt.Fprintln(w, "Next step: continue with `stave apply` on new snapshots.")
	return err
}

func writeDiagnosesList(w io.Writer, diagnoses []diagnosis.Entry, labelFn LabelFunc) error {
	warn := labelFn("warning", fmt.Sprintf("Diagnostics (%d):", len(diagnoses)))
	if _, err := fmt.Fprintf(w, "\n%s\n", warn); err != nil {
		return err
	}

	for i, diag := range diagnoses {
		if err := writeDiagnosisItem(w, i, diag); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w, "\nNext step: apply the suggested action/command, then rerun `stave apply` and `stave diagnose`."); err != nil {
		return err
	}
	return nil
}

func writeDiagnosisItem(w io.Writer, index int, diag diagnosis.Entry) error {
	if _, err := fmt.Fprintf(w, "\n[%d] %s\n", index+1, diag.Case); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "    Signal: %s\n", diag.Signal); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "    Evidence: %s\n", diag.Evidence); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "    Action: %s\n", diag.Action); err != nil {
		return err
	}
	if diag.Command != "" {
		if _, err := fmt.Fprintf(w, "    Command: %s\n", diag.Command); err != nil {
			return err
		}
	}
	return nil
}
