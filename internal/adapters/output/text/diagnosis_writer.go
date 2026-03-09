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
	var err error
	writef := func(format string, args ...any) {
		if err != nil {
			return
		}
		_, err = fmt.Fprintf(w, format, args...)
	}

	writef("Summary\n")
	writef("-------\n")
	writef("  Snapshots:        %d\n", report.Summary.TotalSnapshots)
	writef("  Assets:           %d\n", report.Summary.TotalAssets)
	writef("  Controls:         %d\n", report.Summary.TotalControls)
	writef("  Time span:        %s\n", timeutil.FormatDurationHuman(report.Summary.TimeSpan.Std()))
	writef("  Threshold:        %s\n", timeutil.FormatDurationHuman(report.Summary.MaxUnsafeThreshold.Std()))
	writef("  Violations:       %d\n", report.Summary.ViolationsFound)
	writef("  Attack surface resources: %d\n", report.Summary.AttackSurface)
	return err
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
	_, err := fmt.Fprintln(w, "\nNext step: apply the suggested action/command, then rerun `stave apply` and `stave diagnose`.")
	return err
}

func writeDiagnosisItem(w io.Writer, index int, diag diagnosis.Entry) error {
	var err error
	writef := func(format string, args ...any) {
		if err != nil {
			return
		}
		_, err = fmt.Fprintf(w, format, args...)
	}

	writef("\n[%d] %s\n", index+1, diag.Case)
	writef("    Signal: %s\n", diag.Signal)
	writef("    Evidence: %s\n", diag.Evidence)
	writef("    Action: %s\n", diag.Action)
	if diag.Command != "" {
		writef("    Command: %s\n", diag.Command)
	}
	return err
}
