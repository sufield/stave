package apply

import (
	"errors"
	"fmt"
	"io"
	"strings"

	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/cli/ui"
	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
	"github.com/sufield/stave/internal/core/evaluation"
	validation "github.com/sufield/stave/internal/core/schemaval"
)

// Reporter handles the visual presentation of evaluation and readiness
// results to the user. It writes structured output to Stdout and
// progress/hint messages to Stderr.
type Reporter struct {
	Stdout  io.Writer
	Stderr  io.Writer
	Runtime *ui.Runtime
	Quiet   bool
}

// NewReporter constructs a Reporter from the standard CLI IO bundle.
// Centralises the (Stdout / Stderr / Runtime / Quiet) wiring so the
// run-mode dispatch sites stop carrying the four-field literal —
// they pass StandardIO + Runtime and let the constructor extract the
// quiet flag from the bundle.
func NewReporter(sio StandardIO, rt *ui.Runtime) *Reporter {
	return &Reporter{
		Stdout:  sio.Stdout,
		Stderr:  sio.Stderr,
		Runtime: rt,
		Quiet:   sio.Quiet,
	}
}

// Emit writes a single line to w when the reporter is not in quiet
// mode. Centralises the (!r.Quiet) guard that ReportApply /
// ReportPlan / CheckSLAPolicy used to repeat at every Fprintln site.
// nil receiver and quiet receivers swallow output silently so callers
// can stop nil-checking.
func (r *Reporter) Emit(w io.Writer, msg string) {
	if r == nil || r.Quiet {
		return
	}
	_, _ = fmt.Fprintln(w, msg)
}

// Emitf wraps Emit for the printf-style call sites; same quiet
// guard, same swallow-on-nil semantics.
func (r *Reporter) Emitf(w io.Writer, format string, args ...any) {
	if r == nil || r.Quiet {
		return
	}
	_, _ = fmt.Fprintf(w, format, args...)
}

// ShouldEmit reports whether the reporter is currently emitting
// output. Used by call sites that wrap multiple prints in a single
// branch (the LevelBlock case below).
func (r *Reporter) ShouldEmit() bool {
	return r != nil && !r.Quiet
}

// ReportApply prints the outcome of an evaluation and returns an error
// when the response policy indicates failure. Per-signal phrasing
// lives on EnforcementOutcome.SummaryMessage; this method composes
// that message with the (advisory / block) hint plumbing.
func (r *Reporter) ReportApply(res EvaluateResult, policy evaluation.EnforcementPolicy) error {
	outcome := policy.Evaluate(res.SecurityState)
	if msg := outcome.SummaryMessage(); msg != "" {
		r.Emit(r.Stderr, msg)
	}

	switch {
	case outcome.IsAllow():
		return nil
	case outcome.IsAdvisory():
		if r.ShouldEmit() && res.DiagnoseCommand != "" {
			ui.WriteHint(r.Stderr, res.DiagnoseCommand)
		}
		return nil
	default: // IsBlock
		if r.ShouldEmit() {
			ui.WriteHint(r.Stderr, res.DiagnoseCommand)
			r.Runtime.PrintNextSteps(res.NextSteps...)
		}
		return ui.ErrViolationsFound
	}
}

// ReportPlan prints the readiness report (used by apply --dry-run).
func (r *Reporter) ReportPlan(report validation.ReadinessAssessment) error {
	if !r.ShouldEmit() {
		return nil
	}

	w := r.Stdout
	if _, err := fmt.Fprintf(w, "Plan Summary\n------------\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Ready:        %t\n", report.IsSafe); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Controls:     %s\n", report.ControlSource); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Checks: %s\n", report.ObservationSource); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Checked:      %d controls, %d snapshots, %d asset observations\n",
		report.Summary.ControlsVerified,
		report.Summary.StatesVerified,
		report.Summary.ResourcesAnalyzed); err != nil {
		return err
	}

	issues := report.Findings()
	if len(issues) > 0 {
		if _, err := fmt.Fprintln(w, "\nIssues:"); err != nil {
			return err
		}
		for _, issue := range issues {
			if err := printReadinessIssue(w, issue); err != nil {
				return err
			}
		}
	}

	nextCmd := readinessNextCommand(report)
	_, err := fmt.Fprintf(w, "\nNext: %s\n", nextCmd)
	return err
}

// readinessNextCommand returns the recommended next CLI command based on readiness status.
func readinessNextCommand(report validation.ReadinessAssessment) string {
	if report.IsSafe {
		return fmt.Sprintf("stave apply --controls %s --observations %s",
			report.ControlSource, report.ObservationSource)
	}
	return fmt.Sprintf("stave validate --controls %s --observations %s",
		report.ControlSource, report.ObservationSource)
}

func printReadinessIssue(w io.Writer, issue validation.ValidationFinding) error {
	if _, err := fmt.Fprintf(w, "  [%s] %s: %s\n", issue.Status.String(), issue.Name, issue.Message); err != nil {
		return err
	}

	if fix := strings.TrimSpace(issue.Remediation); fix != "" {
		if _, err := fmt.Fprintf(w, "    Fix: %s\n", fix); err != nil {
			return err
		}
	}

	if cmd := strings.TrimSpace(issue.FixCommand); cmd != "" {
		if _, err := fmt.Fprintf(w, "    Command: %s\n", cmd); err != nil {
			return err
		}
	}

	return nil
}

// CheckSLAPolicy returns an error (exit code 3) when SLA breaches
// violate the configured policy. Default "warn" never triggers a
// non-zero exit. The reporter owns both the destination writer and
// the quiet-mode gate, so callers stop passing those as raw
// arguments.
//
// SLA breaches are findings, not security-audit gating events. The
// earlier shape returned ErrSecurityAuditFindings, which the global
// classifier maps to exit code 1 (security-audit gating) — but
// `apply` emits SLA breach findings as part of normal evaluation,
// not as a gate. Routing them through ErrViolationsFound (exit 3)
// keeps the exit-code map's semantic split intact: 1 is reserved
// for the dedicated `security-audit` command, 3 is "evaluation
// completed with findings".
func (r *Reporter) CheckSLAPolicy(policy SLAPolicy, res EvaluateResult) error {
	if !res.ShouldFailForPolicy(policy) {
		return nil
	}
	switch policy {
	case SLAPolicyStrict:
		r.Emit(r.Stderr, "SLA policy: strict — SLA breach detected, failing.")
	case SLAPolicyCriticalOnly:
		r.Emit(r.Stderr, "SLA policy: critical-only — critical SLA breach detected, failing.")
	}
	return ui.ErrViolationsFound
}

// decorateError maps domain-specific errors to user-facing remediation hints.
// This is presentation logic — it translates domain errors into CLI guidance
// using sentinel error matching via errors.Is.
func decorateError(err error) error {
	var hint error
	switch {
	case errors.Is(err, appeval.ErrNoControls):
		hint = ui.ErrHintNoControls
	case errors.Is(err, appeval.ErrNoSnapshots):
		hint = ui.ErrHintNoSnapshots
	case errors.Is(err, appeval.ErrSourceTypeMissing),
		errors.Is(err, appeval.ErrSourceTypeUnsupported):
		hint = ui.ErrHintSourceType
	case errors.Is(err, contractvalidator.ErrSchemaValidationFailed):
		hint = ui.ErrHintSchemaValidation
	default:
		return err
	}
	return &ui.UserError{Err: ui.EvaluateErrorWithHint(ui.WithHint(err, hint))}
}
