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

// ReportApply prints the outcome of an evaluation and returns an error
// when the response policy indicates failure.
func (r *Reporter) ReportApply(res EvaluateResult, policy evaluation.EnforcementPolicy) error {
	outcome := policy.Evaluate(res.SecurityState)

	switch outcome.Signal {
	case evaluation.LevelAllow:
		if !r.Quiet {
			if _, err := fmt.Fprintln(r.Stderr, "Evaluation complete. No violations found."); err != nil {
				return err
			}
		}
		return nil

	case evaluation.LevelAdvisory:
		if !r.Quiet {
			if _, err := fmt.Fprintln(r.Stderr, "Evaluation complete. No violations, but at-risk assets detected."); err != nil {
				return err
			}
			if res.DiagnoseCommand != "" {
				ui.WriteHint(r.Stderr, res.DiagnoseCommand)
			}
		}
		return nil

	default: // LevelBlock
		if !r.Quiet {
			ui.WriteHint(r.Stderr, res.DiagnoseCommand)
			r.Runtime.PrintNextSteps(res.NextSteps...)
		}
		return ui.ErrViolationsFound
	}
}

// ReportPlan prints the readiness report (used by apply --dry-run).
func (r *Reporter) ReportPlan(report validation.ReadinessAssessment) error {
	if r.Quiet {
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

// checkSLAPolicy returns an error (exit code 3) when SLA breaches violate
// the configured policy. Default "warn" never triggers a non-zero exit.
//
// SLA breaches are findings, not security-audit gating events. The
// earlier shape returned ErrSecurityAuditFindings, which the global
// classifier maps to exit code 1 (security-audit gating) — but
// `apply` emits SLA breach findings as part of normal evaluation,
// not as a gate. Routing them through ErrViolationsFound (exit 3)
// keeps the exit-code map's semantic split intact: 1 is reserved
// for the dedicated `security-audit` command, 3 is "evaluation
// completed with findings".
func checkSLAPolicy(stderr io.Writer, policy SLAPolicy, res EvaluateResult, quiet bool) error {
	switch policy {
	case SLAPolicyStrict:
		if res.HasSLABreach {
			if !quiet {
				fmt.Fprintln(stderr, "SLA policy: strict — SLA breach detected, failing.")
			}
			return ui.ErrViolationsFound
		}
	case SLAPolicyCriticalOnly:
		if res.HasCriticalSLABreach {
			if !quiet {
				fmt.Fprintln(stderr, "SLA policy: critical-only — critical SLA breach detected, failing.")
			}
			return ui.ErrViolationsFound
		}
	}
	// "warn" (default) — no exit code change.
	return nil
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
