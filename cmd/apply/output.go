package apply

import (
	"errors"
	"fmt"
	"io"

	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/cli/ui"
	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
	"github.com/sufield/stave/internal/core/evaluation"
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

// ShouldEmit reports whether the reporter is currently emitting
// output. Used by call sites that wrap multiple prints in a single
// branch (the LevelBlock case below).
func (r *Reporter) ShouldEmit() bool {
	return r != nil && !r.Quiet
}

// hasInteractiveUI reports whether the reporter is wired to a
// runtime capable of providing interactive feedback. The
// constructor (NewReporter) normally injects a non-nil Runtime,
// but tests and literal Reporter constructions may leave it nil;
// this predicate names the capability so callers describe the
// "we have a hint surface" check rather than a memory-safety
// probe.
func (r *Reporter) hasInteractiveUI() bool {
	return r != nil && r.Runtime != nil
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
			// Match the advisory branch above: only emit the diagnose
			// hint when one was actually wired. A bare `WriteHint`
			// with an empty command renders as a misleading
			// "next: <empty>" line in the operator's terminal.
			if res.DiagnoseCommand != "" {
				ui.WriteHint(r.Stderr, res.DiagnoseCommand)
			}
			// Skip the next-steps hint when no runtime is wired.
			// The violation error is the foundational signal here;
			// the hint is purely advisory UI.
			if r.hasInteractiveUI() {
				r.Runtime.PrintNextSteps(res.NextSteps...)
			}
		}
		return ui.ErrViolationsFound
	}
}

// gateViolations returns the violation gating error for a security
// state without rendering any user-facing summary. It mirrors the
// terminal decision in ReportApply (policy.Evaluate → block ⇒
// ErrViolationsFound) so the --new-only / --new-since path can apply
// the same exit-code gate after rendering its own signal-filtered
// view. Returns nil for allow/advisory outcomes; ui.ErrViolationsFound
// for a block (non-compliant) state.
func gateViolations(res EvaluateResult) error {
	outcome := evaluation.EnforcementPolicy{}.Evaluate(res.SecurityState)
	if outcome.IsAllow() || outcome.IsAdvisory() {
		return nil
	}
	return ui.ErrViolationsFound
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
	if msg := policy.FailureMessage(); msg != "" {
		r.Emit(r.Stderr, msg)
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
	case errors.Is(err, contractvalidator.ErrSchemaValidationFailed):
		hint = ui.ErrHintSchemaValidation
	default:
		return err
	}
	return &ui.UserError{Err: ui.EvaluateErrorWithHint(ui.WithHint(err, hint))}
}
