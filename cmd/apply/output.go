package apply

import (
	"errors"
	"fmt"
	"io"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

// Gate signal values returned by the standard evaluation facade (mirrors
// evaluation.EnforcementLevel without importing the engine package).
const (
	gateAllow    = "ALLOW"
	gateAdvisory = "ADVISORY"
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

// ReportApply prints the outcome of an evaluation and returns an error when
// the gate decision (precomputed by stave.EvaluateStandard) indicates a block.
// The summary message + advisory/block hint plumbing are composed from the
// primitive StandardResult; the diagnose hint + next steps are built
// command-side from the security state and resolved dirs.
func (r *Reporter) ReportApply(res stave.StandardResult, controlsDir, observationsDir string) error {
	if res.SummaryMessage != "" {
		r.Emit(r.Stderr, res.SummaryMessage)
	}

	switch res.Gate {
	case gateAllow:
		return nil
	case gateAdvisory:
		if r.ShouldEmit() {
			if diagnose := BuildDiagnoseHint(controlsDir, observationsDir); diagnose != "" {
				ui.WriteHint(r.Stderr, diagnose)
			}
		}
		return nil
	default: // block
		if r.ShouldEmit() {
			// Only emit the diagnose hint when one was actually built. A
			// bare WriteHint with an empty command renders as a misleading
			// "next: <empty>" line in the operator's terminal.
			diagnose := BuildDiagnoseHint(controlsDir, observationsDir)
			if diagnose != "" {
				ui.WriteHint(r.Stderr, diagnose)
			}
			// Skip the next-steps hint when no runtime is wired. The
			// violation error is the foundational signal; the hint is UI.
			if r.hasInteractiveUI() {
				r.Runtime.PrintNextSteps(applyNextSteps(diagnose)...)
			}
		}
		return ui.ErrViolationsFound
	}
}

// gateViolations returns the violation gating error without rendering any
// user-facing summary, so the --new-only path applies the same exit-code gate
// after rendering its own signal-filtered view. nil for allow/advisory;
// ui.ErrViolationsFound for a block (non-compliant) state.
func gateViolations(res stave.StandardResult) error {
	if res.Gate == gateAllow || res.Gate == gateAdvisory {
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
func (r *Reporter) CheckSLAPolicy(policy SLAPolicy, res stave.StandardResult) error {
	if !shouldFailForSLA(policy, res) {
		return nil
	}
	if msg := policy.FailureMessage(); msg != "" {
		r.Emit(r.Stderr, msg)
	}
	return ui.ErrViolationsFound
}

// shouldFailForSLA maps the policy to which breach flag gates the run.
// Returns false for SLAPolicyWarn (the no-fail default) and any unrecognised
// value. Replaces the former EvaluateResult.ShouldFailForPolicy.
func shouldFailForSLA(policy SLAPolicy, res stave.StandardResult) bool {
	switch policy {
	case SLAPolicyStrict:
		return res.HasSLABreach
	case SLAPolicyCriticalOnly:
		return res.HasCriticalSLABreach
	default:
		return false
	}
}

// decorateError maps domain-specific errors to user-facing remediation hints.
// This is presentation logic — it translates domain errors into CLI guidance
// using sentinel error matching via errors.Is.
func decorateError(err error) error {
	var hint error
	switch {
	case errors.Is(err, stave.ErrNoControls):
		hint = ui.ErrHintNoControls
	case errors.Is(err, stave.ErrNoSnapshots):
		hint = ui.ErrHintNoSnapshots
	case errors.Is(err, stave.ErrSchemaValidation):
		hint = ui.ErrHintSchemaValidation
	default:
		return err
	}
	return &ui.UserError{Err: ui.EvaluateErrorWithHint(ui.WithHint(err, hint))}
}
