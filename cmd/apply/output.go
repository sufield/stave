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

// ReportApply prints the outcome of an evaluation and returns an error when
// the gate decision (precomputed by stave.EvaluateStandard) indicates a block.
// The summary message + advisory/block hint plumbing are composed from the
// primitive StandardResult; the diagnose hint + next steps are built
// command-side from the security state and resolved dirs.
func (r *Reporter) ReportApply(res stave.StandardResult) error {
	if res.SummaryMessage != "" {
		r.Emit(r.Stderr, res.SummaryMessage)
	}

	// The findings output is the result; unsolicited "Hint:" / "Next steps:"
	// chatter on every run is noise (and trained users to ignore stderr).
	// `stave diagnose` and the other follow-ups are documented in --help.
	switch res.Gate {
	case gateAllow, gateAdvisory:
		return nil
	default: // block
		return ui.ErrViolationsFound
	}
}

// gateViolations returns the violation gating error without rendering any
// user-facing summary, so the --new-only path applies the same exit-code gate
// after rendering its own signal-filtered view. nil for allow/advisory;
// ui.ErrViolationsFound for a block (non-compliant) state.
//
// In compound-only mode, exit 0 when no compound findings exist even if
// atomic findings triggered a BLOCK gate.
func gateViolations(res stave.StandardResult) error {
	if res.Gate == gateAllow || res.Gate == gateAdvisory {
		return nil
	}
	if res.CompoundOnlyMode && res.CompoundFindingCount == 0 {
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
