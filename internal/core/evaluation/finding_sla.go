package evaluation

import (
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// SLA state vocabulary on Finding. The four predicates form a
// strict-subset ladder; pick the loosest one that answers the
// caller's actual question.
//
//	HasSLA()              ← a deadline applies (the SLA evaluator
//	                        attached one). Says nothing about
//	                        whether it was met.
//	IsAnyBreach()         ← the breach flag is set. The overdue
//	                        duration may not be captured (degraded
//	                        mode when the evaluator runs without a
//	                        timestamped deadline). Use for boolean
//	                        rollups (count of breached, gating).
//	IsOverdue()           ← breached AND the overdue duration was
//	                        recorded. Use when the value will be
//	                        dereferenced (the renderer that prints
//	                        "%.0fh overdue").
//	IsCriticalSLABreach() ← breached AND the original or escalated
//	                        severity reaches Critical. The
//	                        gating-side "must block CI" predicate.
//
// Ladder direction: HasSLA ⊇ IsAnyBreach ⊇ IsOverdue (overdue
// implies breach implies tracked). IsCriticalSLABreach is a
// strictly tighter version of IsAnyBreach (severity-bounded), not
// of IsOverdue — a critical breach can fire without an overdue
// duration recorded.

// IsCriticalSLABreach reports whether this finding is an SLA breach
// where either the original control severity or the SLA-escalated
// severity reaches Critical. Consumed by the apply runner to decide
// whether to set HasCriticalSLABreach on the run summary.
func (f *Finding) IsCriticalSLABreach() bool {
	if !f.slaBreached {
		return false
	}
	return f.ControlSeverity == policy.SeverityCritical ||
		f.slaEscalatedSeverity == policy.SeverityCritical
}

// IsAnyBreach reports whether this finding has breached its SLA,
// regardless of severity OR overdue-duration capture. Use for
// counters, gating booleans, and CSV status columns where only
// the "did the breach happen" signal matters; prefer IsOverdue
// when the renderer will dereference the overdue hours value.
//
// See the SLA state vocabulary on IsCriticalSLABreach for the
// full ladder.
func (f *Finding) IsAnyBreach() bool {
	return f != nil && f.slaBreached
}

// IsOverdue reports whether the finding has breached SLA AND the
// overdue duration is recorded. Use this when the renderer or
// summary will dereference the overdue value; use IsAnyBreach for
// boolean-only rollups.
//
// The two-field check matters: a finding can be flagged breached
// without an overdue duration when the SLA evaluator runs in a
// degraded mode (no deadline configured). Treating the breach
// flag alone as "overdue" inflated counters in those cases.
//
// See IsCriticalSLABreach for the full SLA state vocabulary.
func (f *Finding) IsOverdue() bool {
	return f.slaBreached && f.slaOverdueHours != nil
}

// HasSLA reports whether an SLA deadline applies to this finding.
// The loosest predicate in the SLA vocabulary: says only that the
// evaluator attached a deadline, not that the deadline has been
// met or breached. Use for "is this finding under SLA tracking?"
// gating; use IsAnyBreach / IsOverdue for breach-state checks.
//
// See IsCriticalSLABreach for the full SLA state ladder.
func (f *Finding) HasSLA() bool {
	return f != nil && f.slaDeadlineHours != nil
}

// SLADeadlineValue returns the SLA deadline in hours together with
// a presence indicator. Replaces patterns that dereferenced
// f.slaDeadlineHours after a separate nil check; callers can pass
// the (value, ok) pair through their formatters without touching
// the underlying pointer.
func (f *Finding) SLADeadlineValue() (float64, bool) {
	if f == nil || f.slaDeadlineHours == nil {
		return 0, false
	}
	return *f.slaDeadlineHours, true
}

// OverdueHours returns the number of hours past SLA, with a presence
// indicator. Returns (0, false) when the finding is not overdue or
// has no recorded overdue duration. Replaces the raw
// (*f.slaOverdueHours) dereference in cmd/export/compliance/output.go
// and callers that need the value without re-checking the nil.
func (f *Finding) OverdueHours() (float64, bool) {
	if f == nil || f.slaOverdueHours == nil {
		return 0, false
	}
	return *f.slaOverdueHours, true
}

// RehydrateSLA restores the SLA state from previously-serialised
// wire fields. Used by loaders / library converters that
// reconstruct a Finding from JSON (or from a public mirror like
// pkg/stave.Finding); the AnnotateSLA invariant — only the
// evaluation package writes the SLA fields — is preserved
// because RehydrateSLA itself lives in the evaluation package
// and accepts the wire shape as input.
//
// The escalated severity carries through as-is; if the snapshot
// did not capture an escalation, callers pass policy.SeverityNone.
func (f *Finding) RehydrateSLA(deadline *float64, breached bool, overdue *float64, escalated policy.Severity, source kernel.SLAPolicySource) {
	if f == nil {
		return
	}
	f.slaDeadlineHours = deadline
	f.slaBreached = breached
	f.slaOverdueHours = overdue
	f.slaEscalatedSeverity = escalated
	f.slaPolicySource = source
}

// SLAEscalatedSeverityValue returns the escalated severity the SLA
// evaluator computed for this finding (Critical when dwell time
// has rolled the original severity past the catalog ladder).
// Returns SeverityNone when no escalation applied.
func (f *Finding) SLAEscalatedSeverityValue() policy.Severity {
	if f == nil {
		return policy.SeverityNone
	}
	return f.slaEscalatedSeverity
}

// SLAPolicySourceLabel returns the SLA policy source's wire-format
// label ("control_override", "profile:<id>", or "" when no SLA
// applies). Replaces the f.slaPolicySource.String() probe.
func (f *Finding) SLAPolicySourceLabel() string {
	if f == nil {
		return ""
	}
	return f.slaPolicySource.String()
}

// SLAPolicySourceValue returns the typed SLA policy source. Use
// when comparing against kernel.SLAPolicySource constants;
// renderers prefer SLAPolicySourceLabel.
func (f *Finding) SLAPolicySourceValue() kernel.SLAPolicySource {
	if f == nil {
		return ""
	}
	return f.slaPolicySource
}

// SLADeadlinePtr returns the SLA deadline as a *float64 — same
// pointer shape the wire format and DTO use. Nil when no deadline
// applies. For boolean / numeric inspection prefer HasSLA,
// IsOverdue, SLADeadlineValue.
func (f *Finding) SLADeadlinePtr() *float64 {
	if f == nil {
		return nil
	}
	return f.slaDeadlineHours
}

// SLAOverduePtr returns the SLA-overdue dwell as a *float64. See
// SLADeadlinePtr for the pointer-shape rationale.
func (f *Finding) SLAOverduePtr() *float64 {
	if f == nil {
		return nil
	}
	return f.slaOverdueHours
}

// SLABreachedFlag returns the raw boolean. Use only when copying
// the SLA triple into a DTO that mirrors the wire shape;
// otherwise prefer the predicate methods (IsAnyBreach, IsOverdue,
// SLAContribution).
func (f *Finding) SLABreachedFlag() bool {
	return f != nil && f.slaBreached
}

// SLAUrgencyFactor returns the multiplier the rank-priority pass
// applies to a finding's base risk score based on how close it is to
// (or past) its SLA POLICY deadline.
//
// Urgency is computed against f.slaDeadlineHours — the deadline
// AnnotateSLA derives from the SLA profile (or control override) — NOT
// against Evidence.ThresholdHours (the control's max_unsafe_duration).
// The two are distinct: a finding exists precisely because the unsafe
// dwell already exceeded the control threshold, so the threshold-based
// "remaining" is always negative and would pin every finding at maximum
// urgency. The SLA deadline is a separate policy clock the operator sets
// for remediation, and remaining = deadline − dwell is genuinely
// positive while a finding is still within its SLA.
//
// Returns 1.0 when the finding carries no SLA deadline (AnnotateSLA was
// not run, or the profile sets no deadline for this severity) so callers
// can multiply unconditionally — no policy clock means no urgency.
//
// urgencyFn is the package-level multiplier function from the rank
// package; passing it as a parameter avoids importing the rank package
// from core (which would invert the dependency arrow). The caller
// (rank.BuildRoadmap) supplies SLAUrgencyMultiplier.
func (f *Finding) SLAUrgencyFactor(urgencyFn func(remainingHours float64, isOverdue bool) float64) float64 {
	if f == nil || urgencyFn == nil {
		return 1.0
	}
	deadline, hasSLA := f.SLADeadlineValue()
	if !hasSLA {
		return 1.0
	}
	remaining := deadline - f.Evidence.UnsafeDurationHours
	return urgencyFn(remaining, f.IsOverdue())
}

// SLAStats is the per-finding SLA contribution surfaced by
// SLAContribution. Renderers and aggregators consume one struct
// rather than three accessors (HasSLA, IsOverdue, OverdueHours)
// in sequence.
//
//   - Detected is 1 when an SLA deadline applies to this finding.
//   - Breached is 1 when the deadline has been exceeded.
//   - WithinSLA is 1 when the deadline applies but is not yet
//     breached. Detected = Breached + WithinSLA.
//   - OverdueHours is the dwell-time excess past the deadline.
type SLAStats struct {
	Detected     int
	Breached     int
	WithinSLA    int
	OverdueHours float64
}

// SLAContribution returns this finding's contribution to an SLA
// rollup. Replaces the (HasSLA / IsOverdue / OverdueHours)
// triple-call pattern in cmd/export/compliance/output.go and
// similar accumulators so a future SLA-shape change is one edit
// on the type.
func (f *Finding) SLAContribution() SLAStats {
	if f == nil || !f.HasSLA() {
		return SLAStats{}
	}
	out := SLAStats{Detected: 1}
	switch {
	case f.IsOverdue():
		out.Breached = 1
		if h, ok := f.OverdueHours(); ok {
			out.OverdueHours = h
		}
	case f.IsAnyBreach():
		// Degraded-mode breach: the SLA flag is set but the
		// overdue-hours field is nil (snapshot lacks lifecycle
		// dates needed to compute remaining time). Counts as
		// breached, NOT within-SLA — the previous else branch
		// silently classified these as compliant.
		out.Breached = 1
	default:
		out.WithinSLA = 1
	}
	return out
}
