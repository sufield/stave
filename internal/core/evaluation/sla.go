package evaluation

import (
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// SLAConfig holds the resolved SLA policy for finding annotation.
type SLAConfig struct {
	// ProfileID is the loaded SLA profile (e.g. "hipaa", "default").
	ProfileID string

	// DeadlineBySeverity maps severity string to deadline in hours.
	DeadlineBySeverity map[string]float64

	// EscalationFactor is the multiplier per breach period.
	EscalationFactor float64
}

// AnnotateSLA populates SLA fields on the finding based on the
// control-level deadline (if set) or the profile-level default. The
// computation lives on Finding because it both reads (severity, dwell)
// and writes (SLABreached, SLAOverdueHours, SLAEscalatedSeverity) the
// finding's own state — keeping the mutation on the receiver that owns
// the fields.
func (f *Finding) AnnotateSLA(ctl *policy.ControlDefinition, cfg *SLAConfig) {
	if f == nil || cfg == nil {
		return
	}

	// Determine deadline: control override takes precedence.
	var deadlineHours float64
	var source kernel.SLAPolicySource
	if ctl != nil && ctl.HasSLADeadline() {
		deadlineHours = ctl.SLADeadline().Hours()
		source = kernel.SLAPolicySourceControlOverride
	} else {
		sev := f.SeverityLabel()
		deadlineHours = cfg.DeadlineBySeverity[sev]
		source = kernel.SLAPolicySourceProfile(cfg.ProfileID)
	}

	if deadlineHours <= 0 {
		return
	}

	f.slaDeadlineHours = &deadlineHours
	f.slaPolicySource = source

	dwell := f.Evidence.UnsafeDurationHours
	if dwell <= deadlineHours {
		return
	}

	// SLA breached.
	f.slaBreached = true
	overdue := dwell - deadlineHours
	f.slaOverdueHours = &overdue

	// Escalation: bump severity by one tier per multiple of the
	// deadline elapsed. The mapping is intentionally measured in
	// dwell, not overdue:
	//
	//   dwell ∈ (1×, 2×) → +1 tier
	//   dwell ∈ [2×, 3×) → +2 tiers
	//   dwell ∈ [3×, ∞)  → +3 tiers (then capped at critical)
	//
	// The earlier formula divided `overdue` by `deadline` and
	// floored, so dwell of exactly 2× gave overdue/deadline = 1.0,
	// floor = 1, producing only +1 tier — off by one. Using
	// `int(dwell/deadline)` directly fixes the boundary so a finding
	// that has sat at twice the SLA deadline visibly escalates two
	// tiers, and three times escalates three. The explicit max(,1)
	// preserves the "anything past deadline gets at least +1"
	// behavior for the just-breached case (dwell ≈ 1.001×).
	periodsOverdue := max(int(dwell/deadlineHours), 1)
	escalated := f.ControlSeverity.Bump(periodsOverdue)
	if escalated != f.ControlSeverity {
		f.slaEscalatedSeverity = escalated
	}
}
