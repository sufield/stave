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

	// Escalation: bump severity by tier-count derived from how many
	// (deadline × EscalationFactor) periods of dwell have elapsed.
	// Tier-count layout:
	//
	//   dwell ∈ (1×, 2×) → +1 tier
	//   dwell ∈ [2×, 3×) → +2 tiers
	//   dwell ∈ [3×, ∞)  → +3 tiers (capped at critical via Bump)
	//
	// EscalationFactor scales the period length: a factor of 2 means
	// the operator wants escalation only every TWO deadlines of
	// overrun (more lenient than 1×); a factor of 0.5 escalates
	// every half-deadline (stricter). The previous shape silently
	// ignored EscalationFactor by dividing dwell by deadlineHours
	// directly. A non-positive EscalationFactor falls back to 1.0
	// to preserve the default behaviour.
	factor := cfg.EscalationFactor
	if factor <= 0 {
		factor = 1.0
	}
	periodHours := deadlineHours * factor
	periodsOverdue := max(int(dwell/periodHours), 1)
	escalated := f.ControlSeverity.Bump(periodsOverdue)
	if escalated != f.ControlSeverity {
		f.slaEscalatedSeverity = escalated
	}
}
