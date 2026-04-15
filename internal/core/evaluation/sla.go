package evaluation

import (
	policy "github.com/sufield/stave/internal/core/controldef"
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

// AnnotateFindingSLA populates SLA fields on a single finding based
// on the control-level deadline (if set) or the profile-level default.
func AnnotateFindingSLA(f *Finding, ctl *policy.ControlDefinition, cfg *SLAConfig) {
	if cfg == nil {
		return
	}

	// Determine deadline: control override takes precedence.
	var deadlineHours float64
	var source string
	if ctl != nil && ctl.HasSLADeadline() {
		deadlineHours = ctl.SLADeadline().Hours()
		source = "control_override"
	} else {
		sev := f.ControlSeverity.String()
		deadlineHours = cfg.DeadlineBySeverity[sev]
		source = "profile:" + cfg.ProfileID
	}

	if deadlineHours <= 0 {
		return
	}

	f.SLADeadlineHours = &deadlineHours
	f.SLAPolicySource = source

	dwell := f.Evidence.UnsafeDurationHours
	if dwell <= deadlineHours {
		return
	}

	// SLA breached.
	f.SLABreached = true
	overdue := dwell - deadlineHours
	f.SLAOverdueHours = &overdue

	// Escalation: bump severity by one tier per breach period.
	// 1× overdue = +1 tier, 2× = +2, 3×+ = cap at critical.
	periodsOverdue := max(int(overdue/deadlineHours), 1)
	escalated := escalateSeverity(f.ControlSeverity.String(), periodsOverdue)
	if escalated != f.ControlSeverity.String() {
		f.SLAEscalatedSeverity = escalated
	}
}

// escalateSeverity bumps severity by n tiers, capping at critical.
func escalateSeverity(base string, tiers int) string {
	order := []string{"low", "medium", "high", "critical"}
	idx := -1
	for i, s := range order {
		if s == base {
			idx = i
			break
		}
	}
	if idx < 0 {
		return base
	}
	target := idx + tiers
	if target >= len(order) {
		target = len(order) - 1
	}
	return order[target]
}
