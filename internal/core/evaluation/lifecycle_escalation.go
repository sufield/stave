package evaluation

import (
	"time"

	policy "github.com/sufield/stave/internal/core/controldef"
)

// AnnotateLifecycleDeadline escalates severity based on proximity to
// a service deprecation deadline. When a control's lifecycle block
// carries status sunset/eol AND a deadline date, findings from that
// control grow more severe as the deadline approaches:
//
//	>180 days remaining: no change
//	91–180 days:         +1 tier
//	31–90 days:          +2 tiers
//	≤30 days:            +3 tiers (capped at critical via Bump)
//
// This is distinct from SLA escalation (dwell time against a
// remediation deadline). Lifecycle escalation reflects the urgency
// of migrating off a service that AWS is removing.
func (f *Finding) AnnotateLifecycleDeadline(ctl *policy.ControlDefinition, evalTime time.Time) {
	if f == nil || ctl == nil {
		return
	}
	if !ctl.Lifecycle.EffectiveStatus().IsDeprecated() {
		return
	}
	if ctl.Lifecycle.Deadline == "" {
		return
	}

	deadline, err := time.Parse("2006-01-02", ctl.Lifecycle.Deadline)
	if err != nil {
		return
	}

	remaining := int(deadline.Sub(evalTime).Hours() / 24)
	f.lifecycleDeadline = ctl.Lifecycle.Deadline
	f.lifecycleDaysRemaining = &remaining

	var tiers int
	switch {
	case remaining > 180:
		return
	case remaining > 90:
		tiers = 1
	case remaining > 30:
		tiers = 2
	default:
		tiers = 3
	}

	escalated := f.ControlSeverity.Bump(tiers)
	if escalated != f.ControlSeverity {
		f.lifecycleEscalatedSeverity = escalated
	}
}

// LifecycleEscalatedSeverityValue returns the lifecycle-escalated
// severity, or SeverityNone when no escalation applied.
func (f *Finding) LifecycleEscalatedSeverityValue() policy.Severity {
	if f == nil {
		return policy.SeverityNone
	}
	return f.lifecycleEscalatedSeverity
}

// LifecycleDeadline returns the deprecation deadline date string
// and a presence indicator.
func (f *Finding) LifecycleDeadline() (string, bool) {
	if f == nil || f.lifecycleDeadline == "" {
		return "", false
	}
	return f.lifecycleDeadline, true
}

// LifecycleDaysRemaining returns the days until the deprecation
// deadline, with a presence indicator.
func (f *Finding) LifecycleDaysRemaining() (int, bool) {
	if f == nil || f.lifecycleDaysRemaining == nil {
		return 0, false
	}
	return *f.lifecycleDaysRemaining, true
}
