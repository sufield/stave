package ports

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// AlertSink receives watch alerts from the continuous monitor.
// Implementations handle formatting and delivery (stdout, file, webhook).
type AlertSink interface {
	Emit(ctx context.Context, alert WatchAlert) error
	Close() error
}

// WatchTransition describes the state change between assessment runs.
type WatchTransition string

const (
	TransitionRegression  WatchTransition = "REGRESSION"
	TransitionRecovery    WatchTransition = "RECOVERY"
	TransitionDegradation WatchTransition = "DEGRADATION"
	TransitionStable      WatchTransition = "STABLE"
	TransitionInitial     WatchTransition = "INITIAL"
	TransitionError       WatchTransition = "ERROR"
)

// WatchAlert carries the result of a single assessment cycle in
// the continuous monitor. Emitted to all registered AlertSinks.
type WatchAlert struct {
	Timestamp     time.Time       `json:"timestamp"`
	Transition    WatchTransition `json:"transition"`
	SecurityState string          `json:"security_state"`
	Violations    int             `json:"violations"`
	NewViolations int             `json:"new_violations"`
	Regressions   []string        `json:"regressions,omitempty"`

	// SLA metrics for governance reporting.
	ActiveSLABreaches int     `json:"active_sla_breaches"`
	MaxDwellTimeHours float64 `json:"max_dwell_time_hours"`

	// Error context for DATA_INTEGRITY_FAILURE.
	ErrorMessage string `json:"error_message,omitempty"`

	// Owner routing fields — populated when a team manifest is loaded.
	OwnerTeamID       string `json:"owner_team_id,omitempty"`
	OwnerTeamName     string `json:"owner_team_name,omitempty"`
	OwnerContact      string `json:"owner_contact,omitempty"`
	OwnerSlackChannel string `json:"owner_slack_channel,omitempty"`
	OwnerJiraProject  string `json:"owner_jira_project,omitempty"`
}

// IsError reports whether this alert was emitted because the watch
// cycle itself failed (DATA_INTEGRITY_FAILURE etc.) rather than
// representing a normal posture transition. Sinks branch on this
// to surface the failure prominently instead of summarising the
// usual violation counters.
func (a WatchAlert) IsError() bool {
	return a.Transition == TransitionError
}

// StateLabel returns a short human-readable suffix that describes
// what the cycle observed: "no change" for STABLE, "recovered" for
// RECOVERY, the empty string for transitions whose default rendering
// is sufficient (REGRESSION / DEGRADATION / INITIAL). Owns the
// transition → label mapping so multiple sinks (stdout, future
// webhook) cannot drift.
func (a WatchAlert) StateLabel() string {
	switch a.Transition {
	case TransitionStable:
		return "no change"
	case TransitionRecovery:
		return "recovered"
	case TransitionRegression:
		return "regression"
	case TransitionDegradation:
		return "degradation"
	case TransitionInitial:
		return "initial"
	case TransitionError:
		return "error"
	default:
		// All six WatchTransition constants are handled above; an
		// unknown value here is a producer bug. Surface it in the
		// label so an operator sees the malformed alert rather than
		// silently rendering as a regression.
		return "unknown_transition:" + string(a.Transition)
	}
}

// FormatLine renders this alert as a single stdout-friendly summary
// line, prefixed with ts. Replaces the per-Transition switch in the
// stdout adapter so all six WatchTransition constants are handled
// in one place — adding a new transition forces an explicit case
// here instead of silently falling through to a default formatter.
func (a WatchAlert) FormatLine(ts string) string {
	switch a.Transition {
	case TransitionError:
		return fmt.Sprintf("[%s] WATCH  state=ERROR  %s", ts, a.ErrorMessage)
	case TransitionStable, TransitionRecovery:
		return fmt.Sprintf("[%s] WATCH  state=%s violations=%d (%s)",
			ts, a.SecurityState, a.Violations, a.StateLabel())
	case TransitionRegression, TransitionDegradation, TransitionInitial:
		parts := []string{
			fmt.Sprintf("[%s] WATCH  state=%s violations=%d new=%d",
				ts, a.SecurityState, a.Violations, a.NewViolations),
		}
		if len(a.Regressions) > 0 {
			parts = append(parts, fmt.Sprintf("regressions=[%s]", strings.Join(a.Regressions, ",")))
		}
		if a.MaxDwellTimeHours > 0 {
			parts = append(parts, fmt.Sprintf("max_dwell=%.0fh", a.MaxDwellTimeHours))
		}
		if a.ActiveSLABreaches > 0 {
			parts = append(parts, fmt.Sprintf("sla_breaches=%d", a.ActiveSLABreaches))
		}
		return strings.Join(parts, " ")
	default:
		return fmt.Sprintf("[%s] WATCH  unknown_transition=%q state=%s violations=%d",
			ts, a.Transition, a.SecurityState, a.Violations)
	}
}
