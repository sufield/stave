package ports

import (
	"context"
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

// CEFSeverity returns the ArcSight CEF "severity" field for the
// transition (1 = informational, 10 = highest). Centralised on the
// type so adapter code stops re-implementing the
// transition→numeric-severity mapping.
//
// Mapping: Error=10, Regression=8, Degradation=6, Recovery=3,
// other (Stable / Initial) = 1.
func (t WatchTransition) CEFSeverity() int {
	switch t {
	case TransitionRegression:
		return 8
	case TransitionDegradation:
		return 6
	case TransitionError:
		return 10
	case TransitionRecovery:
		return 3
	default:
		return 1
	}
}

// SyslogSeverity returns the RFC 5424 syslog severity number
// (0 = emergency, 6 = informational, 7 = debug). Adapter code
// converts this to its concrete syslog.Priority — keeping the
// numeric mapping on the core type so ports/alert.go does not
// import the platform-only log/syslog package.
//
// Mapping: Error=2 (CRIT), Regression=3 (ERR),
// Degradation=4 (WARNING), Recovery / other = 6 (INFO).
func (t WatchTransition) SyslogSeverity() int {
	switch t {
	case TransitionRegression:
		return 3
	case TransitionDegradation:
		return 4
	case TransitionError:
		return 2
	case TransitionRecovery:
		return 6
	default:
		return 6
	}
}

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
