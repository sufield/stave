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
}
