//go:build !windows

package alert

import (
	"context"
	"fmt"
	"log/syslog"
	"strings"

	"github.com/sufield/stave/internal/core/ports"
)

// SyslogSink emits WatchAlerts as RFC 5424 structured syslog messages
// to the local syslog daemon. No network calls — the resident log
// forwarder (Splunk UF, Filebeat, rsyslog) owns the transport.
//
// Construct via NewSyslogSink. A zero-value SyslogSink is NOT valid:
// its writer is nil, and every method returns ErrSinkNotInitialized
// rather than panicking on the nil dereference.
type SyslogSink struct {
	writer *syslog.Writer
}

var _ ports.AlertSink = (*SyslogSink)(nil)

// NewSyslogSink opens a connection to the local syslog daemon.
func NewSyslogSink(facility syslog.Priority, tag string) (*SyslogSink, error) {
	w, err := syslog.New(facility|syslog.LOG_WARNING, tag)
	if err != nil {
		return nil, fmt.Errorf("open syslog: %w", err)
	}
	return &SyslogSink{writer: w}, nil
}

// ParseSyslogFacility converts a string facility name to syslog.Priority.
func ParseSyslogFacility(name string) (syslog.Priority, error) {
	switch strings.ToLower(name) {
	case "local0":
		return syslog.LOG_LOCAL0, nil
	case "local1":
		return syslog.LOG_LOCAL1, nil
	case "local2":
		return syslog.LOG_LOCAL2, nil
	case "local3":
		return syslog.LOG_LOCAL3, nil
	case "local4":
		return syslog.LOG_LOCAL4, nil
	case "local5":
		return syslog.LOG_LOCAL5, nil
	case "local6":
		return syslog.LOG_LOCAL6, nil
	case "local7":
		return syslog.LOG_LOCAL7, nil
	case "daemon":
		return syslog.LOG_DAEMON, nil
	case "user":
		return syslog.LOG_USER, nil
	default:
		return 0, fmt.Errorf("unknown syslog facility %q (use local0-local7, daemon, or user)", name)
	}
}

// Emit writes an alert to syslog with severity-appropriate priority.
// Routes through WatchTransition.SyslogSeverity (RFC 5424 numeric
// severity) so the syslog mapping table lives on the core type
// rather than duplicated here.
func (s *SyslogSink) Emit(_ context.Context, a ports.WatchAlert) error {
	if s.writer == nil {
		return ErrSinkNotInitialized
	}
	msg := FormatSyslog(a)
	switch syslog.Priority(a.Transition.SyslogSeverity()) {
	case syslog.LOG_CRIT:
		return s.writer.Crit(msg)
	case syslog.LOG_ERR:
		return s.writer.Err(msg)
	case syslog.LOG_WARNING:
		return s.writer.Warning(msg)
	default:
		return s.writer.Info(msg)
	}
}

// Close closes the syslog connection. Returns ErrSinkNotInitialized
// for a zero-value receiver rather than panicking on the nil
// dereference.
func (s *SyslogSink) Close() error {
	if s.writer == nil {
		return ErrSinkNotInitialized
	}
	return s.writer.Close()
}

// FormatSyslog produces an RFC 5424 structured data message from a WatchAlert.
func FormatSyslog(a ports.WatchAlert) string {
	var parts []string
	parts = append(parts, fmt.Sprintf(`transition="%s"`, a.Transition))
	parts = append(parts, fmt.Sprintf(`state="%s"`, a.SecurityState))
	parts = append(parts, fmt.Sprintf(`violations="%d"`, a.Violations))
	parts = append(parts, fmt.Sprintf(`new_violations="%d"`, a.NewViolations))
	if a.ActiveSLABreaches > 0 {
		parts = append(parts, fmt.Sprintf(`sla_breaches="%d"`, a.ActiveSLABreaches))
	}
	if a.MaxDwellTimeHours > 0 {
		parts = append(parts, fmt.Sprintf(`max_dwell_hours="%.0f"`, a.MaxDwellTimeHours))
	}
	if len(a.Regressions) > 0 {
		parts = append(parts, fmt.Sprintf(`regressions="%s"`, strings.Join(a.Regressions, ",")))
	}

	sd := "[stave@32473 " + strings.Join(parts, " ") + "]"
	return sd + " " + humanSummary(a)
}

func humanSummary(a ports.WatchAlert) string {
	if a.Transition == ports.TransitionError {
		return "watch error: " + a.ErrorMessage
	}
	return fmt.Sprintf("%s: %d violations (%d new), state=%s",
		a.Transition, a.Violations, a.NewViolations, a.SecurityState)
}
