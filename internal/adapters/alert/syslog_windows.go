//go:build windows

package alert

import (
	"context"
	"errors"

	"github.com/sufield/stave/internal/core/ports"
)

// SyslogSink is not available on Windows. Use FileSink or CEFFileSink.
type SyslogSink struct{}

// NewSyslogSink returns an error on Windows — syslog is Unix-only.
func NewSyslogSink(_ int, _ string) (*SyslogSink, error) {
	return nil, errors.New("syslog is not supported on Windows; use --sink file:<path> or --sink cef:<path>")
}

// Emit is not supported on Windows.
func (s *SyslogSink) Emit(_ context.Context, _ ports.WatchAlert) error {
	return errors.New("syslog not supported on Windows")
}

// Close is a no-op.
func (s *SyslogSink) Close() error { return nil }

// ParseSyslogFacility returns an error on Windows.
func ParseSyslogFacility(_ string) (int, error) {
	return 0, errors.New("syslog not supported on Windows")
}

// FormatSyslog is available on all platforms for testing.
func FormatSyslog(a ports.WatchAlert) string {
	return string(a.Transition) + ": " + a.SecurityState
}
