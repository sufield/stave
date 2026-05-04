package alert

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/version"
)

// errSinkClosed is returned when Emit is called after Close.
var errSinkClosed = errors.New("alert sink: already closed")

// CEFFileSink emits WatchAlerts in ArcSight Common Event Format (CEF)
// to a file. Picked up by Splunk UF, Filebeat, or any log forwarder.
//
// CEF: CEF:Version|Device Vendor|Device Product|Device Version|
//
//	Signature ID|Name|Severity|Extension
type CEFFileSink struct {
	path string
	f    *os.File
	mu   sync.Mutex
}

var _ ports.AlertSink = (*CEFFileSink)(nil)

// NewCEFFileSink opens a CEF output file in append mode.
func NewCEFFileSink(path string) (*CEFFileSink, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // user-specified path
	if err != nil {
		return nil, fmt.Errorf("open CEF file %q: %w", path, err)
	}
	return &CEFFileSink{path: path, f: f}, nil
}

// Emit appends a CEF-formatted alert line to the file.
func (s *CEFFileSink) Emit(_ context.Context, a ports.WatchAlert) error {
	line := FormatCEF(a)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return errSinkClosed
	}
	_, err := fmt.Fprintln(s.f, line)
	return err
}

// Close closes the CEF file. Subsequent Emit calls return errSinkClosed.
//
// Sync is called before Close so a process exit immediately after
// Close cannot lose buffered alert lines on filesystems where the
// page cache hasn't yet flushed. Same discipline applied to FileSink
// and fsutil.WriteFileAtomic.
func (s *CEFFileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	syncErr := s.f.Sync()
	closeErr := s.f.Close()
	s.f = nil
	// errors.Join keeps both diagnostics visible when both fail —
	// previously closeErr was silently dropped on a Sync failure,
	// hiding a separate underlying problem.
	return errors.Join(syncErr, closeErr)
}

// FormatCEF produces a CEF line from a WatchAlert.
//
// Header: CEF:0|Stave|stave-watch|<version>|<signatureID>|<name>|<severity>|<ext>
//
// Severity mapping (CEF uses 0-10):
//
//	REGRESSION  → 8
//	DEGRADATION → 6
//	ERROR       → 10
//	RECOVERY    → 3
//	STABLE      → 1
//	INITIAL     → 1
func FormatCEF(a ports.WatchAlert) string {
	sigID := string(a.Transition)
	name := humanSummaryCEF(a)
	sev := a.Transition.CEFSeverity()

	// Extension key=value pairs.
	var ext []string
	ext = append(ext, fmt.Sprintf("rt=%d", a.Timestamp.UnixMilli()))
	ext = append(ext, "cs1="+cefEscape(a.SecurityState))
	ext = append(ext, "cs1Label=SecurityState")
	ext = append(ext, fmt.Sprintf("cn1=%d", a.Violations))
	ext = append(ext, "cn1Label=Violations")
	ext = append(ext, fmt.Sprintf("cn2=%d", a.NewViolations))
	ext = append(ext, "cn2Label=NewViolations")
	if a.ActiveSLABreaches > 0 {
		ext = append(ext, fmt.Sprintf("cn3=%d", a.ActiveSLABreaches))
		ext = append(ext, "cn3Label=SLABreaches")
	}
	if a.MaxDwellTimeHours > 0 {
		ext = append(ext, fmt.Sprintf("cfp1=%.1f", a.MaxDwellTimeHours))
		ext = append(ext, "cfp1Label=MaxDwellHours")
	}
	if len(a.Regressions) > 0 {
		ext = append(ext, "cs2="+cefEscape(strings.Join(a.Regressions, ",")))
		ext = append(ext, "cs2Label=Regressions")
	}
	if a.ErrorMessage != "" {
		ext = append(ext, "msg="+cefEscape(a.ErrorMessage))
	}

	return fmt.Sprintf("CEF:0|Stave|stave-watch|%s|%s|%s|%d|%s",
		cefEscape(version.String),
		cefEscape(sigID),
		cefEscape(name),
		sev,
		strings.Join(ext, " "))
}

func humanSummaryCEF(a ports.WatchAlert) string {
	if a.Transition == ports.TransitionError {
		return "Watch error: " + a.ErrorMessage
	}
	return fmt.Sprintf("%s: %d violations (%d new)",
		a.Transition, a.Violations, a.NewViolations)
}

// cefEscape escapes CEF values per ArcSight spec:
// backslash → \\, pipe → \|, equals → \=, newline → \n
func cefEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `|`, `\|`)
	s = strings.ReplaceAll(s, `=`, `\=`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}
