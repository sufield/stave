package alert

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
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
	path   string
	f      *os.File
	mu     sync.Mutex
	closed bool
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
	if s.closed || s.f == nil {
		return errSinkClosed
	}
	if _, err := fmt.Fprintln(s.f, line); err != nil {
		// Mirror FileSink: a write failure (disk full, broken pipe,
		// stale NFS handle) leaves the descriptor in an undefined
		// state. Close + mark the sink failed so subsequent Emit
		// calls return errSinkClosed instead of writing into a
		// half-broken FD or leaking it across every later call.
		closeErr := s.f.Close()
		s.f = nil
		s.closed = true
		if closeErr != nil {
			return errors.Join(
				fmt.Errorf("write CEF alert to %s: %w", s.path, err),
				fmt.Errorf("close CEF file after write failure: %w", closeErr),
			)
		}
		return fmt.Errorf("write CEF alert to %s: %w", s.path, err)
	}
	return nil
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
	s.closed = true
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
	ext = append(ext, "rt="+strconv.FormatInt(a.Timestamp.UnixMilli(), 10))
	ext = append(ext, "cs1="+cefEscape(a.SecurityState))
	ext = append(ext, "cs1Label=SecurityState")
	ext = append(ext, "cn1="+strconv.Itoa(a.Violations))
	ext = append(ext, "cn1Label=Violations")
	ext = append(ext, "cn2="+strconv.Itoa(a.NewViolations))
	ext = append(ext, "cn2Label=NewViolations")
	if a.ActiveSLABreaches > 0 {
		ext = append(ext, "cn3="+strconv.Itoa(a.ActiveSLABreaches))
		ext = append(ext, "cn3Label=SLABreaches")
	}
	if a.MaxDwellTimeHours > 0 {
		ext = append(ext, "cfp1="+strconv.FormatFloat(a.MaxDwellTimeHours, 'f', 1, 64))
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
	s = strings.ReplaceAll(s, "\r", `\r`)
	return s
}
