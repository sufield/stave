// Package exception implements the acknowledged exception mechanism for
// controls that have legitimate configurations failing checks. Exceptions
// require compensating controls that must all pass for the exception to
// be valid.
package exception

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/profile"

	"gopkg.in/yaml.v3"
)

// Config represents a single acknowledged exception declaration.
type Config struct {
	ControlID        kernel.ControlID   `yaml:"control_id" json:"control_id"`
	Bucket           string             `yaml:"bucket" json:"bucket"`
	Rationale        string             `yaml:"rationale" json:"rationale"`
	AcknowledgedBy   string             `yaml:"acknowledged_by" json:"acknowledged_by"`
	AcknowledgedDate Date               `yaml:"acknowledged_date" json:"acknowledged_date"`
	RequiresPassing  []kernel.ControlID `yaml:"requires_passing" json:"requires_passing"`
}

// Date wraps time.Time for YAML/JSON fields that accept both "2006-01-02"
// and RFC3339 formats. The zero value renders as an empty string.
type Date struct{ time.Time }

// UnmarshalYAML parses a date string in either "2006-01-02" or RFC3339 format.
func (d *Date) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	if s == "" {
		d.Time = time.Time{}
		return nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		t, err = time.Parse(time.RFC3339, s)
	}
	if err != nil {
		return fmt.Errorf("invalid date %q (use YYYY-MM-DD or RFC3339)", s)
	}
	d.Time = t
	return nil
}

// MarshalJSON renders the date as "2006-01-02" for JSON output.
func (d Date) MarshalJSON() ([]byte, error) {
	if d.IsZero() {
		return []byte(`""`), nil
	}
	return []byte(`"` + d.Format("2006-01-02") + `"`), nil
}

// String returns the date as "2006-01-02".
func (d Date) String() string {
	if d.IsZero() {
		return ""
	}
	return d.Format("2006-01-02")
}

// StaveConfig is the top-level stave.yaml structure (only exceptions parsed).
type StaveConfig struct {
	Exceptions []Config `yaml:"exceptions"`
}

// LoadExceptions loads exception declarations from a stave.yaml file.
// Returns nil with no error if the file does not exist.
func LoadExceptions(path string) ([]Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path from user config
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var cfg StaveConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	for i, exc := range cfg.Exceptions {
		if err := validateException(exc); err != nil {
			return nil, fmt.Errorf("exception[%d] (%s): %w", i, exc.ControlID, err)
		}
	}

	return cfg.Exceptions, nil
}

func validateException(exc Config) error {
	if strings.TrimSpace(string(exc.ControlID)) == "" {
		return errors.New("control_id is required")
	}
	if strings.TrimSpace(exc.Rationale) == "" {
		return errors.New("rationale is required")
	}
	// Audit-field requirements. An acknowledged exception is a
	// human-attributable security decision; without `acknowledged_by`
	// there is no person to reach when the exception's
	// compensating-control assumption breaks, and without
	// `acknowledged_date` the expiry check (MaxExceptionAge) has no
	// reference point and would treat the exception as never
	// expiring. Both must be present at validation, not just
	// "filled in eventually."
	if strings.TrimSpace(exc.AcknowledgedBy) == "" {
		return errors.New("acknowledged_by is required — exceptions must be human-attributable")
	}
	if exc.AcknowledgedDate.IsZero() {
		return errors.New("acknowledged_date is required — exceptions must carry the date they were accepted so expiry can be computed")
	}
	if len(exc.RequiresPassing) == 0 {
		return errors.New("requires_passing is mandatory — compensating controls must be specified")
	}
	return nil
}

// InvalidReason classifies why an exception was rejected.
type InvalidReason string

const (
	// InvalidReasonNone means the exception is valid (zero value).
	InvalidReasonNone InvalidReason = ""
	// InvalidReasonCompensatingFailed means one or more compensating controls are not passing.
	InvalidReasonCompensatingFailed InvalidReason = "compensating_controls_failing"
	// InvalidReasonExpired means the exception has exceeded its validity period.
	InvalidReasonExpired InvalidReason = "expired"
)

// AcknowledgedResult represents the outcome of applying an exception.
type AcknowledgedResult struct {
	ControlID            kernel.ControlID      `json:"control_id"`
	Bucket               string                `json:"bucket"`
	Rationale            string                `json:"rationale"`
	AcknowledgedBy       string                `json:"acknowledged_by"`
	AcknowledgedDate     Date                  `json:"acknowledged_date"`
	CompensatingControls []CompensatingControl `json:"compensating_controls"`
	Valid                bool                  `json:"valid"`
	InvalidReason        InvalidReason         `json:"invalid_reason,omitempty"`
	InvalidDetail        string                `json:"invalid_detail,omitempty"`
}

// CompensatingControl shows the status of a required compensating invariant.
type CompensatingControl struct {
	ControlID kernel.ControlID `json:"control_id"`
	Passing   bool             `json:"passing"`
}

// MaxExceptionAge is the default validity period for an
// acknowledged exception. After this many days from the
// AcknowledgedDate, the exception is treated as expired and stops
// suppressing the finding. Operators must re-acknowledge with a
// fresh date to keep the exception in effect — the rule prevents
// "I said it was OK once in 2019" from suppressing findings
// indefinitely.
const MaxExceptionAge = 365 * 24 * time.Hour

// ApplyExceptions processes exception declarations against profile results.
// It modifies results in place: valid exceptions change FAIL to ACKNOWLEDGED.
// currentBucket is the bucket name being evaluated; exceptions scoped to a
// different bucket (non-empty Bucket field that does not match) are skipped.
// Returns the list of acknowledged results for reporting.
//
// `now` anchors the expiry check: an exception whose
// AcknowledgedDate is more than MaxExceptionAge before `now` is
// rejected with InvalidReasonExpired and does NOT suppress the
// finding. Pass time.Time{} (the zero value) to disable the
// expiry check — useful for fixture tests that want to assert the
// non-expiry branches without the date drifting under them.
func ApplyExceptions(exceptions []Config, results []profile.Result, currentBucket string, now time.Time) []AcknowledgedResult {
	if len(exceptions) == 0 {
		return nil
	}

	// Build result lookup.
	resultMap := make(map[kernel.ControlID]*profile.Result)
	for i := range results {
		resultMap[results[i].ControlID] = &results[i]
	}

	var acknowledged []AcknowledgedResult

	for _, exc := range exceptions {
		// Skip exceptions scoped to a different bucket.
		if exc.Bucket != "" && exc.Bucket != currentBucket {
			continue
		}

		r, exists := resultMap[exc.ControlID]
		if !exists || r.Pass {
			continue // not evaluated or already passing
		}

		// Check compensating controls.
		controls := make([]CompensatingControl, len(exc.RequiresPassing))
		allPassing := true
		for i, reqID := range exc.RequiresPassing {
			passing := false
			if req, ok := resultMap[reqID]; ok {
				passing = req.Pass
			}
			controls[i] = CompensatingControl{ControlID: reqID, Passing: passing}
			if !passing {
				allPassing = false
			}
		}

		// Expiry check runs before compensating-control check. An
		// expired exception is invalid regardless of whether the
		// compensating controls happen to still pass — the
		// operator's promise that they were watching has aged out.
		expired := false
		if !now.IsZero() && !exc.AcknowledgedDate.IsZero() {
			expiresAt := exc.AcknowledgedDate.Add(MaxExceptionAge)
			expired = now.After(expiresAt)
		}

		ack := AcknowledgedResult{
			ControlID:            exc.ControlID,
			Bucket:               exc.Bucket,
			Rationale:            exc.Rationale,
			AcknowledgedBy:       exc.AcknowledgedBy,
			AcknowledgedDate:     exc.AcknowledgedDate,
			CompensatingControls: controls,
			Valid:                allPassing && !expired,
		}

		if expired {
			ack.InvalidReason = InvalidReasonExpired
			expiresAt := exc.AcknowledgedDate.Add(MaxExceptionAge)
			ack.InvalidDetail = fmt.Sprintf(
				"acknowledged %s, validity period (%d days) ended %s — re-acknowledge with a fresh date to keep the exception in effect",
				exc.AcknowledgedDate, int(MaxExceptionAge.Hours()/24),
				expiresAt.Format("2006-01-02"))
			r.Finding = r.Finding + fmt.Sprintf(
				" [Exception expired on %s; re-acknowledge to suppress]",
				expiresAt.Format("2006-01-02"))
			acknowledged = append(acknowledged, ack)
			continue
		}

		if allPassing {
			// Exception is valid: change result to ACKNOWLEDGED.
			r.Finding = fmt.Sprintf("ACKNOWLEDGED: %s (exception by %s on %s)",
				exc.Rationale, exc.AcknowledgedBy, exc.AcknowledgedDate)
			r.Remediation = ""
			r.Pass = true
			r.Severity = policy.SeverityLow
		} else {
			// Exception invalid: keep FAIL, note the failure.
			var failing []string
			for _, c := range controls {
				if !c.Passing {
					failing = append(failing, string(c.ControlID))
				}
			}
			ack.InvalidReason = InvalidReasonCompensatingFailed
			ack.InvalidDetail = "compensating control(s) not passing: " + strings.Join(failing, ", ")
			r.Finding = r.Finding + fmt.Sprintf(
				" [Exception declared but compensating control %s is not passing]",
				strings.Join(failing, ", "))
		}

		acknowledged = append(acknowledged, ack)
	}

	return acknowledged
}
