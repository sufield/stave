// Package exception implements the acknowledged exception mechanism for
// controls that have legitimate configurations failing checks. Exceptions
// require compensating controls that must all pass for the exception to
// be valid.
package exception

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/platform/fsutil"
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
//
// Path traversal hygiene: LoadExceptions runs before any other
// command-side input validation, so a maliciously crafted relative
// path (e.g. `../../etc/passwd`) used to be passed straight into
// os.ReadFile and leaked file contents through the YAML-parse
// error message. CleanUserPath normalizes the path lexically and
// rejects the canonical traversal sequences before we touch the
// filesystem.
func LoadExceptions(path string) ([]Config, error) {
	// Reject parent-directory traversal on the raw input. filepath.Clean
	// rewrites interior `..` segments (a/b/../c → a/c) but keeps leading
	// ones (../etc → ../etc), so checking after Clean catches only some
	// of the cases authors actually try. Reject any "..", canonicalized
	// or not, on the user-provided string so the rejection is total
	// rather than dependent on the operating system's normalization.
	if strings.Contains(path, "..") {
		return nil, fmt.Errorf("exceptions path %q contains parent-directory traversal", path)
	}
	clean := fsutil.CleanUserPath(path)
	data, err := os.ReadFile(clean) //nolint:gosec // path normalized via CleanUserPath above
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", clean, err)
	}

	var cfg StaveConfig
	// KnownFields(true): reject unknown keys outright. Operators
	// editing exceptions YAML routinely mistype keys (`controll_id`,
	// `expires`); silent unmarshal would accept the file and quietly
	// drop the misspelled exception, leaving the real production
	// finding ungated. Failing fast surfaces the typo at load time.
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
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
	// InvalidReasonNoCompensatingControls means the exception was
	// constructed without any compensating controls, which is a
	// "trust me" suppression — rejected so the finding stays
	// active. validateException already catches this at load time;
	// the constant covers callsites that bypass validation.
	InvalidReasonNoCompensatingControls InvalidReason = "no_compensating_controls"
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

// IsValid reports whether the exception successfully suppressed the
// finding (compensating controls all in place, not expired). Mirrors
// controldef.AcknowledgedFinding.IsValid so cmd/evaluate's filter
// loop reads through the same predicate name regardless of which
// acknowledged shape it holds.
func (a *AcknowledgedResult) IsValid() bool {
	return a != nil && a.Valid
}

// ToAcknowledgedEntry projects this AcknowledgedResult into the
// profile.AcknowledgedEntry shape the report consumes. Replaces
// the field-by-field copy block at cmd/evaluate/cmd.go so the
// projection lives on the type that owns the source fields.
//
// nil receiver returns the zero entry so a defensive caller can
// translate optional results without nil-guarding.
func (a *AcknowledgedResult) ToAcknowledgedEntry() profile.AcknowledgedEntry {
	if a == nil {
		return profile.AcknowledgedEntry{}
	}
	return profile.AcknowledgedEntry{
		ControlID:        a.ControlID,
		Bucket:           a.Bucket,
		Rationale:        a.Rationale,
		AcknowledgedBy:   a.AcknowledgedBy,
		AcknowledgedDate: a.AcknowledgedDate.String(),
		Valid:            a.Valid,
		InvalidReason:    string(a.InvalidReason),
		InvalidDetail:    a.InvalidDetail,
	}
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

	// Build result lookup. originallyPassing freezes the pre-exception
	// pass state so subsequent exceptions on the same control are not
	// silently skipped after the first one acknowledges the finding
	// via MarkExempt (which flips Result.Pass to true).
	resultMap := make(map[kernel.ControlID]*profile.Result)
	originallyPassing := make(map[kernel.ControlID]bool)
	for i := range results {
		resultMap[results[i].ControlID] = &results[i]
		originallyPassing[results[i].ControlID] = results[i].Pass
	}

	var acknowledged []AcknowledgedResult

	for _, exc := range exceptions {
		// Skip exceptions scoped to a different bucket.
		if exc.Bucket != "" && exc.Bucket != currentBucket {
			continue
		}

		r, exists := resultMap[exc.ControlID]
		if !exists {
			continue // control not evaluated in this run
		}
		if originallyPassing[exc.ControlID] {
			continue // control passed evaluation; nothing to acknowledge
		}

		// Check compensating controls. validateException already
		// rejects empty RequiresPassing at load time, but a callsite
		// that bypasses validation (tests constructing Config
		// literals, future code paths, etc.) must not silently
		// suppress findings without ANY compensating-control
		// assertion. An exception with no listed compensating
		// controls is functionally "trust me", which violates the
		// design contract — flag it invalid so the finding stays
		// active. Sets allPassing = false to surface the gap rather
		// than panicking, which would abort an entire evaluation.
		controls := make([]CompensatingControl, len(exc.RequiresPassing))
		allPassing := true
		if len(exc.RequiresPassing) == 0 {
			allPassing = false
		}
		for i, reqID := range exc.RequiresPassing {
			// Read from originallyPassing instead of req.Pass: an
			// earlier exception in this loop may have called
			// MarkExempt on a previously-failing compensating
			// control, flipping its Pass flag to true. Trusting the
			// mutated state would let exceptions prop each other up
			// — A's compensating control B passes only because B
			// was itself acknowledged. The snapshot keeps every
			// "compensating control passes" assertion grounded in
			// the original evaluation result.
			passing := originallyPassing[reqID]
			controls[i] = CompensatingControl{ControlID: reqID, Passing: passing}
			if !passing {
				allPassing = false
			}
		}

		// InvalidReason priority order (highest first):
		//   1. InvalidReasonExpired
		//   2. InvalidReasonNoCompensatingControls
		//   3. InvalidReasonCompensatingFailed
		//
		// When an exception trips multiple conditions (e.g. expired
		// AND empty RequiresPassing), only the highest-priority
		// reason is reported on AcknowledgedResult. Expiry wins
		// because the operator's promise to watch the
		// compensating-control state has aged out — re-acknowledging
		// with a fresh date is the prerequisite for any further
		// triage of the underlying compensating-control set. The
		// InvalidReason field is a single value, not a set; if a
		// future report needs to surface every applicable reason,
		// extend the type rather than concatenating into the detail
		// string (renderers parse the reason classifier verbatim).
		//
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
			r.MarkExempt(policy.SeverityLow)
		} else {
			// Exception invalid: keep FAIL, set a specific reason.
			// Two distinct cases produce !allPassing here:
			//   1. RequiresPassing is empty (validation bypass)
			//   2. one or more listed controls are failing
			// Distinguishing them lets reports show operators
			// exactly what to fix, and prevents the empty-list
			// case from displaying as "compensating controls
			// failing" (which suggests a different remediation).
			if len(exc.RequiresPassing) == 0 {
				ack.InvalidReason = InvalidReasonNoCompensatingControls
				ack.InvalidDetail = "exception declared no compensating controls; an empty RequiresPassing list is rejected"
				r.Finding = r.Finding + " [Exception declared without any compensating controls]"
			} else {
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
		}

		acknowledged = append(acknowledged, ack)
	}

	return acknowledged
}
