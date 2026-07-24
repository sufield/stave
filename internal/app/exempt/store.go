// Package exempt provides CRUD operations for risk acceptance files.
package exempt

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"time"

	"github.com/sufield/stave/internal/platform/fsutil"
	"gopkg.in/yaml.v3"
)

// AcceptanceFile is the on-disk format for the managed risk acceptance file.
type AcceptanceFile struct {
	SchemaVersion   string                `yaml:"schema_version" json:"schema_version"`
	LastModified    string                `yaml:"last_modified" json:"last_modified"`
	LastModifiedBy  string                `yaml:"last_modified_by" json:"last_modified_by"`
	Acknowledgments []AcknowledgmentEntry `yaml:"acknowledgments,omitempty" json:"acknowledgments,omitempty"`
	Exceptions      []ExceptionEntry      `yaml:"exceptions,omitempty" json:"exceptions,omitempty"`
	Exemptions      []ExemptionEntry      `yaml:"exemptions,omitempty" json:"exemptions,omitempty"`
}

// Acknowledgment status string literals. Centralised so the status
// predicate methods and the writer-side constructors (Add / Remove /
// Expire) can all reference the same canonical strings instead of
// open-coding "active" / "revoked" / "expired" at every site.
const (
	AckStatusActive  = "active"
	AckStatusRevoked = "revoked"
	AckStatusExpired = "expired"
)

// AcknowledgmentEntry is a formal risk acceptance.
// YAML tags match controldef.AcknowledgmentRule so the produced file
// is consumable by stave apply --acknowledgment-file without modification.
type AcknowledgmentEntry struct {
	ID                   string       `yaml:"id" json:"id"`
	ControlID            string       `yaml:"control_id" json:"control_id"`
	AssetID              string       `yaml:"asset_id" json:"asset_id"`
	Reason               string       `yaml:"rationale" json:"rationale"`
	Approver             string       `yaml:"acknowledged_by" json:"acknowledged_by"`
	AcknowledgedDate     string       `yaml:"acknowledged_date" json:"acknowledged_date"`
	ExpiryDate           string       `yaml:"expiry_date" json:"expiry_date"`
	ReviewBy             string       `yaml:"review_by,omitempty" json:"review_by,omitempty"`
	ReviewCadence        string       `yaml:"review_cadence,omitempty" json:"review_cadence,omitempty"`
	CompensatingControls []string     `yaml:"compensating_controls,omitempty" json:"compensating_controls,omitempty"`
	Status               string       `yaml:"status" json:"status"`
	AuditTrail           []AuditEvent `yaml:"audit_trail" json:"audit_trail"`
}

// IsActive reports whether the entry's status is the canonical
// "active" value.
func (a *AcknowledgmentEntry) IsActive() bool { return a.Status == AckStatusActive }

// IsRevoked reports whether the entry has been administratively
// revoked.
func (a *AcknowledgmentEntry) IsRevoked() bool { return a.Status == AckStatusRevoked }

// IsExpired reports whether the entry has passed its expiry date and
// been moved to the "expired" status.
func (a *AcknowledgmentEntry) IsExpired() bool { return a.Status == AckStatusExpired }

// IsInactive reports whether the entry is no longer in force —
// either revoked or expired. Replaces the (IsRevoked() || IsExpired())
// disjunction in the formatter so callers stop joining the two
// status questions at every site.
func (a *AcknowledgmentEntry) IsInactive() bool {
	return a != nil && (a.IsRevoked() || a.IsExpired())
}

// DaysRemaining parses the entry's ExpiryDate (YYYY-MM-DD) and
// returns the number of whole days from now until expiry. Negative
// values indicate the entry has already lapsed. Returns (0, false)
// when the date string is missing or unparseable so callers can
// distinguish "no expiry data" from "0 days left".
//
// Replaces the inline time.Parse + Hours()/24 arithmetic in
// internal/app/exempt/status.go's ComputeStatus loop.
func (a *AcknowledgmentEntry) DaysRemaining(now time.Time) (int, bool) {
	if a == nil || a.ExpiryDate == "" {
		return 0, false
	}
	expiry, err := time.Parse("2006-01-02", a.ExpiryDate)
	if err != nil {
		return 0, false
	}
	// Calendar-day arithmetic: truncate both endpoints to midnight UTC
	// before subtracting so the result counts whole days, not 24-hour
	// windows. Without truncation, an entry whose ExpiryDate already
	// passed earlier today (e.g. expiry 00:00 UTC, now 18:00 UTC) lands
	// at -0.75 → int = 0 → "expiring_soon" instead of the correct
	// "expired" — `int()` truncates toward zero for negative floats.
	expiryDay := expiry.Truncate(24 * time.Hour)
	nowDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	return int(expiryDay.Sub(nowDay).Hours() / 24), true
}

// ExpiryClassification labels the entry's lifetime against the
// expiry-status thresholds the exempt status report uses:
//   - "expired"        — DaysRemaining < 0
//   - "expiring_soon"  — 0 ≤ DaysRemaining ≤ 30
//   - "expiring_60d"   — 30 < DaysRemaining ≤ 60
//   - "active"         — DaysRemaining > 60
//   - ""               — ExpiryDate missing / unparseable
//
// Replaces the cascade of inline arithmetic in ComputeStatus. The
// 60-day bucket lets the report distinguish near-term renewals (the
// exempt-renewal cohort) from healthy long-lived entries without
// the caller post-processing on a separate `<=60` branch.
func (a *AcknowledgmentEntry) ExpiryClassification(now time.Time) string {
	days, ok := a.DaysRemaining(now)
	if !ok {
		return ""
	}
	switch {
	case days < 0:
		return "expired"
	case days <= 30:
		return "expiring_soon"
	case days <= 60:
		return "expiring_60d"
	default:
		return "active"
	}
}

// IsExportable reports whether the acknowledgment should appear in
// POA&M / external compliance exports. Active and expired entries
// both export — active becomes an "accepted" risk, expired becomes
// an "open" risk so the auditor can see that the prior acceptance
// has lapsed. Revoked entries never export.
func (a *AcknowledgmentEntry) IsExportable() bool {
	return a != nil && (a.IsActive() || a.IsExpired())
}

// ExportStatus returns the POA&M-side risk status string for an
// exportable acknowledgment: "accepted" for active entries,
// "open" for expired entries (the prior acceptance has lapsed and
// the risk is back on the queue), and "" for non-exportable
// entries. Mirrors the if-active/else-if-expired branch the
// exempt export was open-coding.
func (a *AcknowledgmentEntry) ExportStatus() string {
	switch {
	case a == nil:
		return ""
	case a.IsActive():
		return "accepted"
	case a.IsExpired():
		return "open"
	default:
		return ""
	}
}

// ExceptionEntry is an operational suppression.
type ExceptionEntry struct {
	ControlID  string `yaml:"control_id" json:"control_id"`
	AssetID    string `yaml:"asset_id" json:"asset_id"`
	ExpiryDate string `yaml:"expiry_date,omitempty" json:"expiry_date,omitempty"`
	Reason     string `yaml:"reason" json:"reason"`
}

// ExemptionEntry is a scope exclusion.
type ExemptionEntry struct {
	AssetPattern string `yaml:"asset_pattern" json:"asset_pattern"`
	Reason       string `yaml:"reason" json:"reason"`
}

// AuditEvent records a change to an acceptance entry.
type AuditEvent struct {
	Event     string `yaml:"event" json:"event"`
	Timestamp string `yaml:"timestamp" json:"timestamp"`
	Actor     string `yaml:"actor" json:"actor"`
	Note      string `yaml:"note,omitempty" json:"note,omitempty"`
}

// Load reads an acceptance file from disk. Returns empty file if not found.
func Load(path string) (*AcceptanceFile, error) {
	data, err := fsutil.ReadFileLimited(path)
	if os.IsNotExist(err) {
		return &AcceptanceFile{SchemaVersion: "1"}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var f AcceptanceFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if f.SchemaVersion == "" {
		f.SchemaVersion = "1"
	}
	return &f, nil
}

// Save writes the acceptance file to disk. Caller sets LastModified.
func Save(path string, f *AcceptanceFile, modifiedBy, timestamp string) error {
	f.LastModified = timestamp
	f.LastModifiedBy = modifiedBy
	data, err := yaml.Marshal(f)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if err = fsutil.SafeWriteFile(path, data, fsutil.ConfigWriteOpts()); err != nil {
		return fmt.Errorf("write acceptance file: %w", err)
	}
	return nil
}

// AddAcknowledgment adds a formal risk acceptance. timestamp is RFC3339.
func (f *AcceptanceFile) AddAcknowledgment(entry AcknowledgmentEntry, timestamp string) error {
	if entry.ControlID == "" {
		return errors.New("control_id is required")
	}
	if entry.AssetID == "" {
		return errors.New("asset_id is required")
	}
	if entry.Reason == "" {
		return errors.New("reason is required for acknowledgments")
	}
	if entry.Approver == "" {
		return errors.New("approver is required for acknowledgments")
	}
	if entry.ExpiryDate == "" {
		return errors.New("expiry_date is required for acknowledgments")
	}
	expiry, err := time.Parse("2006-01-02", entry.ExpiryDate)
	if err != nil {
		return fmt.Errorf("invalid expiry_date %q: expected YYYY-MM-DD", entry.ExpiryDate)
	}
	ts, tsErr := time.Parse(time.RFC3339, timestamp)
	if tsErr != nil {
		return fmt.Errorf("cannot validate expiry: invalid timestamp %q: %w", timestamp, tsErr)
	}
	tsDate := time.Date(ts.Year(), ts.Month(), ts.Day(), 0, 0, 0, 0, time.UTC)
	if expiry.Before(tsDate) {
		return fmt.Errorf("expiry_date %s is in the past", entry.ExpiryDate)
	}

	entry.ID = entry.ControlID + "@" + entry.AssetID
	// time.Parse(RFC3339, ...) above already rejected anything shorter
	// than the 20-char minimum (`YYYY-MM-DDTHH:MM:SSZ`), so the first
	// 10 chars are guaranteed to be the date.
	entry.AcknowledgedDate = timestamp[:10] // YYYY-MM-DD from RFC3339
	entry.Status = AckStatusActive
	createdEvent := AuditEvent{
		Event:     "created",
		Timestamp: timestamp,
		Actor:     currentUser(),
		Note:      "Added via stave exempt acknowledge",
	}

	// Update existing entry with the same ID. Preserve the prior
	// AuditTrail (the original "created" event, any intermediate
	// "revoked" events) and append an "updated" entry pointing at
	// this merge — overwriting the trail wholesale would erase the
	// acceptance history that audits rely on.
	for i := range f.Acknowledgments {
		if f.Acknowledgments[i].ID != entry.ID {
			continue
		}
		updatedEvent := AuditEvent{
			Event:     "updated",
			Timestamp: timestamp,
			Actor:     currentUser(),
			Note:      "Re-acknowledged via stave exempt acknowledge",
		}
		// Build the merged trail in a fresh slice so the append
		// result lands on entry.AuditTrail (gocritic appendAssign)
		// — appending to f.Acknowledgments[i].AuditTrail directly
		// would alias whichever backing array YAML unmarshal
		// happened to allocate.
		merged := make([]AuditEvent, 0, len(f.Acknowledgments[i].AuditTrail)+1)
		merged = append(merged, f.Acknowledgments[i].AuditTrail...)
		merged = append(merged, updatedEvent)
		entry.AuditTrail = merged
		f.Acknowledgments[i] = entry
		return nil
	}

	// Fresh entry: seed the trail with the "created" event.
	entry.AuditTrail = []AuditEvent{createdEvent}
	f.Acknowledgments = append(f.Acknowledgments, entry)
	return nil
}

// AddException adds an operational suppression.
func (f *AcceptanceFile) AddException(entry ExceptionEntry, timestamp string) error {
	if entry.ControlID == "" {
		return errors.New("control_id is required")
	}
	if entry.AssetID == "" {
		return errors.New("asset_id is required")
	}
	if entry.ExpiryDate != "" {
		expiry, err := time.Parse("2006-01-02", entry.ExpiryDate)
		if err != nil {
			return fmt.Errorf("invalid expiry_date %q: expected YYYY-MM-DD", entry.ExpiryDate)
		}
		ts, tsErr := time.Parse(time.RFC3339, timestamp)
		if tsErr != nil {
			return fmt.Errorf("cannot validate expiry: invalid timestamp %q: %w", timestamp, tsErr)
		}
		tsDate := time.Date(ts.Year(), ts.Month(), ts.Day(), 0, 0, 0, 0, time.UTC)
		if expiry.Before(tsDate) {
			return fmt.Errorf("expiry_date %s is in the past", entry.ExpiryDate)
		}
	}

	for i := range f.Exceptions {
		if f.Exceptions[i].ControlID == entry.ControlID && f.Exceptions[i].AssetID == entry.AssetID {
			f.Exceptions[i].ExpiryDate = entry.ExpiryDate
			f.Exceptions[i].Reason = entry.Reason
			return nil
		}
	}

	f.Exceptions = append(f.Exceptions, entry)
	return nil
}

// AddExemption adds a scope exclusion.
func (f *AcceptanceFile) AddExemption(entry ExemptionEntry) error {
	if entry.AssetPattern == "" {
		return errors.New("asset_pattern is required")
	}
	for i := range f.Exemptions {
		if f.Exemptions[i].AssetPattern == entry.AssetPattern {
			f.Exemptions[i].Reason = entry.Reason
			return nil
		}
	}
	f.Exemptions = append(f.Exemptions, entry)
	return nil
}

// Remove marks an acknowledgment as revoked by ID. timestamp is RFC3339.
func (f *AcceptanceFile) Remove(id, timestamp string) error {
	for i := range f.Acknowledgments {
		if f.Acknowledgments[i].ID == id {
			f.Acknowledgments[i].Status = AckStatusRevoked
			f.Acknowledgments[i].AuditTrail = append(f.Acknowledgments[i].AuditTrail, AuditEvent{
				Event:     "revoked",
				Timestamp: timestamp,
				Actor:     currentUser(),
				Note:      "Revoked via stave exempt remove",
			})
			return nil
		}
	}
	return fmt.Errorf("acknowledgment %q not found", id)
}

// ValidateWithCatalog checks all entries including compensating control IDs
// against the provided set of known control IDs.
func (f *AcceptanceFile) ValidateWithCatalog(knownIDs map[string]struct{}) []string {
	errs := f.Validate()
	if len(knownIDs) == 0 {
		return errs
	}
	for i := range f.Acknowledgments {
		a := &f.Acknowledgments[i]
		if a.ControlID != "" {
			if _, ok := knownIDs[a.ControlID]; !ok {
				errs = append(errs, fmt.Sprintf("acknowledgment[%d]: control %q not found in catalog", i, a.ControlID))
			}
		}
		for _, cc := range a.CompensatingControls {
			if _, ok := knownIDs[cc]; !ok {
				errs = append(errs, fmt.Sprintf("acknowledgment[%d]: compensating control %q not found in catalog", i, cc))
			}
		}
	}
	for i := range f.Exceptions {
		e := &f.Exceptions[i]
		if e.ControlID != "" {
			if _, ok := knownIDs[e.ControlID]; !ok {
				errs = append(errs, fmt.Sprintf("exception[%d]: control %q not found in catalog", i, e.ControlID))
			}
		}
	}
	return errs
}

// Validate checks all entries for required fields and valid dates.
func (f *AcceptanceFile) Validate() []string {
	var errs []string
	for i := range f.Acknowledgments {
		a := &f.Acknowledgments[i]
		if a.ControlID == "" {
			errs = append(errs, fmt.Sprintf("acknowledgment[%d]: control_id required", i))
		}
		if a.AssetID == "" {
			errs = append(errs, fmt.Sprintf("acknowledgment[%d]: asset_id required", i))
		}
		if a.Reason == "" {
			errs = append(errs, fmt.Sprintf("acknowledgment[%d]: reason required", i))
		}
		if a.Approver == "" {
			errs = append(errs, fmt.Sprintf("acknowledgment[%d]: approver required", i))
		}
		if a.ExpiryDate != "" {
			if _, err := time.Parse("2006-01-02", a.ExpiryDate); err != nil {
				errs = append(errs, fmt.Sprintf("acknowledgment[%d]: invalid expiry_date %q", i, a.ExpiryDate))
			}
		}
		if a.ReviewBy != "" {
			if _, err := time.Parse("2006-01-02", a.ReviewBy); err != nil {
				errs = append(errs, fmt.Sprintf("acknowledgment[%d]: invalid review_by %q", i, a.ReviewBy))
			}
		}
	}
	for i, e := range f.Exceptions {
		if e.ControlID == "" {
			errs = append(errs, fmt.Sprintf("exception[%d]: control_id required", i))
		}
		if e.AssetID == "" {
			errs = append(errs, fmt.Sprintf("exception[%d]: asset_id required", i))
		}
		if e.ExpiryDate != "" {
			if _, err := time.Parse("2006-01-02", e.ExpiryDate); err != nil {
				errs = append(errs, fmt.Sprintf("exception[%d]: invalid expiry_date %q", i, e.ExpiryDate))
			}
		}
	}
	for i, e := range f.Exemptions {
		if e.AssetPattern == "" {
			errs = append(errs, fmt.Sprintf("exemption[%d]: asset_pattern required", i))
		}
	}
	return errs
}

// OverdueReviews returns warnings for active acknowledgments whose review_by
// date has passed.
func (f *AcceptanceFile) OverdueReviews(now time.Time) []string {
	var warnings []string
	for i := range f.Acknowledgments {
		a := &f.Acknowledgments[i]
		if a.ReviewBy == "" || !a.IsActive() {
			continue
		}
		reviewDate, err := time.Parse("2006-01-02", a.ReviewBy)
		if err != nil {
			continue
		}
		if reviewDate.Before(now) {
			warnings = append(warnings, fmt.Sprintf("acknowledgment[%d]: overdue for review (was due %s)", i, a.ReviewBy))
		}
	}
	return warnings
}

// Upcoming returns acknowledgments expiring within the given number of days from now.
func (f *AcceptanceFile) Upcoming(days int, now time.Time) []AcknowledgmentEntry {
	nowDate := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	cutoffDate := nowDate.AddDate(0, 0, days)
	var result []AcknowledgmentEntry
	for i := range f.Acknowledgments {
		a := &f.Acknowledgments[i]
		if !a.IsActive() || a.ExpiryDate == "" {
			continue
		}
		expiry, err := time.Parse("2006-01-02", a.ExpiryDate)
		if err != nil {
			continue
		}
		// Only entries expiring in the future (after now) but before the
		// cutoff are "upcoming". An entry whose expiry is already in the
		// past is expired, not upcoming, so it must be excluded by the
		// lower bound — without it, a long-lapsed acceptance still
		// satisfies expiry < cutoff and is wrongly returned.
		if !expiry.Before(nowDate) && expiry.Before(cutoffDate) {
			result = append(result, *a)
		}
	}
	return result
}

// ActiveCount returns counts by type (only active entries).
func (f *AcceptanceFile) ActiveCount() (acks, exceptions, exemptions int) {
	for i := range f.Acknowledgments {
		if f.Acknowledgments[i].IsActive() {
			acks++
		}
	}
	return acks, len(f.Exceptions), len(f.Exemptions)
}

// History returns all acknowledgments including their full audit trails,
// regardless of status. This is the complete audit record.
func (f *AcceptanceFile) History() []AcknowledgmentEntry {
	result := make([]AcknowledgmentEntry, len(f.Acknowledgments))
	copy(result, f.Acknowledgments)
	return result
}

func currentUser() string {
	u, err := user.Current()
	if err != nil {
		return "unknown"
	}
	return u.Username
}
