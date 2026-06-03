// Package exempt provides CRUD operations for risk acceptance files.
package exempt

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"time"

	"gopkg.in/yaml.v3"
)

// AcceptanceFile is the on-disk format for the managed risk acceptance file.
type AcceptanceFile struct {
	SchemaVersion   string                `yaml:"schema_version"`
	LastModified    string                `yaml:"last_modified"`
	LastModifiedBy  string                `yaml:"last_modified_by"`
	Acknowledgments []AcknowledgmentEntry `yaml:"acknowledgments,omitempty"`
	Exceptions      []ExceptionEntry      `yaml:"exceptions,omitempty"`
	Exemptions      []ExemptionEntry      `yaml:"exemptions,omitempty"`
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
	ID                   string       `yaml:"id"`
	ControlID            string       `yaml:"control_id"`
	AssetID              string       `yaml:"asset_id"`
	Reason               string       `yaml:"rationale"`
	Approver             string       `yaml:"acknowledged_by"`
	AcknowledgedDate     string       `yaml:"acknowledged_date"`
	ExpiryDate           string       `yaml:"expiry_date"`
	CompensatingControls []string     `yaml:"compensating_controls,omitempty"`
	Status               string       `yaml:"status"`
	AuditTrail           []AuditEvent `yaml:"audit_trail"`
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
	nowDay := now.UTC().Truncate(24 * time.Hour)
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
	ControlID  string `yaml:"control_id"`
	AssetID    string `yaml:"asset_id"`
	ExpiryDate string `yaml:"expiry_date,omitempty"`
	Reason     string `yaml:"reason"`
}

// ExemptionEntry is a scope exclusion.
type ExemptionEntry struct {
	AssetPattern string `yaml:"asset_pattern"`
	Reason       string `yaml:"reason"`
}

// AuditEvent records a change to an acceptance entry.
type AuditEvent struct {
	Event     string `yaml:"event"`
	Timestamp string `yaml:"timestamp"`
	Actor     string `yaml:"actor"`
	Note      string `yaml:"note,omitempty"`
}

// Load reads an acceptance file from disk. Returns empty file if not found.
func Load(path string) (*AcceptanceFile, error) {
	data, err := os.ReadFile(path) //nolint:gosec // user-specified path
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
	if err = os.WriteFile(path, data, 0o644); err != nil { //nolint:gosec // user-managed file
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
	if expiry.Before(ts.Truncate(24 * time.Hour)) {
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
func (f *AcceptanceFile) AddException(entry ExceptionEntry) error {
	if entry.ControlID == "" {
		return errors.New("control_id is required")
	}
	if entry.AssetID == "" {
		return errors.New("asset_id is required")
	}
	f.Exceptions = append(f.Exceptions, entry)
	return nil
}

// AddExemption adds a scope exclusion.
func (f *AcceptanceFile) AddExemption(entry ExemptionEntry) error {
	if entry.AssetPattern == "" {
		return errors.New("asset_pattern is required")
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
func (f *AcceptanceFile) ValidateWithCatalog(knownIDs map[string]bool) []string {
	errs := f.Validate()
	if len(knownIDs) == 0 {
		return errs
	}
	for i := range f.Acknowledgments {
		a := &f.Acknowledgments[i]
		for _, cc := range a.CompensatingControls {
			if !knownIDs[cc] {
				errs = append(errs, fmt.Sprintf("acknowledgment[%d]: compensating control %q not found in catalog", i, cc))
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
	}
	for i, e := range f.Exceptions {
		if e.ControlID == "" {
			errs = append(errs, fmt.Sprintf("exception[%d]: control_id required", i))
		}
		if e.AssetID == "" {
			errs = append(errs, fmt.Sprintf("exception[%d]: asset_id required", i))
		}
	}
	for i, e := range f.Exemptions {
		if e.AssetPattern == "" {
			errs = append(errs, fmt.Sprintf("exemption[%d]: asset_pattern required", i))
		}
	}
	return errs
}

// Upcoming returns acknowledgments expiring within the given number of days from now.
func (f *AcceptanceFile) Upcoming(days int, now time.Time) []AcknowledgmentEntry {
	cutoff := now.AddDate(0, 0, days)
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
		if expiry.Before(cutoff) {
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
