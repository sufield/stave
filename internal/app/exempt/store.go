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
	return os.WriteFile(path, data, 0o644) //nolint:gosec // user-managed file
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
	ts, _ := time.Parse(time.RFC3339, timestamp)
	if !ts.IsZero() && expiry.Before(ts.Truncate(24*time.Hour)) {
		return fmt.Errorf("expiry_date %s is in the past", entry.ExpiryDate)
	}

	entry.ID = entry.ControlID + "@" + entry.AssetID
	entry.AcknowledgedDate = timestamp[:10] // YYYY-MM-DD from RFC3339
	entry.Status = "active"
	entry.AuditTrail = []AuditEvent{
		{
			Event:     "created",
			Timestamp: timestamp,
			Actor:     currentUser(),
			Note:      "Added via stave exempt acknowledge",
		},
	}

	// Replace existing entry with same ID.
	for i := range f.Acknowledgments {
		if f.Acknowledgments[i].ID == entry.ID {
			f.Acknowledgments[i] = entry
			return nil
		}
	}

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
			f.Acknowledgments[i].Status = "revoked"
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
		if a.Status != "active" || a.ExpiryDate == "" {
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
		if f.Acknowledgments[i].Status == "active" {
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
