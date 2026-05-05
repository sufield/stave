package controldef

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

// AcknowledgmentRule is a single accepted-risk acknowledgment.
type AcknowledgmentRule struct {
	ControlID            kernel.ControlID   `json:"control_id" yaml:"control_id"`
	AssetID              asset.ID           `json:"asset_id" yaml:"asset_id"`
	Rationale            string             `json:"rationale" yaml:"rationale"`
	AcknowledgedBy       string             `json:"acknowledged_by" yaml:"acknowledged_by"`
	AcknowledgedDate     string             `json:"acknowledged_date" yaml:"acknowledged_date"`
	ExpiryDate           string             `json:"expiry_date,omitempty" yaml:"expiry_date,omitempty"`
	CompensatingControls []kernel.ControlID `json:"compensating_controls,omitempty" yaml:"compensating_controls,omitempty"`
}

// AcknowledgmentConfig holds the set of acknowledgment rules.
type AcknowledgmentConfig struct {
	rules []AcknowledgmentRule
	index map[kernel.ControlID][]*AcknowledgmentRule
	once  sync.Once
}

// NewAcknowledgmentConfig creates a config from a slice of rules.
func NewAcknowledgmentConfig(rules []AcknowledgmentRule) *AcknowledgmentConfig {
	if len(rules) == 0 {
		return nil
	}
	return &AcknowledgmentConfig{rules: rules}
}

func (c *AcknowledgmentConfig) prepare() {
	c.index = make(map[kernel.ControlID][]*AcknowledgmentRule, len(c.rules))
	for i := range c.rules {
		r := &c.rules[i]
		c.index[r.ControlID] = append(c.index[r.ControlID], r)
	}
}

// FindRule returns the matching acknowledgment rule for a (control, asset) pair,
// or nil if none matches.
func (c *AcknowledgmentConfig) FindRule(controlID kernel.ControlID, assetID asset.ID) *AcknowledgmentRule {
	if c == nil || len(c.rules) == 0 {
		return nil
	}
	c.once.Do(c.prepare)
	var wildcard *AcknowledgmentRule
	for _, r := range c.index[controlID] {
		if r.AssetID == assetID {
			return r
		}
		if wildcard == nil && string(r.AssetID) == "*" {
			wildcard = r
		}
	}
	return wildcard
}

// IsExpired returns true if the rule has an expiry date that has passed.
func (r *AcknowledgmentRule) IsExpired(now time.Time) bool {
	if r.ExpiryDate == "" {
		return false // no expiry = permanent
	}
	expiry, err := time.Parse("2006-01-02", r.ExpiryDate)
	if err != nil {
		return false // unparseable = permanent
	}
	expiryBoundary := expiry.AddDate(0, 0, 1)
	return !now.Before(expiryBoundary)
}

// CompensatingControlStatus reports whether a compensating control is passing.
type CompensatingControlStatus struct {
	ControlID kernel.ControlID `json:"control_id"`
	Status    string           `json:"status"` // "pass" or "fail"
}

// AcknowledgedFinding is the output record for an acknowledged finding.
type AcknowledgedFinding struct {
	FindingID            string                      `json:"finding_id"`
	ControlID            kernel.ControlID            `json:"control_id"`
	AssetID              asset.ID                    `json:"asset_id"`
	Severity             Severity                    `json:"severity,omitempty"`
	Verdict              string                      `json:"verdict"`
	Rationale            string                      `json:"rationale"`
	AcknowledgedBy       string                      `json:"acknowledged_by"`
	AcknowledgedDate     string                      `json:"acknowledged_date"`
	ExpiryDate           string                      `json:"expiry_date,omitempty"`
	CompensatingControls []CompensatingControlStatus `json:"compensating_controls,omitempty"`
	Valid                bool                        `json:"valid"`
	InvalidReason        string                      `json:"invalid_reason,omitempty"`
	InvalidDetail        string                      `json:"invalid_detail,omitempty"`
}

// StatusLabel returns the bracketed status string used by rank /
// inspect output: "[ACK]" when the acknowledgment is valid, or
// "[INVALID: <reason>]" when it has been rejected.
func (a *AcknowledgedFinding) StatusLabel() string {
	if a.Valid {
		return "[ACK]"
	}
	return "[INVALID: " + a.ReasonDetail() + "]"
}

// IsValid reports whether the acknowledgment is currently in force.
// Replaces direct (af.Valid) reads at the suppression-set
// construction site so callers branch through the named predicate
// (recvcheck-friendly: pointer receiver matches the mutating Mark*
// methods below).
func (a *AcknowledgedFinding) IsValid() bool {
	return a != nil && a.Valid
}

// HasRationale reports whether the acknowledgment carries a
// non-empty rationale string. Replaces (af.Rationale != "") probes
// in cmd/rank's inspect renderer so the field check stays on the
// type that owns Rationale.
func (a *AcknowledgedFinding) HasRationale() bool {
	return a != nil && a.Rationale != ""
}

// HasAcknowledger reports whether the acknowledgment records the
// approver's identity. Sibling of HasRationale.
func (a *AcknowledgedFinding) HasAcknowledger() bool {
	return a != nil && a.AcknowledgedBy != ""
}

// HasExpiry reports whether the acknowledgment carries an explicit
// expiry date. Sibling of HasRationale and HasAcknowledger.
func (a *AcknowledgedFinding) HasExpiry() bool {
	return a != nil && a.ExpiryDate != ""
}

// Verdict vocabulary for AcknowledgedFinding state transitions.
// Centralised here so producers (the assessor's apply pass) and
// consumers cannot drift on the literal strings.
const (
	verdictAcknowledged = "acknowledged"
	verdictFail         = "fail"

	invalidReasonExpired                  = "expired"
	invalidReasonCompensatingControlsFail = "compensating_controls_failing"
)

// MarkExpired records that the acknowledgment has lapsed past its
// expiry date: Verdict reverts to fail, Valid is cleared, and the
// reason carries the "expired" tag for downstream operator
// messaging. Replaces the three-field assignment block in the
// assessor's apply pass.
func (a *AcknowledgedFinding) MarkExpired() {
	if a == nil {
		return
	}
	a.Verdict = verdictFail
	a.Valid = false
	a.InvalidReason = invalidReasonExpired
}

// MarkCompensatingFailed records that one or more compensating
// controls listed by the acknowledgment rule are failing on this
// asset: the acknowledgment cannot stand. Sibling of MarkExpired.
func (a *AcknowledgedFinding) MarkCompensatingFailed() {
	if a == nil {
		return
	}
	a.Verdict = verdictFail
	a.Valid = false
	a.InvalidReason = invalidReasonCompensatingControlsFail
}

// MarkValid records a successful acknowledgment: Verdict transitions
// to "acknowledged" and Valid is set. Counterpart to MarkExpired and
// MarkCompensatingFailed for the success branch in the assessor's
// apply pass.
func (a *AcknowledgedFinding) MarkValid() {
	if a == nil {
		return
	}
	a.Verdict = verdictAcknowledged
	a.Valid = true
}

// ReasonDetail returns the most-specific available reason text for an
// invalid acknowledgment: InvalidDetail when populated (carries the
// human-readable explanation), otherwise the shorter InvalidReason
// classifier. Empty string when the finding is valid or no reason
// was recorded.
func (a *AcknowledgedFinding) ReasonDetail() string {
	if a.InvalidDetail != "" {
		return a.InvalidDetail
	}
	return a.InvalidReason
}

// WriteDetails writes the rationale / acknowledger / expiry block
// the rank inspect renderer surfaces under each acknowledged
// finding. Each subline is conditional: missing fields are
// skipped silently rather than rendered as blank rows. Replaces
// the per-field HasRationale / HasAcknowledger / HasExpiry probe
// chain at the renderer site so the rendering policy stays on
// the type that owns the fields.
//
// Returns no error by design: callers feed this into
// human-facing terminal renderers where a partial-flush failure
// (broken pipe to a paged less, closed terminal) is recovered by
// the surrounding command-loop frame and surfacing it through
// every WriteDetails call site would force every renderer to
// thread an error channel that ultimately gets logged once at
// the boundary anyway. Structured / contract-bearing output
// uses the marshaler paths in adapters/, which DO return errors.
func (a *AcknowledgedFinding) WriteDetails(w io.Writer) {
	if a == nil {
		return
	}
	if a.HasRationale() {
		fmt.Fprintf(w, "         Rationale: %s\n", a.Rationale)
	}
	if a.HasAcknowledger() {
		fmt.Fprintf(w, "         By: %s on %s\n", a.AcknowledgedBy, a.AcknowledgedDate)
	}
	if a.HasExpiry() {
		fmt.Fprintf(w, "         Expires: %s\n", a.ExpiryDate)
	}
}
