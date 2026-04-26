package controldef

import (
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
}
