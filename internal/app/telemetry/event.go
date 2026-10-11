// Package telemetry maps Stave assessment output to structured NDJSON
// telemetry events consumable by log shippers, SIEM pipelines, and
// time series databases.
package telemetry

import (
	"slices"
	"strings"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

// UnsafeDurationDays encapsulates elapsed unaddressed violation duration in fractional calendar days.
type UnsafeDurationDays float64

// Float64 returns the raw float64 value in days.
func (u UnsafeDurationDays) Float64() float64 {
	return float64(u)
}

// Duration converts days to time.Duration.
func (u UnsafeDurationDays) Duration() time.Duration {
	return time.Duration(float64(u) * float64(24*time.Hour))
}

// IsZero reports whether the duration is zero.
func (u UnsafeDurationDays) IsZero() bool {
	return u == 0
}

// WindowID represents an active or historical violation window identifier.
type WindowID string

// String returns the raw string value of the window ID.
func (wid WindowID) String() string {
	return string(wid)
}

// IsEmpty reports whether the window ID is empty.
func (wid WindowID) IsEmpty() bool {
	return strings.TrimSpace(string(wid)) == ""
}

// ClosedWindowIDs is a domain collection of closed window identifiers with query methods.
type ClosedWindowIDs []WindowID

// Len returns the count of closed window IDs.
func (c ClosedWindowIDs) Len() int {
	return len(c)
}

// Contains reports whether the target window ID is in the collection.
func (c ClosedWindowIDs) Contains(wid WindowID) bool {
	return slices.Contains(c, wid)
}

// Event represents a single telemetry record for one finding.
// One JSON object per line in NDJSON output.
type Event struct {
	SchemaVersion      string             `json:"schema_version"`
	CapturedAt         time.Time          `json:"captured_at"`
	ControlID          kernel.ControlID   `json:"control_id"`
	ControlName        string             `json:"control_name"`
	Severity           policy.Severity    `json:"severity"`
	ResourceID         asset.ID           `json:"resource_id"`
	ResourceType       kernel.AssetType   `json:"resource_type"`
	Verdict            evaluation.Verdict `json:"verdict"`
	FindingID          string             `json:"finding_id"`
	PolicyFingerprint  string             `json:"policy_fingerprint"`
	ControlFingerprint string             `json:"control_fingerprint,omitempty"`
	EnvironmentalScore *float64           `json:"environmental_score,omitempty"`
	ExposureScore      float64            `json:"exposure_score,omitempty"`
	CompoundChains     []kernel.ChainID   `json:"compound_chains,omitempty"`
	AttackStage        string             `json:"attack_stage,omitempty"`
	Exploitability     string             `json:"exploitability,omitempty"`
	UnsafeDurationDays UnsafeDurationDays `json:"unsafe_duration_days,omitempty"`
	WindowID           *WindowID          `json:"window_id,omitempty"`
	Status             string             `json:"status"`
}

const schemaVersion = "telemetry.v2"
