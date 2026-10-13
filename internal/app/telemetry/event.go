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

// ChainIDs is a domain collection of compound attack chain identifiers.
type ChainIDs []kernel.ChainID

// Len returns the number of chain IDs in the collection.
func (c ChainIDs) Len() int {
	return len(c)
}

// Contains reports whether the target chain ID is present in the collection.
func (c ChainIDs) Contains(id kernel.ChainID) bool {
	return slices.Contains(c, id)
}

// ExposureScore encapsulates the exposure score of a telemetry finding.
type ExposureScore float64

// Float64 returns the raw float64 exposure score value.
func (e ExposureScore) Float64() float64 { return float64(e) }

// IsZero reports whether the exposure score is zero.
func (e ExposureScore) IsZero() bool { return e == 0 }

// IsHigh reports whether the exposure score meets or exceeds the given threshold.
func (e ExposureScore) IsHigh(threshold float64) bool { return float64(e) >= threshold }

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
	ExposureScore      ExposureScore      `json:"exposure_score,omitempty"`
	CompoundChains     ChainIDs           `json:"compound_chains,omitempty"`
	AttackStage        string             `json:"attack_stage,omitempty"`
	Exploitability     string             `json:"exploitability,omitempty"`
	UnsafeDurationDays UnsafeDurationDays `json:"unsafe_duration_days,omitempty"`
	WindowID           *WindowID          `json:"window_id,omitempty"`
	Status             string             `json:"status"`
}

// Events is a domain collection of telemetry Event records with query and filtering methods.
type Events []Event

// Len returns the count of telemetry events.
func (ev Events) Len() int {
	return len(ev)
}

// ByControl returns a new Events collection filtered by control ID.
func (ev Events) ByControl(id kernel.ControlID) Events {
	if len(ev) == 0 {
		return nil
	}
	var filtered Events
	for i := range ev {
		if ev[i].ControlID == id {
			filtered = append(filtered, ev[i])
		}
	}
	return filtered
}

// BySeverity returns a new Events collection filtered by severity.
func (ev Events) BySeverity(sev policy.Severity) Events {
	if len(ev) == 0 {
		return nil
	}
	var filtered Events
	for i := range ev {
		if ev[i].Severity == sev {
			filtered = append(filtered, ev[i])
		}
	}
	return filtered
}

// ByResource returns a new Events collection filtered by resource ID.
func (ev Events) ByResource(id asset.ID) Events {
	if len(ev) == 0 {
		return nil
	}
	var filtered Events
	for i := range ev {
		if ev[i].ResourceID == id {
			filtered = append(filtered, ev[i])
		}
	}
	return filtered
}

// Violations returns a new Events collection containing only violation verdicts.
func (ev Events) Violations() Events {
	if len(ev) == 0 {
		return nil
	}
	var filtered Events
	for i := range ev {
		if ev[i].Verdict == evaluation.VerdictViolation {
			filtered = append(filtered, ev[i])
		}
	}
	return filtered
}

const schemaVersion = "telemetry.v2"
