// Package telemetry maps Stave assessment output to structured NDJSON
// telemetry events consumable by log shippers, SIEM pipelines, and
// time series databases.
package telemetry

import "time"

// Event represents a single telemetry record for one finding.
// One JSON object per line in NDJSON output.
type Event struct {
	SchemaVersion      string    `json:"schema_version"`
	CapturedAt         time.Time `json:"captured_at"`
	ControlID          string    `json:"control_id"`
	ControlName        string    `json:"control_name"`
	Severity           string    `json:"severity"`
	ResourceID         string    `json:"resource_id"`
	ResourceType       string    `json:"resource_type"`
	Verdict            string    `json:"verdict"`
	FindingID          string    `json:"finding_id"`
	PolicyFingerprint  string    `json:"policy_fingerprint"`
	ControlFingerprint string    `json:"control_fingerprint,omitempty"`
	EnvironmentalScore *float64  `json:"environmental_score,omitempty"`
	ExposureScore      float64   `json:"exposure_score,omitempty"`
	CompoundChains     []string  `json:"compound_chains,omitempty"`
	AttackStage        string    `json:"attack_stage,omitempty"`
	Exploitability     string    `json:"exploitability,omitempty"`
	UnsafeDurationDays float64   `json:"unsafe_duration_days,omitempty"`
	WindowID           *string   `json:"window_id,omitempty"`
	Status             string    `json:"status"`
}

const schemaVersion = "telemetry.v2"
