// Package telemetry maps Stave assessment output to structured NDJSON
// telemetry events consumable by log shippers, SIEM pipelines, and
// time series databases.
package telemetry

import "time"

// Event represents a single telemetry record for one finding.
// One JSON object per line in NDJSON output.
type Event struct {
	SchemaVersion     string    `json:"schema_version"`
	CapturedAt        time.Time `json:"captured_at"`
	ControlID         string    `json:"control_id"`
	ControlName       string    `json:"control_name"`
	Severity          string    `json:"severity"`
	ResourceID        string    `json:"resource_id"`
	ResourceType      string    `json:"resource_type"`
	Verdict           string    `json:"verdict"`
	PolicyFingerprint string    `json:"policy_fingerprint"`
	Status            string    `json:"status"`
}

const schemaVersion = "telemetry.v1"
