// Package telemetry maps Stave assessment output to structured NDJSON
// telemetry events consumable by log shippers, SIEM pipelines, and
// time series databases.
package telemetry

import (
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

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
	UnsafeDurationDays float64            `json:"unsafe_duration_days,omitempty"`
	WindowID           *string            `json:"window_id,omitempty"`
	Status             string             `json:"status"`
}

const schemaVersion = "telemetry.v2"
