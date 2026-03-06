package snapshot

import (
	"time"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
)

const (
	severityError   = "error"
	severityWarning = "warning"
)

type qualityIssue struct {
	Code     string         `json:"code"`
	Severity string         `json:"severity"`
	Message  string         `json:"message"`
	Evidence map[string]any `json:"evidence,omitempty"`
}

type qualitySummary struct {
	Snapshots        int       `json:"snapshots"`
	OldestCapturedAt time.Time `json:"oldest_captured_at"`
	LatestCapturedAt time.Time `json:"latest_captured_at"`
	MaxGap           string    `json:"max_gap,omitempty"`
}

type qualityReport struct {
	SchemaVersion string         `json:"schema_version"`
	Kind          string         `json:"kind"`
	CheckedAt     time.Time      `json:"checked_at"`
	Pass          bool           `json:"pass"`
	Strict        bool           `json:"strict"`
	Summary       qualitySummary `json:"summary"`
	Issues        []qualityIssue `json:"issues"`
}

// qualityParams defines inputs for snapshot quality assessment.
type qualityParams struct {
	Snapshots         []asset.Snapshot
	Now               time.Time
	MinSnapshots      int
	MaxStaleness      time.Duration
	MaxGap            time.Duration
	RequiredResources []string
	Strict            bool
}

type qualityAssessor struct {
	params qualityParams
	report qualityReport
	sorted []asset.Snapshot
}

type qualityInput struct {
	observationsDir   string
	minSnapshots      int
	maxStaleness      time.Duration
	maxGap            time.Duration
	requiredAssets []string
	now               time.Time
	format            ui.OutputFormat
	strict            bool
}
