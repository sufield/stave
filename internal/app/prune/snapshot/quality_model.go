package snapshot

import (
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"
)

// qualitySeverity classifies the severity of a snapshot quality issue.
type qualitySeverity string

const (
	severityError   qualitySeverity = "error"
	severityWarning qualitySeverity = "warning"
)

type qualityIssue struct {
	Code     string          `json:"code"`
	Severity qualitySeverity `json:"severity"`
	Message  string          `json:"message"`
	Evidence map[string]any  `json:"evidence,omitempty"`
}

type qualitySummary struct {
	Snapshots        int       `json:"snapshots"`
	OldestCapturedAt time.Time `json:"oldest_captured_at"`
	LatestCapturedAt time.Time `json:"latest_captured_at"`
	MaxGap           string    `json:"max_gap,omitempty"`
}

type qualityReport struct {
	SchemaVersion kernel.Schema     `json:"schema_version"`
	Kind          kernel.OutputKind `json:"kind"`
	CheckedAt     time.Time         `json:"checked_at"`
	Pass          bool              `json:"pass"`
	Strict        bool              `json:"strict"`
	Summary       qualitySummary    `json:"summary"`
	Issues        []qualityIssue    `json:"issues"`
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
