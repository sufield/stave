package contracts

import (
	"encoding/json"
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/risk"
)

// ReportRequest bundles all data required to generate a hygiene report.
type ReportRequest struct {
	Context   ReportContext
	Snapshots SnapshotStats
	Risks     RiskStats
	Trends    []evaluation.TrendMetric
}

// ReportContext provides the temporal metadata for the report.
type ReportContext struct {
	Now         time.Time
	PreviousNow time.Time
	Lookback    time.Duration
	DueSoon     time.Duration
}

// SnapshotStats summarizes snapshot inventory and retention posture.
type SnapshotStats struct {
	Active            int           `json:"active"`
	Archived          int           `json:"archived"`
	PruneCandidates   int           `json:"prune_candidates"`
	RetentionTier     string        `json:"retention_tier"`
	RetentionDuration time.Duration `json:"retention_duration"`
	KeepMin           int           `json:"keep_min"`
}

// Total returns Active + Archived.
func (s SnapshotStats) Total() int { return s.Active + s.Archived }

// MarshalJSON includes the computed Total field in JSON output.
func (s SnapshotStats) MarshalJSON() ([]byte, error) {
	type raw SnapshotStats
	return json.Marshal(struct {
		raw
		Total int `json:"total"`
	}{raw: raw(s), Total: s.Total()})
}

// RiskStats captures the current and upcoming risk surface.
type RiskStats struct {
	CurrentViolations int `json:"current_violations"`
	Overdue           int `json:"overdue"`
	DueNow            int `json:"due_now"`
	DueSoon           int `json:"due_soon"`
	Later             int `json:"later"`
}

// UpcomingTotal returns the sum of all urgency buckets.
func (s RiskStats) UpcomingTotal() int { return s.Overdue + s.DueNow + s.DueSoon + s.Later }

// MarshalJSON includes the computed UpcomingTotal field in JSON output.
func (s RiskStats) MarshalJSON() ([]byte, error) {
	type raw RiskStats
	return json.Marshal(struct {
		raw
		UpcomingTotal int `json:"upcoming_total"`
	}{raw: raw(s), UpcomingTotal: s.UpcomingTotal()})
}

// NewRiskStats creates RiskStats from current violations and a risk summary.
func NewRiskStats(violations int, summary risk.Summary) RiskStats {
	return RiskStats{
		CurrentViolations: violations,
		Overdue:           summary.Overdue,
		DueNow:            summary.DueNow,
		DueSoon:           summary.DueSoon,
		Later:             summary.Later,
	}
}
