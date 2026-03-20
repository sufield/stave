package contracts

import (
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
// Use NewSnapshotStats to ensure Total is consistent with Active + Archived.
type SnapshotStats struct {
	Active            int           `json:"active"`
	Archived          int           `json:"archived"`
	Total             int           `json:"total"`
	PruneCandidates   int           `json:"prune_candidates"`
	RetentionTier     string        `json:"retention_tier"`
	RetentionDuration time.Duration `json:"retention_duration"`
	KeepMin           int           `json:"keep_min"`
}

// NewSnapshotStats creates SnapshotStats with Total computed as Active + Archived.
func NewSnapshotStats(active, archived, pruneCandidates, keepMin int, tier string, retentionDuration time.Duration) SnapshotStats {
	return SnapshotStats{
		Active:            active,
		Archived:          archived,
		Total:             active + archived,
		PruneCandidates:   pruneCandidates,
		RetentionTier:     tier,
		RetentionDuration: retentionDuration,
		KeepMin:           keepMin,
	}
}

// RiskStats captures the current and upcoming risk surface.
// Use NewRiskStats to ensure UpcomingTotal is consistent with the urgency buckets.
type RiskStats struct {
	CurrentViolations int `json:"current_violations"`
	Overdue           int `json:"overdue"`
	DueNow            int `json:"due_now"`
	DueSoon           int `json:"due_soon"`
	Later             int `json:"later"`
	UpcomingTotal     int `json:"upcoming_total"`
}

// NewRiskStats creates RiskStats from current violations and a risk summary.
// UpcomingTotal is derived from the summary rather than set independently.
func NewRiskStats(violations int, summary risk.Summary) RiskStats {
	return RiskStats{
		CurrentViolations: violations,
		Overdue:           summary.Overdue,
		DueNow:            summary.DueNow,
		DueSoon:           summary.DueSoon,
		Later:             summary.Later,
		UpcomingTotal:     summary.Total,
	}
}
