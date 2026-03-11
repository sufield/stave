package contracts

import "time"

// ReportRequest bundles all data required to generate a hygiene report.
type ReportRequest struct {
	Context   ReportContext
	Snapshots SnapshotStats
	Risks     RiskStats
	Trends    []TrendMetric
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
	Total             int           `json:"total"`
	PruneCandidates   int           `json:"prune_candidates"`
	RetentionTier     string        `json:"retention_tier"`
	RetentionDuration time.Duration `json:"retention_duration"`
	KeepMin           int           `json:"keep_min"`
}

// RiskStats captures the current and upcoming risk surface.
type RiskStats struct {
	CurrentViolations int `json:"current_violations"`
	Overdue           int `json:"overdue"`
	DueNow            int `json:"due_now"`
	DueSoon           int `json:"due_soon"`
	Later             int `json:"later"`
	UpcomingTotal     int `json:"upcoming_total"`
}

// TrendMetric compares current vs previous values for a metric.
type TrendMetric struct {
	Name     string `json:"name"`
	Current  int    `json:"current"`
	Previous int    `json:"previous"`
}
