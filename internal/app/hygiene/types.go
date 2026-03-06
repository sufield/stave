package hygiene

import "time"

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

// Output is the structured representation of a hygiene report.
type Output struct {
	GeneratedAt      time.Time      `json:"generated_at"`
	LookbackStart    time.Time      `json:"lookback_start"`
	LookbackDuration string         `json:"lookback_duration"`
	DueSoonThreshold string         `json:"due_soon_threshold"`
	Filters          map[string]any `json:"filters,omitempty"`
	SnapshotStats    SnapshotStats  `json:"snapshot_stats"`
	RiskStats        RiskStats      `json:"risk_stats"`
	Trend            []TrendMetric  `json:"trend"`
}
