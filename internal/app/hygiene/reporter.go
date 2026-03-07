package hygiene

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
