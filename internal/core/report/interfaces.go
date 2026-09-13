package report

// ReportReader provides read-only access to an assessment's summary
// data. The 20+ packages that read report summaries without
// constructing them depend on this interface.
type ReportReader interface {
	HasFindings() bool
	HasTimestamp() bool
	SnapshotID() string
	CountBySeverity() SeverityCounts
}

var _ ReportReader = (*Assessment)(nil)
