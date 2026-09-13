package evaluation

// FindingSummary provides read-only access to a finding's identity,
// severity, and classification state. Output adapters and reporting
// consumers depend on this interface; only the engine and enrichment
// passes use the concrete Finding struct.
type FindingSummary interface {
	SpanKey() string
	SeverityLabel() string
	HasSLA() bool
	IsOverdue() bool
	IsChainMember() bool
	HasReachability() bool
	HasSource() bool
	IsIndeterminate() bool
}

var _ FindingSummary = (*Finding)(nil)
