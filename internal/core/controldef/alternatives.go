package controldef

// Alternative records a coverage relationship between this control and a
// check in an alternative detection tool. Tool is an opaque string; this
// package does not interpret or pattern-match on its value.
type Alternative struct {
	Tool     string
	CheckID  string
	Coverage CoverageStatus
	Note     string
}

// CoverageStatus expresses how completely a Stave control covers an
// alternative tool's check. Absence of any control with an entry for a
// given (tool, check_id) implies the check is not covered by Stave.
type CoverageStatus string

const (
	CoverageCovered CoverageStatus = "covered"
	CoveragePartial CoverageStatus = "partial"
)
