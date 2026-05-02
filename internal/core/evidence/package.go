package evidence

import "time"

// EvidencePackage is the complete collection of evidence records from a
// single assessment run. It aggregates pass, fail, and incomplete verdicts
// into a single auditable artifact.
type EvidencePackage struct {
	SnapshotID      string            `json:"snapshot_id"`
	AssessedAt      time.Time         `json:"assessed_at"`
	Records         []*EvidenceRecord `json:"records"`
	PassCount       int               `json:"pass_count"`
	FailCount       int               `json:"fail_count"`
	IncompleteCount int               `json:"incomplete_count"`
}

// NewEvidencePackage creates an empty package for the given snapshot.
func NewEvidencePackage(snapshotID string, assessedAt time.Time) *EvidencePackage {
	return &EvidencePackage{
		SnapshotID: snapshotID,
		AssessedAt: assessedAt,
	}
}

// Add appends a record and updates the summary counts.
func (p *EvidencePackage) Add(r *EvidenceRecord) {
	p.Records = append(p.Records, r)
	switch r.Verdict {
	case VerdictPass:
		p.PassCount++
	case VerdictFail:
		p.FailCount++
	case VerdictIncomplete:
		p.IncompleteCount++
	}
}

// TotalRecords returns the number of evidence records in the package.
func (p *EvidencePackage) TotalRecords() int {
	return len(p.Records)
}

// FindByControlID returns all evidence records for the given control ID.
// Returns nil if no records match.
func (p *EvidencePackage) FindByControlID(controlID string) []*EvidenceRecord {
	var matches []*EvidenceRecord
	for _, r := range p.Records {
		if r.ControlID == controlID {
			matches = append(matches, r)
		}
	}
	return matches
}

// AggregateVerdict returns the worst-case verdict across the
// package's records, using the pre-computed counts (Add maintains
// them in step with Records). Precedence: any Fail dominates, then
// Incomplete, then Pass. A package with zero pass/fail/incomplete
// records (e.g. only NotApplicable) returns VerdictNotApplicable.
//
// Mirrors the per-control aggregateFromCounts helper used by
// profile_evaluator.go so the same precedence rule lives in one
// place.
func (p *EvidencePackage) AggregateVerdict() EvidenceVerdict {
	if p == nil {
		return VerdictNotApplicable
	}
	return aggregateFromCounts(p.PassCount, p.FailCount, p.IncompleteCount)
}

// aggregateFromCounts is the shared verdict-precedence rule. Used
// by EvidencePackage.AggregateVerdict and the per-control
// aggregator in profile_evaluator.go.
func aggregateFromCounts(pass, fail, incomplete int) EvidenceVerdict {
	switch {
	case fail > 0:
		return VerdictFail
	case incomplete > 0:
		return VerdictIncomplete
	case pass > 0:
		return VerdictPass
	default:
		return VerdictNotApplicable
	}
}
