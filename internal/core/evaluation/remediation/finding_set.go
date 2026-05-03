package remediation

// FindingSet wraps a slice of Findings for aggregate operations.
// Replaces near-identical multi-probe accumulation loops in
// cmd/trend with a single named pass — callers ask the set for the
// summary they want instead of reproducing the
// "iterate, branch on IsCritical / HasSLA / IsOverdue, mutate three
// counters" boilerplate at every site.
//
// FindingSet is a thin slice alias; conversion is a no-op
// (FindingSet(slice)) and the underlying capacity / mutation
// semantics match the wrapped slice. The methods dispatch through
// the embedded evaluation.Finding's predicates (IsCritical, HasSLA,
// IsOverdue, SeverityLabel), so adding a new aggregate touches one
// type instead of every call site.
type FindingSet []Finding

// SLASummaryStats groups the per-team SLA aggregates trend reports
// emit. Critical counts findings whose ControlSeverity is Critical;
// SLATotal counts findings carrying an SLA deadline; SLAWithinTarget
// counts findings within the deadline (i.e. with an SLA but not
// overdue).
type SLASummaryStats struct {
	Critical        int
	SLATotal        int
	SLAWithinTarget int
}

// SLABreachStats groups the per-assessment SLA breach aggregates the
// SLA trend pass emits. TotalWithSLA is the count of findings with
// an SLA deadline; BreachedCount is the subset that have breached;
// BreachedBySeverity bins the breached subset by canonical severity
// label (the SeverityLabel string).
type SLABreachStats struct {
	TotalWithSLA       int
	BreachedCount      int
	BreachedBySeverity map[string]int
}

// SLASummary walks the set once and returns the team-side SLA stats
// trend reports consume. Replaces the manual (critical / slaTotal /
// slaWithin) accumulation loop in cmd/trend/team_trend.go.
func (s FindingSet) SLASummary() SLASummaryStats {
	var stats SLASummaryStats
	for i := range s {
		f := &s[i]
		if f.IsCritical() {
			stats.Critical++
		}
		if f.HasSLA() {
			stats.SLATotal++
			if !f.IsOverdue() {
				stats.SLAWithinTarget++
			}
		}
	}
	return stats
}

// GroupByOwner buckets the set's findings by the owning team's
// key. Findings whose Owner is unset are dropped — the result is
// safe to consume as a "team_id → findings" map without
// downstream nil-key handling. Returns nil when the set has no
// owner-tagged findings so callers can branch on len(map) > 0.
func (s FindingSet) GroupByOwner() map[string][]Finding {
	out := map[string][]Finding{}
	for i := range s {
		f := &s[i]
		if !f.HasOwner() {
			continue
		}
		key := f.OwnerKey()
		out[key] = append(out[key], *f)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// SLABreachSummary walks the set once and returns the
// assessment-side SLA breach stats. Replaces the manual
// (totalWithSLA / breachedCount / breachedBySev) accumulation loop
// in cmd/trend/metrics.go's computeSLATrend.
//
// The BreachedBySeverity map is allocated up-front so callers can
// range it without a nil-check even when the set has no SLA-bearing
// findings.
func (s FindingSet) SLABreachSummary() SLABreachStats {
	stats := SLABreachStats{BreachedBySeverity: make(map[string]int)}
	for i := range s {
		f := &s[i]
		if !f.HasSLA() {
			continue
		}
		stats.TotalWithSLA++
		if f.IsOverdue() {
			stats.BreachedCount++
			stats.BreachedBySeverity[f.SeverityLabel()]++
		}
	}
	return stats
}
