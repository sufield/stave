package remediation

import (
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

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
// label (the SeverityLabel string); TotalBySeverity bins the
// SLA-bearing population so callers can compute per-severity
// breach rates.
type SLABreachStats struct {
	TotalWithSLA       int
	BreachedCount      int
	BreachedBySeverity map[string]int
	TotalBySeverity    map[string]int
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

// ViolatedRequirements returns the distinct requirement IDs the
// set's findings violate for the given compliance framework. A
// finding contributes its ControlCompliance entry; controls that
// declare no citation for the framework are skipped.
//
// Centralised so cmd/trend's per-framework readiness pass stops
// walking ControlCompliance.Get inline.
func (s FindingSet) ViolatedRequirements(framework policy.ComplianceFramework) []string {
	if len(s) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	for i := range s {
		req := s[i].ControlCompliance.Get(framework)
		if req.IsEmpty() {
			continue
		}
		seen[string(req)] = struct{}{}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
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
	stats := SLABreachStats{
		BreachedBySeverity: make(map[string]int),
		TotalBySeverity:    make(map[string]int),
	}
	for i := range s {
		f := &s[i]
		if !f.HasSLA() {
			continue
		}
		sev := f.SeverityLabel()
		stats.TotalWithSLA++
		stats.TotalBySeverity[sev]++
		if f.IsOverdue() {
			stats.BreachedCount++
			stats.BreachedBySeverity[sev]++
		}
	}
	return stats
}

// CountCritical returns the number of findings with a Critical
// control severity. Centralised so cmd-side callers stop walking
// the slice and comparing the enum.
func (s FindingSet) CountCritical() int {
	n := 0
	for i := range s {
		if s[i].IsCritical() {
			n++
		}
	}
	return n
}

// Headline returns the ControlID that should represent this set in
// a per-resource or per-framework rollup — the "Headline Finding"
// the scorecard / executive-summary surfaces when many findings
// share an owner. Selection rule:
//
//  1. The first Critical-severity finding (a "first critical wins"
//     heuristic; callers that want strict severity ordering should
//     pre-sort the set).
//  2. Otherwise, the first finding in the set.
//  3. Empty string when the set has no findings.
//
// Centralised here so the scorecard / posture-rollup callers stop
// reproducing the (seen-once + severity-prefer) attribution loop.
func (s FindingSet) Headline() kernel.ControlID {
	if len(s) == 0 {
		return ""
	}
	for i := range s {
		if s[i].IsCritical() {
			return s[i].ControlID
		}
	}
	return s[0].ControlID
}
