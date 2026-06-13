package stave

import "slices"

// FindingsForAsset returns every Finding rooted on the named asset.
// The returned slice is a fresh copy; consumers may mutate it freely
// without affecting the Assessment. Domain question: what fired on
// this asset?
//
// A nil receiver returns an empty (non-nil) slice so callers can
// range over the result without a presence check, matching the
// nil-safe pattern *Report and *GateResult use.
func (a *Assessment) FindingsForAsset(id AssetID) []Finding {
	if a == nil {
		return []Finding{}
	}
	out := make([]Finding, 0)
	for i := range a.Findings {
		if a.Findings[i].AssetID == id {
			out = append(out, a.Findings[i])
		}
	}
	return out
}

// FindingsForControl returns every Finding fired by the named control.
// The returned slice is a fresh copy; consumers may mutate it freely
// without affecting the Assessment. Domain question: which assets did
// this control flag?
//
// A nil receiver returns an empty (non-nil) slice so callers can range
// over the result without a presence check, matching the nil-safe
// pattern used by FindingsForAsset.
func (a *Assessment) FindingsForControl(id ControlID) []Finding {
	if a == nil {
		return []Finding{}
	}
	out := make([]Finding, 0)
	for i := range a.Findings {
		if a.Findings[i].ControlID == id {
			out = append(out, a.Findings[i])
		}
	}
	return out
}

// ConsolidatedIssues returns every Issue that groups more than one
// finding. The returned slice is a fresh copy. Domain question:
// which Issues consolidate multiple findings?
//
// A nil receiver returns an empty (non-nil) slice (see
// FindingsForAsset for the rationale).
func (a *Assessment) ConsolidatedIssues() []Issue {
	if a == nil {
		return []Issue{}
	}
	out := make([]Issue, 0)
	for i := range a.Issues {
		if a.Issues[i].IsConsolidated() {
			out = append(out, a.Issues[i])
		}
	}
	return out
}

// SingletonIssues returns every Issue with exactly one member finding.
// The returned slice is a fresh copy. Domain question: which Issues
// represent a single finding (no consolidation)?
//
// A nil receiver returns an empty (non-nil) slice.
func (a *Assessment) SingletonIssues() []Issue {
	if a == nil {
		return []Issue{}
	}
	out := make([]Issue, 0)
	for i := range a.Issues {
		if !a.Issues[i].IsConsolidated() {
			out = append(out, a.Issues[i])
		}
	}
	return out
}

// FindingsBySeverity returns the findings grouped by severity.
// Use to work through higher-priority findings first when triaging
// many findings: iterate the critical bucket before high, high
// before medium, and so on.
//
// The result map is pre-populated with all five known severities,
// each initialized to an empty (non-nil) slice so callers iterating
// in known order don't need a presence check. Findings whose
// Severity is the empty string are not placed in any bucket.
// Within each bucket, findings preserve the Assessment's emission
// order (no secondary sort). The returned map and its slices are
// fresh copies. Domain question: which findings fired at each
// severity?
func (a *Assessment) FindingsBySeverity() map[Severity][]Finding {
	out := map[Severity][]Finding{
		SeverityInfo:     {},
		SeverityLow:      {},
		SeverityMedium:   {},
		SeverityHigh:     {},
		SeverityCritical: {},
	}
	if a == nil {
		return out
	}
	for i := range a.Findings {
		sev := a.Findings[i].Severity
		if sev == "" {
			continue
		}
		out[sev] = append(out[sev], a.Findings[i])
	}
	return out
}

// CountBySeverity returns the count of findings at each known
// severity level. The result map is pre-populated with all five
// known severities at zero so callers iterating in known order
// don't need a presence check. Findings whose Severity is the empty
// string are not counted toward any bucket. The returned map is a
// fresh copy. Domain question: how do findings break down by
// severity?
func (a *Assessment) CountBySeverity() map[Severity]int {
	out := map[Severity]int{
		SeverityInfo:     0,
		SeverityLow:      0,
		SeverityMedium:   0,
		SeverityHigh:     0,
		SeverityCritical: 0,
	}
	if a == nil {
		return out
	}
	for i := range a.Findings {
		sev := a.Findings[i].Severity
		if sev == "" {
			continue
		}
		out[sev]++
	}
	return out
}

// FailingFindingsByFramework groups findings by each compliance
// framework cited in their ControlCompliance map. A finding citing
// N frameworks appears in N groups. Findings with no compliance
// citations do not appear in any group. The returned map and its
// slices are fresh copies. Domain question: which findings cite
// which compliance frameworks?
func (a *Assessment) FailingFindingsByFramework() map[string][]Finding {
	if a == nil {
		return map[string][]Finding{}
	}
	out := make(map[string][]Finding)
	for i := range a.Findings {
		for fw := range a.Findings[i].ControlCompliance {
			out[fw] = append(out[fw], a.Findings[i])
		}
	}
	return out
}

// Frameworks returns the sorted list of compliance frameworks cited
// by the control that produced this finding. Empty when the control
// declares no framework mappings. Domain question: which compliance
// frameworks does this finding's control cite?
func (f Finding) Frameworks() []string {
	if len(f.ControlCompliance) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(f.ControlCompliance))
	for fw := range f.ControlCompliance {
		out = append(out, fw)
	}
	slices.Sort(out)
	return out
}
