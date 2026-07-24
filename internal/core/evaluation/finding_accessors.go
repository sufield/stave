package evaluation

import (
	"fmt"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

// IsUnattributed reports whether this finding lacks a ControlID.
func (f *Finding) IsUnattributed() bool {
	if f == nil {
		return true
	}
	return f.ControlID == ""
}

// SpanKey returns the canonical "<control_id>@<asset_id>" identifier.
func (f *Finding) SpanKey() string {
	if f == nil {
		return ""
	}
	return string(f.ControlID) + "@" + string(f.AssetID)
}

// FallbackID returns a deterministic "<control_id>/<asset_id>" fingerprint.
func (f *Finding) FallbackID() string {
	if f == nil {
		return ""
	}
	return string(f.ControlID) + "/" + string(f.AssetID)
}

// DwellHours returns the dwell time (Evidence.UnsafeDurationHours)
// the trend reports use for MTTR and total-dwell aggregations.
func (f *Finding) DwellHours() float64 {
	if f == nil {
		return 0
	}
	return f.Evidence.UnsafeDurationHours
}

// DwellDays returns the dwell time in days.
func (f *Finding) DwellDays() float64 {
	return f.DwellHours() / 24.0
}

// IsTemporallySignificant reports whether the finding has enough
// temporal data to be a reportable violation rather than an
// unanchored noise event.
func (f *Finding) IsTemporallySignificant() bool {
	if f == nil {
		return false
	}
	return f.Evidence.HasLifecycleDates() || f.Evidence.UnsafeDurationHours > 0
}

// ToDetail returns a FindingDetail seeded with the finding-owned
// fields (Evidence, PostureDrift, Asset summary).
func (f *Finding) ToDetail() FindingDetail {
	if f == nil {
		return FindingDetail{}
	}
	return FindingDetail{
		Evidence:     f.Evidence,
		PostureDrift: f.PostureDrift,
		Asset: FindingAssetSummary{
			ID:         f.AssetID,
			Type:       f.AssetType,
			Vendor:     f.AssetVendor,
			ObservedAt: f.Evidence.LastSeenUnsafeAt,
		},
	}
}

// HasDiagnosis reports whether the finding carries any of the
// authored triage prose (Defect / Infection / Failure).
func (f *Finding) HasDiagnosis() bool {
	return f != nil && (f.Defect != "" || f.Infection != "" || f.Failure != "")
}

// TriageEntry pairs an authored-triage label with its prose.
type TriageEntry struct {
	Label string
	Text  string
}

// TriageEntries returns the non-empty triage prose attached to
// the finding in the canonical Defect → Infection → Failure order.
func (f *Finding) TriageEntries() []TriageEntry {
	if f == nil {
		return nil
	}
	var out []TriageEntry
	if f.Defect != "" {
		out = append(out, TriageEntry{Label: "Defect", Text: f.Defect})
	}
	if f.Infection != "" {
		out = append(out, TriageEntry{Label: "Infection", Text: f.Infection})
	}
	if f.Failure != "" {
		out = append(out, TriageEntry{Label: "Failure", Text: f.Failure})
	}
	return out
}

// HasObservableDiagnosis reports whether the finding carries both
// authored triage prose AND a reasoning trace.
func (f *Finding) HasObservableDiagnosis() bool {
	return f.HasDiagnosis() && f.HasReasoningTrace()
}

// HasDeltaDiagnosis reports whether the finding carries both
// authored triage prose AND a mechanically-derived delta.
func (f *Finding) HasDeltaDiagnosis() bool {
	return f.HasDiagnosis() && f.HasDelta()
}

// HasReasoningTrace reports whether the finding carries the
// predicate-clause reasoning trace.
func (f *Finding) HasReasoningTrace() bool {
	return f != nil && len(f.ReasoningTrace) > 0
}

// HasDelta reports whether the finding carries any mechanically-
// derived fix paths.
func (f *Finding) HasDelta() bool {
	return f != nil && len(f.Delta) > 0
}

// HasExposure reports whether the finding carries the catalog's
// authored Exposure block.
func (f *Finding) HasExposure() bool {
	return f != nil && f.Exposure != nil
}

// ExposureType returns the catalog's exposure type as a string,
// or "" when no exposure block is present.
func (f *Finding) ExposureType() string {
	if !f.HasExposure() {
		return ""
	}
	return string(f.Exposure.Type)
}

// PrincipalScopeString returns the principal-scope rendering
// expected by DTO / SARIF / telemetry surfaces.
func (f *Finding) PrincipalScopeString() string {
	if !f.HasExposure() {
		return ""
	}
	return f.Exposure.PrincipalScope.String()
}

// HasPostureDrift reports whether the finding carries
// recurrence-pattern data.
func (f *Finding) HasPostureDrift() bool {
	return f != nil && f.PostureDrift != nil
}

// PostureDriftPattern returns the catalog-emitted drift label, or
// the zero value when no posture-drift block is present.
func (f *Finding) PostureDriftPattern() DriftPattern {
	if !f.HasPostureDrift() {
		return ""
	}
	return f.PostureDrift.Pattern
}

// PostureDriftWindowCount returns the recurrence count from the
// drift block, or 0 when no posture-drift block is present.
func (f *Finding) PostureDriftWindowCount() int {
	if !f.HasPostureDrift() {
		return 0
	}
	return f.PostureDrift.ExposureWindowCount
}

// HasAlternatives reports whether the catalog declared
// alternative-tool mappings for the finding's control.
func (f *Finding) HasAlternatives() bool {
	return f != nil && len(f.Alternatives) > 0
}

// HasReachability reports whether the finding carries IAM-graph
// reachability context.
func (f *Finding) HasReachability() bool {
	return f != nil && f.Reachability != nil
}

// HasClassification reports whether the finding carries a
// non-empty Classification tag.
func (f *Finding) HasClassification() bool {
	return f != nil && f.Classification != ""
}

// HasScopeTags reports whether the finding carries any
// scope-tag annotations.
func (f *Finding) HasScopeTags() bool {
	return f != nil && len(f.ScopeTags) > 0
}

// HasEnrichedContext reports whether the finding carries
// analytical metadata beyond the bare control violation.
func (f *Finding) HasEnrichedContext() bool {
	return f.IsChainMember() ||
		f.HasReasoningTrace() ||
		f.HasAlternatives() ||
		f.HasClassification() ||
		f.HasScopeTags()
}

// TemporalRiskMessage returns the Evidence-side risk message.
func (f *Finding) TemporalRiskMessage() string {
	if f == nil {
		return ""
	}
	return f.Evidence.TemporalRisk
}

// HasOwner reports whether ownership routing has populated a team
// for this finding.
func (f *Finding) HasOwner() bool {
	return !f.OwnerTeamID.IsEmpty()
}

// OwnerKey returns the owning team's ID rendered as a string.
func (f *Finding) OwnerKey() string {
	if f == nil || !f.HasOwner() {
		return ""
	}
	return f.OwnerTeamID.String()
}

// MatchesOwner reports whether this finding's owner key is present
// in the supplied allow-set.
func (f *Finding) MatchesOwner(allowed map[string]struct{}) bool {
	if f == nil || allowed == nil {
		return false
	}
	_, ok := allowed[f.OwnerKey()]
	return ok
}

// HasSource reports whether the finding carries a SourceRef.
func (f *Finding) HasSource() bool {
	return f != nil && f.Source != nil
}

// ReasoningTraceFromMisconfigurations converts a predicate-extracted
// misconfiguration list into the reasoning-trace shape surfaced on a
// finding.
func ReasoningTraceFromMisconfigurations(ms []policy.Misconfiguration) []MatchedClause {
	if len(ms) == 0 {
		return nil
	}
	out := make([]MatchedClause, len(ms))
	for i, mc := range ms {
		key := mc.DisplayProperty()
		expected := mc.UnsafeValue
		out[i] = MatchedClause{
			PredicateExpr:  formatClauseExpr(key, mc.Operator, expected),
			ObservationKey: kernel.FromFieldPath(key),
			Operator:       mc.Operator,
			ExpectedValue:  expected,
			ObservedValue:  mc.ActualValue,
		}
	}
	return out
}

func formatClauseExpr(key string, op predicate.Operator, expected any) string {
	switch expected.(type) {
	case nil:
		return key + " " + string(op)
	default:
		return key + " " + string(op) + " " + stringifyExpected(expected)
	}
}

func stringifyExpected(v any) string {
	switch t := v.(type) {
	case string:
		return "\"" + t + "\""
	default:
		return fmt.Sprint(t)
	}
}

// SeverityLabel returns the canonical lowercase severity string for
// this finding.
func (f *Finding) SeverityLabel() string {
	if f == nil {
		return ""
	}
	return f.ControlSeverity.String()
}
