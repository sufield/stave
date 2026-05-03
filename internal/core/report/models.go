package report

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/coverage"
	"github.com/sufield/stave/internal/core/evaluation/diagnosis"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
)

// Kind identifies the type of security report generated.
type Kind string

const (
	// KindAssessment is the primary security posture report.
	KindAssessment Kind = "ASSESSMENT"
	// KindAttestation is a verification report proving remediation or drift.
	KindAttestation Kind = "ATTESTATION"
)

// --- Security Assessment Models ---

// AssessmentRequest bundles inputs for constructing a security assessment.
type AssessmentRequest struct {
	Run                  evaluation.RunInfo
	Summary              evaluation.ComplianceSummary
	SecurityState        evaluation.SecurityState
	RiskSignals          risk.ThresholdItems
	Findings             []remediation.Finding
	ChainFindings        []risk.CompoundFinding
	AttackStageSummary   map[kernel.AttackStage]string
	TopExposures         []risk.ExposureRank
	Issues               []evaluation.Issue
	SkippedControls      []evaluation.SkippedControl
	ExemptedAssets       []asset.ExemptedAsset
	ExceptedFindings     []evaluation.ExceptedFinding
	AcknowledgedFindings []policy.AcknowledgedFinding
}

// HasFindings reports whether the assessment carries at least one
// finding. Replaces (len(a.Findings) == 0) probes at score / collect
// gating sites with a named accessor on the type.
func (a *Assessment) HasFindings() bool {
	return a != nil && len(a.Findings) > 0
}

// EnsureFindings normalises the Findings slice in-place: a nil
// slice is replaced with an empty slice. Returns the (now non-nil)
// slice for fluent use. Replaces the (env.Findings == nil →
// []remediation.Finding{}) coercion that loader.ParseFindings
// applied inline so the "JSON output always carries findings: []"
// contract lives on the type that owns the slice.
//
// Named EnsureFindings rather than the plan's suggested Findings()
// because Go does not permit a method to share a name with the
// existing Findings struct field.
func (a *Assessment) EnsureFindings() []remediation.Finding {
	if a == nil {
		return []remediation.Finding{}
	}
	if a.Findings == nil {
		a.Findings = []remediation.Finding{}
	}
	return a.Findings
}

// HasTimestamp reports whether the assessment's Run carries a
// non-zero capture time. Replaces (a.Run.Now.IsZero()) probes at
// snapshotID / sort sites so callers ask the type directly.
func (a *Assessment) HasTimestamp() bool {
	return a != nil && !a.Run.Now.IsZero()
}

// Before reports whether this assessment was captured before other.
// Replaces (a.Run.Now.Compare(b.Run.Now)) inline comparators at the
// score-trend sort site with a named accessor; uses standard
// time.Before semantics so the comparator follows Go conventions.
func (a *Assessment) Before(other *Assessment) bool {
	if a == nil || other == nil {
		return false
	}
	return a.Run.Now.Before(other.Run.Now)
}

// SLASummary returns the (total, breached) pair that summarises the
// assessment's SLA posture: total counts findings carrying an SLA
// deadline, breached counts the subset that have lapsed past it.
// Replaces the manual nil-check + IsOverdue loop duplicated in
// cmd/collect/cmd.go's posture-score path so callers ask the
// assessment for its SLA shape directly.
//
// Returns (0, 0) on a nil receiver so caller-side branches stay
// non-panicking.
func (a *Assessment) SLASummary() (total, breached int) {
	if a == nil {
		return 0, 0
	}
	for i := range a.Findings {
		f := &a.Findings[i]
		if !f.HasSLA() {
			continue
		}
		total++
		if f.IsOverdue() {
			breached++
		}
	}
	return total, breached
}

// SnapshotID returns the deterministic snapshot identifier
// callers (cmd/score's trend builder) attach to per-assessment
// rows: "snap-YYYYMMDD" derived from Run.Now, or "" when the
// assessment carries no timestamp. Centralised here so the
// formatting rule lives on the type that owns Run.Now.
func (a *Assessment) SnapshotID() string {
	if a == nil || !a.HasTimestamp() {
		return ""
	}
	return "snap-" + a.Run.Now.Format("20060102")
}

// CountBySeverity tallies the assessment's findings into the four
// named severity buckets (critical / high / medium / low). Replaces
// the open-coded switch loops in
// internal/app/execreport/builder_helpers.go and
// internal/app/consolidate/consolidate.go so summary builders ask the
// assessment for its counts instead of iterating Findings themselves.
//
// The total count callers used to track separately is available via
// SeverityCounts.Total(), or len(a.Findings) when callers want every
// finding regardless of severity tier.
func (a *Assessment) CountBySeverity() SeverityCounts {
	var c SeverityCounts
	if a == nil {
		return c
	}
	for i := range a.Findings {
		c.Add(a.Findings[i].ControlSeverity)
	}
	return c
}

// ValidateKind reports an error if the assessment's Kind discriminator
// does not match the expected value. Loaders previously did the
// (a.Kind != expected) field probe themselves; centralising the check
// keeps the discriminator-protection rule on the type that owns the
// field, so a future Kind rename or alias-handling tweak is one edit.
//
// Returns a context-rich error including both kinds so the caller can
// pass through directly without re-formatting.
func (a *Assessment) ValidateKind(expected Kind, source string) error {
	if a == nil {
		return fmt.Errorf("invalid artifact in %q: assessment is nil", source)
	}
	if a.Kind != expected {
		return fmt.Errorf("invalid artifact kind in %q: got %q, expected %q",
			source, a.Kind, expected)
	}
	return nil
}

// SeverityCounts groups per-severity finding counters used by
// summary builders. Centralising the shape lets Assessment own the
// canonical "tally findings by control severity" routine and keeps
// downstream summaries (FindingsSummary in execreport,
// AccountSummary in consolidate, TeamSummary in plan/grouper) from
// each reproducing the same switch-on-BucketName loop.
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// Total returns the sum of the four named tiers. Convenient for
// callers that already track a separate "total findings" count and
// want to assert consistency. Pointer receiver matches Add — keeps
// the SeverityCounts method set on a single receiver kind.
func (c *SeverityCounts) Total() int {
	return c.Critical + c.High + c.Medium + c.Low
}

// AsMap returns the counts keyed by canonical bucket name
// (critical / high / medium / low). Buckets with zero count are
// omitted so the map mirrors the open-coded "if count > 0" hooks
// trend metrics used. Allows cmd-side renderers to consume the
// same severity tally as JSON or template output without
// reproducing the four-field struct unpack.
func (c *SeverityCounts) AsMap() map[string]int {
	if c == nil {
		return nil
	}
	out := make(map[string]int, 4)
	if c.Critical > 0 {
		out["critical"] = c.Critical
	}
	if c.High > 0 {
		out["high"] = c.High
	}
	if c.Medium > 0 {
		out["medium"] = c.Medium
	}
	if c.Low > 0 {
		out["low"] = c.Low
	}
	return out
}

// Add increments the bucket that matches the given severity by 1.
// Severity values that don't map to one of the four named tiers
// (None, Info) are dropped — the counters represent only the
// reportable severity ladder. Used by Assessment.CountBySeverity
// and exposed for callers that count from non-Assessment sources
// (plan/grouper's PlanFinding tally).
func (c *SeverityCounts) Add(s policy.Severity) {
	switch s.BucketName() {
	case "critical":
		c.Critical++
	case "high":
		c.High++
	case "medium":
		c.Medium++
	case "low":
		c.Low++
	}
}

// Assessment is the top-level schema for a security evaluation outcome.
type Assessment struct {
	SchemaVersion        kernel.Schema                 `json:"schema_version"`
	Kind                 Kind                          `json:"kind"`
	Run                  evaluation.RunInfo            `json:"run"`
	Summary              evaluation.ComplianceSummary  `json:"summary"`
	Status               evaluation.SecurityState      `json:"status"`
	RiskSignals          risk.ThresholdItems           `json:"risk_signals,omitempty"`
	Findings             []remediation.Finding         `json:"findings"`
	ChainFindings        []risk.CompoundFinding        `json:"chain_findings,omitempty"`
	AttackStageSummary   map[kernel.AttackStage]string `json:"attack_stage_summary,omitempty"`
	TopExposures         []risk.ExposureRank           `json:"top_exposures,omitempty"`
	Issues               []evaluation.Issue            `json:"issues,omitempty"`
	ExceptedFindings     []evaluation.ExceptedFinding  `json:"excepted_findings,omitempty"`
	AcknowledgedFindings []policy.AcknowledgedFinding  `json:"acknowledged_findings,omitempty"`
	RemediationGroups    []remediation.Group           `json:"remediation_groups,omitempty"`
	SkippedControls      []evaluation.SkippedControl   `json:"skipped_controls,omitempty"`
	ExemptedAssets       []asset.ExemptedAsset         `json:"exempted_assets,omitempty"`
	CoveragePosture      *coverage.CoverageIndex       `json:"-"`
	Extensions           *evaluation.Extensions        `json:"extensions,omitempty"`
}

// NewAssessment constructs an Assessment with normalized slices
// (nil → [] for stable JSON output).
func NewAssessment(req AssessmentRequest) *Assessment {
	return &Assessment{
		SchemaVersion:        kernel.SchemaOutput,
		Kind:                 KindAssessment,
		Run:                  req.Run,
		Summary:              req.Summary,
		Status:               req.SecurityState,
		RiskSignals:          req.RiskSignals,
		Findings:             emptyIfNil(req.Findings),
		ChainFindings:        req.ChainFindings,
		AttackStageSummary:   req.AttackStageSummary,
		TopExposures:         req.TopExposures,
		Issues:               req.Issues,
		ExceptedFindings:     emptyIfNil(req.ExceptedFindings),
		AcknowledgedFindings: emptyIfNil(req.AcknowledgedFindings),
		SkippedControls:      emptyIfNil(req.SkippedControls),
		ExemptedAssets:       emptyIfNil(req.ExemptedAssets),
	}
}

// --- Remediation Attestation Models ---

// Attestation represents a "before-and-after" verification of security state.
type Attestation struct {
	SchemaVersion kernel.Schema      `json:"schema_version"`
	Kind          Kind               `json:"kind"`
	Run           AttestationRunInfo `json:"run"`
	Summary       AttestationSummary `json:"summary"`
	Remediated    []AttestationEntry `json:"remediated"`
	Open          []AttestationEntry `json:"open"`
	Regressions   []AttestationEntry `json:"regressions"`
}

// AttestationRunInfo contains metadata for the verification process.
type AttestationRunInfo struct {
	ToolVersion     string        `json:"tool_version"`
	Offline         bool          `json:"offline"`
	Now             time.Time     `json:"now"`
	SLAThreshold    time.Duration `json:"-"`
	BeforeSnapshots int           `json:"before_snapshots"`
	AfterSnapshots  int           `json:"after_snapshots"`
}

// MarshalJSON renders SLAThreshold as a human-readable string
// (e.g. "168h0m0s") instead of raw nanoseconds.
func (v AttestationRunInfo) MarshalJSON() ([]byte, error) {
	type alias AttestationRunInfo
	return json.Marshal(&struct {
		SLA string `json:"sla_threshold"`
		alias
	}{
		SLA:   v.SLAThreshold.String(),
		alias: alias(v),
	})
}

// AttestationSummary provides aggregate counts for remediation verification.
type AttestationSummary struct {
	PreviousViolations int `json:"previous_violations"`
	CurrentViolations  int `json:"current_violations"`
	Remediated         int `json:"remediated"`
	Open               int `json:"open"`
	Regressions        int `json:"regressions"`
}

// AttestationEntry identifies a specific resource-control pairing.
type AttestationEntry struct {
	ControlID   kernel.ControlID `json:"control_id"`
	ControlName string           `json:"control_name"`
	AssetID     asset.ID         `json:"asset_id"`
	AssetType   kernel.AssetType `json:"asset_type"`
}

// AttestationRequest bundles inputs for constructing an Attestation.
type AttestationRequest struct {
	Run         AttestationRunInfo
	Summary     AttestationSummary
	Remediated  []AttestationEntry
	Open        []AttestationEntry
	Regressions []AttestationEntry
}

// NewAttestation constructs an Attestation with normalized slices.
func NewAttestation(req AttestationRequest) *Attestation {
	return &Attestation{
		SchemaVersion: kernel.SchemaOutput,
		Kind:          KindAttestation,
		Run:           req.Run,
		Summary:       req.Summary,
		Remediated:    emptyIfNil(req.Remediated),
		Open:          emptyIfNil(req.Open),
		Regressions:   emptyIfNil(req.Regressions),
	}
}

// --- Readiness (Tool Health) Models ---

// Readiness captures the tool's self-diagnostic or pre-flight state.
type Readiness struct {
	SchemaVersion kernel.Schema     `json:"schema_version"`
	Report        *diagnosis.Report `json:"report"`
}

// NewReadiness constructs a Readiness report with a defensive copy of
// the report to prevent caller-side mutation of the output.
func NewReadiness(report *diagnosis.Report) *Readiness {
	if report == nil {
		return &Readiness{
			SchemaVersion: kernel.SchemaDiagnose,
			Report:        &diagnosis.Report{Issues: []diagnosis.Insight{}},
		}
	}

	cp := *report
	cp.Issues = append([]diagnosis.Insight(nil), report.Issues...)
	if cp.Issues == nil {
		cp.Issues = []diagnosis.Insight{}
	}

	return &Readiness{
		SchemaVersion: kernel.SchemaDiagnose,
		Report:        &cp,
	}
}

// --- Helpers ---

// emptyIfNil returns an empty non-nil slice when in is nil, ensuring
// JSON marshaling produces [] instead of null.
func emptyIfNil[T any](in []T) []T {
	if in == nil {
		return []T{}
	}
	return in
}
