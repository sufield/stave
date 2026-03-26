package safetyenvelope

import (
	"encoding/json"
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/diagnosis"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/remediation"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/risk"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// EnvelopeKind identifies the type of output envelope.
type EnvelopeKind string

const (
	KindEvaluation   EnvelopeKind = "evaluation"
	KindVerification EnvelopeKind = "verification"
)

// --- Evaluation ---

// EvaluationRequest bundles inputs for constructing an Evaluation envelope.
type EvaluationRequest struct {
	Run              evaluation.RunInfo
	Summary          evaluation.Summary
	SafetyStatus     evaluation.SafetyStatus
	AtRisk           risk.ThresholdItems
	Findings         []remediation.Finding
	Skipped          []evaluation.SkippedControl
	ExemptedAssets   []asset.ExemptedAsset
	ExceptedFindings []evaluation.ExceptedFinding
}

// Evaluation is the out.v0.1 evaluation output envelope.
type Evaluation struct {
	SchemaVersion     kernel.Schema                `json:"schema_version"`
	Kind              EnvelopeKind                 `json:"kind"`
	Run               evaluation.RunInfo           `json:"run"`
	Summary           evaluation.Summary           `json:"summary"`
	SafetyStatus      evaluation.SafetyStatus      `json:"safety_status"`
	AtRisk            risk.ThresholdItems          `json:"at_risk,omitempty"`
	Findings          []remediation.Finding        `json:"findings"`
	ExceptedFindings  []evaluation.ExceptedFinding `json:"excepted_findings,omitempty"`
	RemediationGroups []remediation.Group          `json:"remediation_groups,omitempty"`
	Skipped           []evaluation.SkippedControl  `json:"skipped,omitempty"`
	ExemptedAssets    []asset.ExemptedAsset        `json:"exempted_assets,omitempty"`
	Extensions        *evaluation.Extensions       `json:"extensions,omitempty"`
}

// NewEvaluation constructs an Evaluation envelope with normalized slices
// (nil → [] for stable JSON output).
func NewEvaluation(req EvaluationRequest) *Evaluation {
	return &Evaluation{
		SchemaVersion:    kernel.SchemaOutput,
		Kind:             KindEvaluation,
		Run:              req.Run,
		Summary:          req.Summary,
		SafetyStatus:     req.SafetyStatus,
		AtRisk:           req.AtRisk,
		Findings:         emptyIfNil(req.Findings),
		ExceptedFindings: emptyIfNil(req.ExceptedFindings),
		Skipped:          emptyIfNil(req.Skipped),
		ExemptedAssets:   emptyIfNil(req.ExemptedAssets),
	}
}

// --- Verification ---

// Verification is the out.v0.1 verification output envelope.
type Verification struct {
	SchemaVersion kernel.Schema       `json:"schema_version"`
	Kind          EnvelopeKind        `json:"kind"`
	Run           VerificationRunInfo `json:"run"`
	Summary       VerificationSummary `json:"summary"`
	Resolved      []VerificationEntry `json:"resolved"`
	Remaining     []VerificationEntry `json:"remaining"`
	Introduced    []VerificationEntry `json:"introduced"`
}

// VerificationRunInfo contains metadata about the verification run.
type VerificationRunInfo struct {
	StaveVersion      string        `json:"tool_version"`
	Offline           bool          `json:"offline"`
	Now               time.Time     `json:"now"`
	MaxUnsafeDuration time.Duration `json:"-"`
	BeforeSnapshots   int           `json:"before_snapshots"`
	AfterSnapshots    int           `json:"after_snapshots"`
}

// MarshalJSON renders MaxUnsafeDuration as a human-readable string
// (e.g. "168h0m0s") instead of raw nanoseconds.
func (v VerificationRunInfo) MarshalJSON() ([]byte, error) {
	type alias VerificationRunInfo
	return json.Marshal(&struct {
		MaxUnsafe string `json:"max_unsafe"`
		alias
	}{
		MaxUnsafe: v.MaxUnsafeDuration.String(),
		alias:     alias(v),
	})
}

// VerificationSummary provides aggregate counts.
type VerificationSummary struct {
	BeforeViolations int `json:"before_violations"`
	AfterViolations  int `json:"after_violations"`
	Resolved         int `json:"resolved"`
	Remaining        int `json:"remaining"`
	Introduced       int `json:"introduced"`
}

// VerificationEntry identifies a finding in the comparison.
type VerificationEntry struct {
	ControlID   kernel.ControlID `json:"control_id"`
	ControlName string           `json:"control_name"`
	AssetID     asset.ID         `json:"asset_id"`
	AssetType   kernel.AssetType `json:"asset_type"`
}

// VerificationRequest bundles inputs for constructing a Verification envelope.
type VerificationRequest struct {
	Run        VerificationRunInfo
	Summary    VerificationSummary
	Resolved   []VerificationEntry
	Remaining  []VerificationEntry
	Introduced []VerificationEntry
}

// NewVerification constructs a Verification envelope with normalized slices.
func NewVerification(req VerificationRequest) *Verification {
	return &Verification{
		SchemaVersion: kernel.SchemaOutput,
		Kind:          KindVerification,
		Run:           req.Run,
		Summary:       req.Summary,
		Resolved:      emptyIfNil(req.Resolved),
		Remaining:     emptyIfNil(req.Remaining),
		Introduced:    emptyIfNil(req.Introduced),
	}
}

// --- Diagnose ---

// Diagnose is the diagnose.v1 output envelope.
type Diagnose struct {
	SchemaVersion kernel.Schema     `json:"schema_version"`
	Report        *diagnosis.Report `json:"report"`
}

// NewDiagnose constructs a Diagnose envelope with a defensive copy of
// the report to prevent caller-side mutation of the output.
func NewDiagnose(report *diagnosis.Report) *Diagnose {
	if report == nil {
		return &Diagnose{
			SchemaVersion: kernel.SchemaDiagnose,
			Report:        &diagnosis.Report{Issues: []diagnosis.Issue{}},
		}
	}

	cp := *report
	cp.Issues = append([]diagnosis.Issue(nil), report.Issues...)
	if cp.Issues == nil {
		cp.Issues = []diagnosis.Issue{}
	}

	return &Diagnose{
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
