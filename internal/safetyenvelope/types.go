package safetyenvelope

import (
	"encoding/json"
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/diagnosis"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/remediation"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// EnvelopeKind identifies the type of output envelope.
type EnvelopeKind string

const (
	KindEvaluation   EnvelopeKind = "evaluation"
	KindVerification EnvelopeKind = "verification"
)

// JSONEnvelope wraps data in the standard ok/data envelope used in JSON mode.
type JSONEnvelope[T any] struct {
	OK   bool `json:"ok"`
	Data T    `json:"data"`
}

// EvaluationRequest bundles inputs for constructing an Evaluation envelope.
type EvaluationRequest struct {
	Run              evaluation.RunInfo
	Summary          evaluation.Summary
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
	Findings          []remediation.Finding        `json:"findings"`
	ExceptedFindings  []evaluation.ExceptedFinding `json:"excepted_findings,omitempty"`
	RemediationGroups []remediation.Group          `json:"remediation_groups,omitempty"`
	Skipped           []evaluation.SkippedControl  `json:"skipped,omitempty"`
	ExemptedAssets    []asset.ExemptedAsset        `json:"exempted_assets,omitempty"`
	Extensions        *evaluation.Extensions       `json:"extensions,omitempty"`
}

func normalizeSlice[T any](in []T) []T {
	if in == nil {
		return []T{}
	}
	return in
}

func (e *Evaluation) normalize() {
	e.Findings = normalizeSlice(e.Findings)
	e.ExceptedFindings = normalizeSlice(e.ExceptedFindings)
	e.RemediationGroups = normalizeSlice(e.RemediationGroups)
	e.Skipped = normalizeSlice(e.Skipped)
	e.ExemptedAssets = normalizeSlice(e.ExemptedAssets)
}

func NewEvaluation(req EvaluationRequest) Evaluation {
	out := Evaluation{
		SchemaVersion:    kernel.SchemaOutput,
		Kind:             KindEvaluation,
		Run:              req.Run,
		Summary:          req.Summary,
		Findings:         req.Findings,
		ExceptedFindings: req.ExceptedFindings,
		Skipped:          req.Skipped,
		ExemptedAssets:   req.ExemptedAssets,
	}
	out.normalize()
	return out
}

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
	ToolVersion     string        `json:"tool_version"`
	Offline         bool          `json:"offline"`
	Now             time.Time     `json:"now"`
	MaxUnsafe       time.Duration `json:"-"`
	BeforeSnapshots int           `json:"before_snapshots"`
	AfterSnapshots  int           `json:"after_snapshots"`
}

// MarshalJSON ensures MaxUnsafe outputs as a duration string (e.g. "168h0m0s")
// instead of raw nanoseconds.
func (v VerificationRunInfo) MarshalJSON() ([]byte, error) {
	type alias VerificationRunInfo
	return json.Marshal(&struct {
		MaxUnsafe string `json:"max_unsafe"`
		alias
	}{
		MaxUnsafe: v.MaxUnsafe.String(),
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

func NewVerification(req VerificationRequest) Verification {
	out := Verification{
		SchemaVersion: kernel.SchemaOutput,
		Kind:          KindVerification,
		Run:           req.Run,
		Summary:       req.Summary,
		Resolved:      req.Resolved,
		Remaining:     req.Remaining,
		Introduced:    req.Introduced,
	}
	out.normalize()
	return out
}

func (v *Verification) normalize() {
	v.Resolved = normalizeSlice(v.Resolved)
	v.Remaining = normalizeSlice(v.Remaining)
	v.Introduced = normalizeSlice(v.Introduced)
}

// Diagnose is the diagnose.v1 output envelope.
type Diagnose struct {
	SchemaVersion kernel.Schema     `json:"schema_version"`
	Report        *diagnosis.Report `json:"report"`
}

func NewDiagnose(report *diagnosis.Report) Diagnose {
	normalized := &diagnosis.Report{}
	if report != nil {
		cp := *report
		if cp.Issues != nil {
			cp.Issues = append([]diagnosis.Issue(nil), cp.Issues...)
		}
		normalized = &cp
	}
	normalized.Issues = normalizeSlice(normalized.Issues)
	return Diagnose{
		SchemaVersion: kernel.SchemaDiagnose,
		Report:        normalized,
	}
}
