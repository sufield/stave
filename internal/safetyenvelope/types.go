package safetyenvelope

import (
	"encoding/json"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/diagnosis"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/kernel"
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
	Run                evaluation.RunInfo
	Summary            evaluation.Summary
	Findings           []remediation.Finding
	Skipped            []evaluation.SkippedControl
	SkippedAssets      []asset.SkippedAsset
	SuppressedFindings []evaluation.SuppressedFinding
}

// Evaluation is the out.v0.1 evaluation output envelope.
type Evaluation struct {
	SchemaVersion      kernel.Schema                  `json:"schema_version"`
	Kind               EnvelopeKind                   `json:"kind"`
	Run                evaluation.RunInfo             `json:"run"`
	Summary            evaluation.Summary             `json:"summary"`
	Findings           []remediation.Finding          `json:"findings"`
	SuppressedFindings []evaluation.SuppressedFinding `json:"suppressed_findings,omitempty"`
	RemediationGroups  []remediation.Group            `json:"remediation_groups,omitempty"`
	Skipped            []evaluation.SkippedControl    `json:"skipped,omitempty"`
	SkippedAssets      []asset.SkippedAsset           `json:"skipped_assets,omitempty"`
	Extensions         *evaluation.Extensions         `json:"extensions,omitempty"`
}

func normalizeSlice[T any](in []T) []T {
	if in == nil {
		return []T{}
	}
	return in
}

func (e *Evaluation) normalize() {
	e.Findings = normalizeSlice(e.Findings)
	e.SuppressedFindings = normalizeSlice(e.SuppressedFindings)
	e.RemediationGroups = normalizeSlice(e.RemediationGroups)
	e.Skipped = normalizeSlice(e.Skipped)
	e.SkippedAssets = normalizeSlice(e.SkippedAssets)
}

func NewEvaluation(req EvaluationRequest) Evaluation {
	out := Evaluation{
		SchemaVersion:      kernel.SchemaOutput,
		Kind:               KindEvaluation,
		Run:                req.Run,
		Summary:            req.Summary,
		Findings:           req.Findings,
		SuppressedFindings: req.SuppressedFindings,
		Skipped:            req.Skipped,
		SkippedAssets:      req.SkippedAssets,
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

func (v *Verification) Normalize() {
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
		if cp.Entries != nil {
			cp.Entries = append([]diagnosis.Entry(nil), cp.Entries...)
		}
		normalized = &cp
	}
	normalized.Entries = normalizeSlice(normalized.Entries)
	return Diagnose{
		SchemaVersion: kernel.SchemaDiagnose,
		Report:        normalized,
	}
}
