package report

import (
	"encoding/json"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
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
	AttackStageSummary   map[string]string
	TopExposures         []risk.ExposureRank
	SkippedControls      []evaluation.SkippedControl
	ExemptedAssets       []asset.ExemptedAsset
	ExceptedFindings     []evaluation.ExceptedFinding
	AcknowledgedFindings []policy.AcknowledgedFinding
}

// Assessment is the top-level schema for a security evaluation outcome.
type Assessment struct {
	SchemaVersion        kernel.Schema                `json:"schema_version"`
	Kind                 Kind                         `json:"kind"`
	Run                  evaluation.RunInfo           `json:"run"`
	Summary              evaluation.ComplianceSummary `json:"summary"`
	Status               evaluation.SecurityState     `json:"status"`
	RiskSignals          risk.ThresholdItems          `json:"risk_signals,omitempty"`
	Findings             []remediation.Finding        `json:"findings"`
	ChainFindings        []risk.CompoundFinding       `json:"chain_findings,omitempty"`
	AttackStageSummary   map[string]string            `json:"attack_stage_summary,omitempty"`
	TopExposures         []risk.ExposureRank          `json:"top_exposures,omitempty"`
	ExceptedFindings     []evaluation.ExceptedFinding `json:"excepted_findings,omitempty"`
	AcknowledgedFindings []policy.AcknowledgedFinding `json:"acknowledged_findings,omitempty"`
	RemediationGroups    []remediation.Group          `json:"remediation_groups,omitempty"`
	SkippedControls      []evaluation.SkippedControl  `json:"skipped_controls,omitempty"`
	ExemptedAssets       []asset.ExemptedAsset        `json:"exempted_assets,omitempty"`
	Extensions           *evaluation.Extensions       `json:"extensions,omitempty"`
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
