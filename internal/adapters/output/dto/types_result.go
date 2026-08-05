package dto

import (
	"time"

	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

// RunInfoDTO mirrors evaluation.RunInfo.
type RunInfoDTO struct {
	StaveVersion      string          `json:"tool_version"`
	Offline           bool            `json:"offline"`
	EvalTime          time.Time       `json:"eval_time"`
	MaxUnsafeDuration kernel.Duration `json:"sla_threshold"`
	Snapshots         int             `json:"snapshots"`
	InputHashes       *InputHashesDTO `json:"input_hashes,omitempty"`
	PolicyFingerprint kernel.Digest   `json:"policy_fingerprint,omitempty"`
	EvaluatedState    string          `json:"evaluated_state"`
}

// InputHashesDTO mirrors evaluation.InputHashes.
type InputHashesDTO struct {
	Files   map[string]kernel.Digest `json:"files"`
	Overall kernel.Digest            `json:"overall"`
}

// SummaryDTO mirrors evaluation.ComplianceSummary.
type SummaryDTO struct {
	TotalAssets      int `json:"total_assets"`
	ExposedResources int `json:"exposed_resources"`
	Violations       int `json:"violations"`
	Indeterminate    int `json:"indeterminate,omitempty"`
}

// ExtensionsDTO mirrors evaluation.Extensions.
type ExtensionsDTO struct {
	SelectedSource      string             `json:"selected_controls_source,omitempty"`
	ContextName         string             `json:"context_name,omitempty"`
	ResolvedPaths       map[string]string  `json:"resolved_paths,omitempty"`
	EnabledPacks        []string           `json:"enabled_control_packs,omitempty"`
	ResolvedControlIDs  []kernel.ControlID `json:"resolved_control_ids,omitempty"`
	PackRegistryVersion string             `json:"pack_registry_version,omitempty"`
	PackRegistryHash    kernel.Digest      `json:"pack_registry_hash,omitempty"`
}

// IssueDTO mirrors evaluation.Issue for JSON output.
type IssueDTO struct {
	IssueID                 string   `json:"issue_id"`
	AssetID                 string   `json:"asset_id"`
	SharedKeys              []string `json:"shared_keys"`
	HeadlineFindingID       string   `json:"headline_finding_id"`
	MemberFindingIDs        []string `json:"member_finding_ids"`
	ConsolidatedScore       float64  `json:"consolidated_score"`
	ConsolidatedBlastRadius float64  `json:"consolidated_blast_radius"`
}

// IndeterminateDTO represents a control check that could not be completed
// because required observation fields were absent from the snapshot.
type IndeterminateDTO struct {
	ControlID     string   `json:"control_id"`
	ControlName   string   `json:"control_name"`
	Severity      string   `json:"severity"`
	AssetID       string   `json:"asset_id"`
	AssetType     string   `json:"asset_type"`
	Verdict       string   `json:"verdict"`
	MissingFields []string `json:"missing_fields"`
	GapCause      string   `json:"gap_cause"`
}

// TrendSummaryDTO carries baseline comparison counts when available.
type TrendSummaryDTO struct {
	NewCount       int `json:"new_count"`
	ResolvedCount  int `json:"resolved_count"`
	UnchangedCount int `json:"unchanged_count"`
}

// ResultDTO is the top-level evaluation output envelope content.
type ResultDTO struct {
	SchemaVersion     kernel.Schema            `json:"schema_version"`
	Kind              string                   `json:"kind"`
	Run               RunInfoDTO               `json:"run"`
	Summary           SummaryDTO               `json:"summary"`
	SecurityState     evaluation.SecurityState `json:"status"`
	RiskSignals       []AtRiskItemDTO          `json:"risk_signals,omitempty"`
	Findings          []FindingDTO             `json:"findings"`
	Indeterminate     []IndeterminateDTO       `json:"indeterminate,omitempty"`
	MarkerFindings    []FindingDTO             `json:"marker_findings,omitempty"`
	ChainFindings     []ChainFindingDTO        `json:"chain_findings,omitempty"`
	NearMissChains    []NearMissChainDTO       `json:"near_miss_chains,omitempty"`
	Issues            []IssueDTO               `json:"issues,omitempty"`
	RemediationGroups []RemediationGroupDTO    `json:"remediation_groups,omitempty"`
	SkippedControls   []SkippedControlDTO      `json:"skipped_controls,omitempty"`
	ExemptedAssets    []ExemptedAssetDTO       `json:"exempted_assets,omitempty"`
	TopExposures      []ExposureRankDTO        `json:"top_exposures,omitempty"`
	CoveragePosture   CoveragePostureDTO       `json:"coverage_posture,omitempty"`
	TrendSummary      *TrendSummaryDTO         `json:"trend_summary,omitempty"`
	Extensions        *ExtensionsDTO           `json:"extensions,omitempty"`
}
