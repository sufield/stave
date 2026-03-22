// Package dto provides output data transfer objects that decouple
// JSON wire format from domain types. Field names and json tags
// MUST match the current wire format exactly to preserve golden test
// compatibility.
package dto

import (
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// FindingDTO mirrors remediation.Finding for JSON output.
type FindingDTO struct {
	ControlID          kernel.ControlID    `json:"control_id"`
	ControlName        string              `json:"control_name"`
	ControlDescription string              `json:"control_description"`
	AssetID            asset.ID            `json:"asset_id"`
	AssetType          kernel.AssetType    `json:"asset_type"`
	AssetVendor        kernel.Vendor       `json:"asset_vendor"`
	Source             *SourceRefDTO       `json:"source,omitempty"`
	Evidence           EvidenceDTO         `json:"evidence"`
	ControlSeverity    string              `json:"control_severity,omitempty"`
	ControlCompliance  map[string]string   `json:"control_compliance,omitempty"`
	Exposure           *ExposureDTO        `json:"exposure,omitempty"`
	PostureDrift       *PostureDriftDTO    `json:"posture_drift,omitempty"`
	Remediation        RemediationSpecDTO  `json:"remediation"`
	RemediationPlan    *RemediationPlanDTO `json:"fix_plan,omitempty"`
}

// SourceRefDTO mirrors asset.SourceRef.
type SourceRefDTO struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

// EvidenceDTO mirrors evaluation.Evidence.
type EvidenceDTO struct {
	FirstUnsafeAt       time.Time             `json:"first_unsafe_at,omitzero"`
	LastSeenUnsafeAt    time.Time             `json:"last_seen_unsafe_at,omitzero"`
	UnsafeDurationHours float64               `json:"unsafe_duration_hours,omitempty"`
	ThresholdHours      float64               `json:"threshold_hours,omitempty"`
	EpisodeCount        int                   `json:"episode_count,omitempty"`
	WindowDays          int                   `json:"window_days,omitempty"`
	RecurrenceLimit     int                   `json:"recurrence_limit,omitempty"`
	FirstEpisodeAt      time.Time             `json:"first_episode_at,omitzero"`
	LastEpisodeAt       time.Time             `json:"last_episode_at,omitzero"`
	Misconfigurations   []MisconfigurationDTO `json:"misconfigurations,omitempty"`
	RootCauses          []string              `json:"root_causes,omitempty"`
	SourceEvidence      *SourceEvidenceDTO    `json:"source_evidence,omitempty"`
	WhyNow              string                `json:"why_now,omitempty"`
}

// MisconfigurationDTO mirrors policy.Misconfiguration.
type MisconfigurationDTO struct {
	Property    string `json:"property"`
	ActualValue any    `json:"actual_value"`
	Operator    string `json:"operator"`
	UnsafeValue any    `json:"unsafe_value,omitempty"`
}

// SourceEvidenceDTO mirrors evaluation.SourceEvidence.
type SourceEvidenceDTO struct {
	IdentityStatements []string `json:"identity_statements,omitempty"`
	ResourceGrantees   []string `json:"resource_grantees,omitempty"`
}

// PostureDriftDTO mirrors evaluation.PostureDrift.
type PostureDriftDTO struct {
	Pattern      evaluation.DriftPattern `json:"pattern"`
	EpisodeCount int                     `json:"episode_count"`
}

// ExposureDTO mirrors policy.Exposure.
type ExposureDTO struct {
	Type           string `json:"type"`
	PrincipalScope string `json:"principal_scope"`
}

// RemediationSpecDTO mirrors policy.RemediationSpec.
type RemediationSpecDTO struct {
	Description string `json:"description"`
	Action      string `json:"action"`
	Example     string `json:"example,omitempty"`
}

// RemediationPlanDTO mirrors evaluation.RemediationPlan.
type RemediationPlanDTO struct {
	ID             string                 `json:"id"`
	Target         RemediationTargetDTO   `json:"target"`
	Preconditions  []string               `json:"preconditions,omitempty"`
	Actions        []RemediationActionDTO `json:"actions,omitempty"`
	ExpectedEffect string                 `json:"expected_effect,omitempty"`
}

// RemediationTargetDTO mirrors evaluation.RemediationTarget.
type RemediationTargetDTO struct {
	AssetID   asset.ID         `json:"asset_id"`
	AssetType kernel.AssetType `json:"asset_type"`
}

// RemediationActionDTO mirrors evaluation.RemediationAction.
type RemediationActionDTO struct {
	ActionType evaluation.RemediationActionType `json:"action_type"`
	Path       string                           `json:"path"`
	Value      any                              `json:"value,omitempty"`
}

// ExceptedFindingDTO mirrors evaluation.ExceptedFinding.
type ExceptedFindingDTO struct {
	ControlID kernel.ControlID `json:"control_id"`
	AssetID   asset.ID         `json:"asset_id"`
	Reason    string           `json:"reason"`
	Expires   string           `json:"expires,omitempty"`
}

// SkippedControlDTO mirrors evaluation.SkippedControl.
type SkippedControlDTO struct {
	ControlID   kernel.ControlID `json:"control_id"`
	ControlName string           `json:"control_name"`
	Reason      string           `json:"reason"`
}

// ExemptedAssetDTO mirrors asset.ExemptedAsset.
type ExemptedAssetDTO struct {
	AssetID asset.ID `json:"asset_id"`
	Pattern string   `json:"matched_pattern"`
	Reason  string   `json:"reason"`
}

// RunInfoDTO mirrors evaluation.RunInfo.
type RunInfoDTO struct {
	StaveVersion      string          `json:"tool_version"`
	Offline           bool            `json:"offline"`
	Now               time.Time       `json:"now"`
	MaxUnsafeDuration kernel.Duration `json:"max_unsafe"`
	Snapshots         int             `json:"snapshots"`
	InputHashes       *InputHashesDTO `json:"input_hashes,omitempty"`
	PackHash          kernel.Digest   `json:"pack_hash,omitempty"`
}

// InputHashesDTO mirrors evaluation.InputHashes.
type InputHashesDTO struct {
	Files   map[string]kernel.Digest `json:"files"`
	Overall kernel.Digest            `json:"overall"`
}

// SummaryDTO mirrors evaluation.Summary.
type SummaryDTO struct {
	AssetsEvaluated int `json:"assets_evaluated"`
	AttackSurface   int `json:"attack_surface"`
	Violations      int `json:"violations"`
}

// RemediationGroupDTO mirrors remediation.Group.
type RemediationGroupDTO struct {
	AssetID              asset.ID           `json:"asset_id"`
	AssetType            kernel.AssetType   `json:"asset_type"`
	RemediationPlan      RemediationPlanDTO `json:"fix_plan"`
	ContributingControls []kernel.ControlID `json:"contributing_controls"`
	FindingCount         int                `json:"finding_count"`
}

// ExtensionsDTO mirrors evaluation.Extensions.
type ExtensionsDTO struct {
	SelectedSource      string            `json:"selected_controls_source,omitempty"`
	ContextName         string            `json:"context_name,omitempty"`
	ResolvedPaths       map[string]string `json:"resolved_paths,omitempty"`
	EnabledPacks        []string          `json:"enabled_control_packs,omitempty"`
	ResolvedControlIDs  []string          `json:"resolved_control_ids,omitempty"`
	PackRegistryVersion string            `json:"pack_registry_version,omitempty"`
	PackRegistryHash    kernel.Digest     `json:"pack_registry_hash,omitempty"`
	Git                 *GitMetadataDTO   `json:"git,omitempty"`
}

// GitMetadataDTO mirrors evaluation.GitMetadata.
type GitMetadataDTO struct {
	RepoRoot string   `json:"repo_root,omitempty"`
	Head     string   `json:"head_commit,omitempty"`
	Dirty    bool     `json:"dirty"`
	Modified []string `json:"modified_paths,omitempty"`
}

// RowDTO mirrors evaluation.Row.
type RowDTO struct {
	ControlID  kernel.ControlID           `json:"control_id"`
	AssetID    asset.ID                   `json:"asset_id"`
	AssetType  kernel.AssetType           `json:"asset_type"`
	Domain     string                     `json:"asset_domain"`
	Decision   evaluation.Decision        `json:"decision"`
	Confidence evaluation.ConfidenceLevel `json:"confidence"`
	Evidence   *EvidenceDTO               `json:"evidence,omitempty"`
	WhyNow     string                     `json:"why_now,omitempty"`
	Reason     string                     `json:"reason,omitempty"`
}

// ResultDTO is the top-level evaluation output envelope content.
type ResultDTO struct {
	SchemaVersion     kernel.Schema         `json:"schema_version"`
	Kind              string                `json:"kind"`
	Run               RunInfoDTO            `json:"run"`
	Summary           SummaryDTO            `json:"summary"`
	Findings          []FindingDTO          `json:"findings"`
	ExceptedFindings  []ExceptedFindingDTO  `json:"excepted_findings,omitempty"`
	RemediationGroups []RemediationGroupDTO `json:"remediation_groups,omitempty"`
	Skipped           []SkippedControlDTO   `json:"skipped,omitempty"`
	ExemptedAssets    []ExemptedAssetDTO    `json:"exempted_assets,omitempty"`
	Extensions        *ExtensionsDTO        `json:"extensions,omitempty"`
}
