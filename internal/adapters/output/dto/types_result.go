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

// ExtensionsDTO mirrors evaluation.Extensions.
type ExtensionsDTO struct {
	SelectedSource      string             `json:"selected_controls_source,omitempty"`
	ContextName         string             `json:"context_name,omitempty"`
	ResolvedPaths       map[string]string  `json:"resolved_paths,omitempty"`
	EnabledPacks        []string           `json:"enabled_control_packs,omitempty"`
	ResolvedControlIDs  []kernel.ControlID `json:"resolved_control_ids,omitempty"`
	PackRegistryVersion string             `json:"pack_registry_version,omitempty"`
	PackRegistryHash    kernel.Digest      `json:"pack_registry_hash,omitempty"`
	Git                 *GitMetadataDTO    `json:"git,omitempty"`
}

// GitMetadataDTO mirrors evaluation.GitMetadata.
type GitMetadataDTO struct {
	RepoRoot string   `json:"repo_root,omitempty"`
	Head     string   `json:"head_commit,omitempty"`
	Dirty    bool     `json:"dirty"`
	Modified []string `json:"modified_paths,omitempty"`
}

// ResultDTO is the top-level evaluation output envelope content.
type ResultDTO struct {
	SchemaVersion     kernel.Schema           `json:"schema_version"`
	Kind              string                  `json:"kind"`
	Run               RunInfoDTO              `json:"run"`
	Summary           SummaryDTO              `json:"summary"`
	Posture      evaluation.Posture `json:"safety_status"`
	AtRisk            []AtRiskItemDTO         `json:"at_risk,omitempty"`
	Findings          []FindingDTO            `json:"findings"`
	ExceptedFindings  []ExceptedFindingDTO    `json:"excepted_findings,omitempty"`
	RemediationGroups []RemediationGroupDTO   `json:"remediation_groups,omitempty"`
	Skipped           []SkippedControlDTO     `json:"skipped,omitempty"`
	ExemptedAssets    []ExemptedAssetDTO      `json:"exempted_assets,omitempty"`
	Extensions        *ExtensionsDTO          `json:"extensions,omitempty"`
}
