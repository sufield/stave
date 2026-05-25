package dto

import (
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

// ChainFindingDTO mirrors risk.CompoundFinding for wire output.
// Mapping is centralised in mapper_chain.go so callers outside the
// dto package never reach into internal/core/evaluation/risk.
//
// JSON tags must remain identical to the source type — the
// schema is part of the out.v0.1 contract.
type ChainFindingDTO struct {
	ChainID            kernel.ChainID       `json:"chain"`
	AssetID            asset.ID             `json:"asset_id,omitempty"`
	ScopeID            string               `json:"scope_id,omitempty"`
	ScopeField         string               `json:"scope_field,omitempty"`
	ContributingAssets []asset.ID           `json:"contributing_assets,omitempty"`
	Description        string               `json:"description,omitempty"`
	ControlsFailing    []kernel.ControlID   `json:"controls_failing"`
	MissingSafeguards  []kernel.ControlID   `json:"missing_safeguards,omitempty"`
	CompoundScore      float64              `json:"compound_score"`
	Severity           string               `json:"severity"`
	Narrative          string               `json:"narrative"`
	AttackStages       []kernel.AttackStage `json:"attack_stages,omitempty"`
}

// ExposureRankDTO mirrors risk.ExposureRank for wire output.
type ExposureRankDTO struct {
	FindingIndex  int                  `json:"finding_index"`
	ControlID     kernel.ControlID     `json:"control_id"`
	AssetID       asset.ID             `json:"asset_id"`
	ExposureScore kernel.ExposureScore `json:"exposure_score"`
	Breakdown     ScoreBreakdownDTO    `json:"breakdown"`
	SilentKiller  bool                 `json:"silent_killer"`
}

// ScoreBreakdownDTO mirrors risk.ScoreBreakdown for wire output.
type ScoreBreakdownDTO struct {
	BaseScore          int                `json:"base_score"`
	DurationFactor     float64            `json:"duration_factor"`
	BlastMultiplier    kernel.BlastRadius `json:"blast_multiplier"`
	ExposureMultiplier float64            `json:"exposure_multiplier"`
	ChainBonus         float64            `json:"chain_bonus"`
	BlindMultiplier    float64            `json:"blind_multiplier"`
	DaysBlind          float64            `json:"days_blind"`
}
