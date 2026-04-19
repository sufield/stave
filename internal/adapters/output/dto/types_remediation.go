package dto

import (
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

// RemediationPlanDTO mirrors evaluation.RemediationPlan.
type RemediationPlanDTO struct {
	ID             string                 `json:"id"`
	Target         RemediationTargetDTO   `json:"target"`
	Preconditions  []string               `json:"preconditions,omitempty"`
	Actions        []RemediationActionDTO `json:"actions,omitempty"`
	ExpectedEffect string                 `json:"expected_effect,omitempty"`
	// Action carries the same content as the underlying
	// RemediationPlan.Command — parameterized when the control
	// author wrote a templated CLI, prose otherwise. Renamed from
	// the previous "command" wire name to match what the field
	// actually carries; the domain type field remains .Command.
	Action string `json:"action,omitempty"`
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

// RemediationGroupDTO mirrors remediation.Group.
type RemediationGroupDTO struct {
	AssetID              asset.ID           `json:"asset_id"`
	AssetType            kernel.AssetType   `json:"asset_type"`
	RemediationPlan      RemediationPlanDTO `json:"fix_plan"`
	ContributingControls []kernel.ControlID `json:"contributing_controls"`
	FindingCount         int                `json:"finding_count"`
}
