package remediation

import (
	"slices"
	"strings"

	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
)

type s3PublicPlanner struct{}

func (p s3PublicPlanner) CanHandle(class kernel.ControlClass) bool {
	return class == kernel.ClassS3Public
}

func (p s3PublicPlanner) Plan(f Finding) *evaluation.RemediationPlan {
	actions := []evaluation.RemediationAction{
		{ActionType: "set", Path: "properties.storage.controls.block_public_policy", Value: true},
		{ActionType: "set", Path: "properties.storage.controls.restrict_public_buckets", Value: true},
		{ActionType: "set", Path: "properties.storage.controls.block_public_acls", Value: true},
		{ActionType: "set", Path: "properties.storage.controls.ignore_public_acls", Value: true},
	}
	slices.SortFunc(actions, func(a, b evaluation.RemediationAction) int {
		return strings.Compare(a.Path, b.Path)
	})

	return &evaluation.RemediationPlan{
		ID: StablePlanID(f.ControlID, f.AssetID),
		Target: evaluation.RemediationTarget{
			AssetID:   f.AssetID,
			AssetType: f.AssetType,
		},
		Preconditions: []string{
			"Confirm bucket ownership and change window approval.",
			"Ensure public access is not intentionally required for this asset.",
		},
		Actions:        actions,
		ExpectedEffect: "Prevents public access by blocking policy and ACL based exposure paths.",
	}
}
