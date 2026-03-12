package remediation

import (
	"cmp"
	"slices"

	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/ports"
)

type publicExposurePlanner struct {
	idGen ports.IdentityGenerator
}

func (p publicExposurePlanner) CanHandle(class kernel.ControlClass) bool {
	return class == kernel.ClassPublicExposure
}

func (p publicExposurePlanner) Plan(f Finding) *evaluation.RemediationPlan {
	// Actions use normalized domain paths.
	// The 'apply' layer is responsible for translating these to vendor-specific APIs.
	actions := []evaluation.RemediationAction{
		{ActionType: "set", Path: "security_posture.block_identity_public_access", Value: true},
		{ActionType: "set", Path: "security_posture.restrict_resource_public_access", Value: true},
		{ActionType: "set", Path: "security_posture.block_resource_metadata_access", Value: true},
		{ActionType: "set", Path: "security_posture.ignore_resource_metadata_access", Value: true},
	}

	slices.SortFunc(actions, func(a, b evaluation.RemediationAction) int {
		return cmp.Compare(a.Path, b.Path)
	})

	return &evaluation.RemediationPlan{
		ID: StablePlanID(p.idGen, f.ControlID, f.AssetID),
		Target: evaluation.RemediationTarget{
			AssetID:   f.AssetID,
			AssetType: f.AssetType,
		},
		Preconditions: []string{
			"Confirm resource ownership and internal change window approval.",
			"Ensure public access is not explicitly required for this specific resource's function.",
		},
		Actions:        actions,
		ExpectedEffect: "Enforces a hardened security posture by blocking all identity-bound and resource-bound public access paths.",
	}
}
