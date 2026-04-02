package controldef

import (
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
)

const fixIDPrefix = "fix-"

// RemediationPlanID uniquely identifies a remediation plan.
type RemediationPlanID string

// StableRemediationPlanID returns a stable hash-derived fix-plan ID for a control+asset pair.
func StableRemediationPlanID(gen ports.IdentityGenerator, ctlID kernel.ControlID, astID asset.ID) RemediationPlanID {
	return RemediationPlanID(gen.GenerateID(fixIDPrefix, ctlID.String(), astID.String()))
}

// StableRemediationGroupID returns a stable hash-derived group ID for an asset and action set.
func StableRemediationGroupID(gen ports.IdentityGenerator, assetID asset.ID, actionsHash string) RemediationPlanID {
	return RemediationPlanID(gen.GenerateID(fixIDPrefix, assetID.String(), actionsHash))
}
