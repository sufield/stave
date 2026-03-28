package controldef

import (
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
)

const fixIDPrefix = "fix-"

// StableRemediationPlanID returns a stable hash-derived fix-plan ID for a control+asset pair.
func StableRemediationPlanID(gen ports.IdentityGenerator, ctlID kernel.ControlID, astID asset.ID) string {
	return gen.GenerateID(fixIDPrefix, ctlID.String(), astID.String())
}

// StableRemediationGroupID returns a stable hash-derived group ID for an asset and action set.
func StableRemediationGroupID(gen ports.IdentityGenerator, assetID asset.ID, actionsHash string) string {
	return gen.GenerateID(fixIDPrefix, assetID.String(), actionsHash)
}
