package policy

import "github.com/sufield/stave/internal/domain/ports"

// StableRemediationPlanID returns a stable hash-derived fix-plan ID.
func StableRemediationPlanID(h ports.Hasher, controlID, assetID string) string {
	return h.StableID("fix-", controlID+"|"+assetID)
}

// StableRemediationGroupID returns a stable hash-derived group ID for an asset and action set.
func StableRemediationGroupID(h ports.Hasher, controlID, actionsHash string) string {
	return h.StableID("fix-", controlID+"|"+actionsHash)
}
