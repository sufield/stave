package policy

import (
	"crypto/sha256"
	"encoding/hex"
)

// StableRemediationPlanID returns a stable hash-derived fix-plan ID.
func StableRemediationPlanID(controlID, assetID string) string {
	sum := sha256.Sum256([]byte(controlID + "|" + assetID))
	return "fix-" + hex.EncodeToString(sum[:8])
}

// StableRemediationGroupID returns a stable hash-derived group ID for an asset and action set.
func StableRemediationGroupID(assetID, actionsHash string) string {
	sum := sha256.Sum256([]byte(assetID + "|" + actionsHash))
	return "fix-" + hex.EncodeToString(sum[:8])
}
