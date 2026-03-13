package diagnose

import (
	"fmt"
)

func validateFindingDetailArgs(controlID, assetID string) error {
	if controlID == "" {
		return fmt.Errorf("--control-id is required when --asset-id is set")
	}
	if assetID == "" {
		return fmt.Errorf("--asset-id is required when --control-id is set")
	}
	return nil
}
