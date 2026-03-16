package diagnose

import (
	"github.com/samber/lo"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
)

// FilterFindings returns findings matching the given asset ID.
func FilterFindings(all []evaluation.Finding, assetID asset.ID) []evaluation.Finding {
	return lo.Filter(all, func(v evaluation.Finding, _ int) bool { return v.AssetID == assetID })
}
