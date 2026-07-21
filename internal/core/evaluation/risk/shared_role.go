package risk

import (
	"math"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
)

// SharedRoleIndex maps a role ARN to the list of asset IDs that use it.
// Built from snapshot data; used to annotate shared-role findings with
// the actual sharing count and peer list.
type SharedRoleIndex map[string][]asset.ID

// ComputeSharedRoleIndex scans all Lambda function assets across
// snapshots and groups them by execution role ARN. Only roles used
// by more than one function appear in the result.
func ComputeSharedRoleIndex(snapshots []asset.Snapshot) SharedRoleIndex {
	roleToAssets := make(map[string][]asset.ID)
	seen := make(map[string]map[asset.ID]bool)

	for i := range snapshots {
		for j := range snapshots[i].Assets {
			a := &snapshots[i].Assets[j]
			if string(a.Type) != "aws_lambda_function" {
				continue
			}
			roleARN := extractLambdaRoleARN(a.Properties)
			if roleARN == "" {
				continue
			}
			if seen[roleARN] == nil {
				seen[roleARN] = make(map[asset.ID]bool)
			}
			if seen[roleARN][a.ID] {
				continue
			}
			seen[roleARN][a.ID] = true
			roleToAssets[roleARN] = append(roleToAssets[roleARN], a.ID)
		}
	}

	idx := make(SharedRoleIndex)
	for arn, ids := range roleToAssets {
		if len(ids) > 1 {
			slices.SortFunc(ids, func(a, b asset.ID) int {
				return strings.Compare(string(a), string(b))
			})
			idx[arn] = ids
		}
	}
	return idx
}

// SharingCount returns the number of assets sharing the role used by
// assetID. Returns 0 if the asset's role is not shared.
func (idx SharedRoleIndex) SharingCount(assetID asset.ID, snapshots []asset.Snapshot) (count int, roleARN string, peers []asset.ID) {
	for i := range snapshots {
		for j := range snapshots[i].Assets {
			a := &snapshots[i].Assets[j]
			if a.ID != assetID {
				continue
			}
			arn := extractLambdaRoleARN(a.Properties)
			if arn == "" {
				return 0, "", nil
			}
			ids, ok := idx[arn]
			if !ok {
				return 0, arn, nil
			}
			peerList := make([]asset.ID, 0, len(ids)-1)
			for _, id := range ids {
				if id != assetID {
					peerList = append(peerList, id)
				}
			}
			return len(ids), arn, peerList
		}
	}
	return 0, "", nil
}

// BlastMultiplier returns a blast-radius multiplier derived from
// the sharing count: log2(count) clamped to [1.0, 5.0].
// 1 function = 1.0, 2 = 1.0, 4 = 2.0, 8 = 3.0, 16 = 4.0, 32+ = 5.0.
func SharedRoleBlastMultiplier(count int) float64 {
	if count <= 1 {
		return 1.0
	}
	m := math.Log2(float64(count))
	return min(m, 5.0)
}

func extractLambdaRoleARN(props map[string]any) string {
	compute, ok := props["compute"].(map[string]any)
	if !ok {
		return ""
	}
	fn, ok := compute["function"].(map[string]any)
	if !ok {
		return ""
	}
	arn, _ := fn["role_arn"].(string)
	return arn
}
