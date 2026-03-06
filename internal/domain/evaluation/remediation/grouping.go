package remediation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
)

// Group clusters findings that share the same fix plan actions on
// the same asset.
type Group struct {
	AssetID              asset.ID                   `json:"asset_id"`
	AssetType            kernel.AssetType           `json:"asset_type"`
	RemediationPlan      evaluation.RemediationPlan `json:"fix_plan"`
	ContributingControls []kernel.ControlID         `json:"contributing_controls"`
	FindingCount         int                        `json:"finding_count"`
}

// GroupStats returns the total finding count across groups and whether any
// group contains more than one contributing control.
func GroupStats(groups []Group) (totalFindings int, hasMulti bool) {
	for _, g := range groups {
		totalFindings += g.FindingCount
		if g.FindingCount > 1 {
			hasMulti = true
		}
	}
	return totalFindings, hasMulti
}

// BuildGroups computes remediation groups from enriched findings.
func BuildGroups(findings []Finding) []Group {
	acc := newRemediationAccumulator()
	for _, f := range findings {
		if f.RemediationPlan == nil {
			continue
		}
		acc.add(f)
	}
	return acc.toSortedGroups()
}

type remediationAccumulator struct {
	groups map[string]*remediationGroupEntry
	order  []string // insertion order, used before final deterministic sort
}

type remediationGroupEntry struct {
	assetID         asset.ID
	resourceType    kernel.AssetType
	remediationPlan evaluation.RemediationPlan
	controlSet      map[kernel.ControlID]struct{}
	findingCount    int
}

func newRemediationAccumulator() *remediationAccumulator {
	return &remediationAccumulator{
		groups: make(map[string]*remediationGroupEntry),
	}
}

func (a *remediationAccumulator) add(f Finding) {
	hash := canonicalActionsHash(f.RemediationPlan.Actions)
	key := makeRemediationGroupKey(f.AssetID, hash)

	if g, ok := a.groups[key]; ok {
		g.controlSet[f.ControlID] = struct{}{}
		g.findingCount++
		return
	}

	plan := *f.RemediationPlan
	plan.ID = stableRemediationGroupID(f.AssetID.String(), hash)

	a.groups[key] = &remediationGroupEntry{
		assetID:         f.AssetID,
		resourceType:    f.AssetType,
		remediationPlan: plan,
		controlSet:      map[kernel.ControlID]struct{}{f.ControlID: {}},
		findingCount:    1,
	}
	a.order = append(a.order, key)
}

func (a *remediationAccumulator) toSortedGroups() []Group {
	if len(a.order) == 0 {
		return nil
	}

	result := make([]Group, 0, len(a.order))
	for _, key := range a.order {
		g := a.groups[key]
		result = append(result, Group{
			AssetID:              g.assetID,
			AssetType:            g.resourceType,
			RemediationPlan:      g.remediationPlan,
			ContributingControls: sortRemediationControlSet(g.controlSet),
			FindingCount:         g.findingCount,
		})
	}

	slices.SortFunc(result, func(i, j Group) int {
		if i.AssetID != j.AssetID {
			return strings.Compare(i.AssetID.String(), j.AssetID.String())
		}
		return strings.Compare(i.RemediationPlan.ID, j.RemediationPlan.ID)
	})

	return result
}

func makeRemediationGroupKey(assetID asset.ID, actionsHash string) string {
	return assetID.String() + ":" + actionsHash
}

func sortRemediationControlSet(invSet map[kernel.ControlID]struct{}) []kernel.ControlID {
	controls := make([]kernel.ControlID, 0, len(invSet))
	for id := range invSet {
		controls = append(controls, id)
	}
	slices.Sort(controls)
	return controls
}

func canonicalActionsHash(actions []evaluation.RemediationAction) string {
	if len(actions) == 0 {
		return ""
	}

	// 1. Create strings for sorting.
	// We use a specific format to ensure uniqueness and stability.
	parts := make([]string, len(actions))
	for i, a := range actions {
		// Use JSON for the value to ensure stable serialization
		// of complex types (like maps or slices).
		valBytes, _ := json.Marshal(a.Value)
		parts[i] = fmt.Sprintf("%s|%s|%s", a.ActionType, a.Path, valBytes)
	}

	// 2. Sort to ensure the hash is independent of action order.
	slices.Sort(parts)

	// 3. Use a hash.Hash object to avoid extra string/byte allocations
	// from strings.Join() and []byte conversion.
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{'\n'}) // Separator to prevent "collision" attacks
	}

	// 4. Return a short, stable hex prefix.
	return hex.EncodeToString(h.Sum(nil)[:8])
}

func stableRemediationGroupID(assetID, actionsHash string) string {
	return policy.StableRemediationGroupID(assetID, actionsHash)
}
