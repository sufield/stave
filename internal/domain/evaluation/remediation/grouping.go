package remediation

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/ports"
)

// Group clusters findings that share the same remediation actions for the same asset.
type Group struct {
	AssetID              asset.ID                   `json:"asset_id"`
	AssetType            kernel.AssetType           `json:"asset_type"`
	RemediationPlan      evaluation.RemediationPlan `json:"fix_plan"`
	ContributingControls []kernel.ControlID         `json:"contributing_controls"`
	FindingCount         int                        `json:"finding_count"`
}

// GroupStats computes aggregate statistics across remediation groups.
func GroupStats(groups []Group) (totalFindings int, hasMulti bool) {
	for _, g := range groups {
		totalFindings += g.FindingCount
		if g.FindingCount > 1 {
			hasMulti = true
		}
	}
	return totalFindings, hasMulti
}

// BuildGroups aggregates findings into groups based on their remediation intent.
func BuildGroups(h ports.Hasher, findings []Finding) []Group {
	acc := newAccumulator(h)
	for _, f := range findings {
		if f.RemediationPlan != nil {
			acc.add(f)
		}
	}
	return acc.toSortedGroups()
}

type groupEntry struct {
	assetID         asset.ID
	assetType       kernel.AssetType
	remediationPlan evaluation.RemediationPlan
	controlSet      map[kernel.ControlID]struct{}
	findingCount    int
}

type accumulator struct {
	hasher ports.Hasher
	groups map[string]*groupEntry
	order  []string // Tracks insertion order for semi-determinism before final sort
}

func newAccumulator(h ports.Hasher) *accumulator {
	return &accumulator{
		hasher: h,
		groups: make(map[string]*groupEntry),
	}
}

func (a *accumulator) add(f Finding) {
	hash := canonicalActionsHash(a.hasher, f.RemediationPlan.Actions)
	key := fmt.Sprintf("%s:%s", f.AssetID, hash)

	if g, ok := a.groups[key]; ok {
		g.controlSet[f.ControlID] = struct{}{}
		g.findingCount++
		return
	}

	// Clone the plan to avoid side-effects on the original finding
	plan := *f.RemediationPlan
	plan.ID = policy.StableRemediationGroupID(a.hasher, f.AssetID.String(), hash)

	a.groups[key] = &groupEntry{
		assetID:         f.AssetID,
		assetType:       f.AssetType,
		remediationPlan: plan,
		controlSet:      map[kernel.ControlID]struct{}{f.ControlID: {}},
		findingCount:    1,
	}
	a.order = append(a.order, key)
}

func (a *accumulator) toSortedGroups() []Group {
	if len(a.order) == 0 {
		return nil
	}

	result := make([]Group, 0, len(a.order))
	for _, key := range a.order {
		g := a.groups[key]

		// Convert control set to sorted slice
		controls := make([]kernel.ControlID, 0, len(g.controlSet))
		for id := range g.controlSet {
			controls = append(controls, id)
		}
		slices.Sort(controls)

		result = append(result, Group{
			AssetID:              g.assetID,
			AssetType:            g.assetType,
			RemediationPlan:      g.remediationPlan,
			ContributingControls: controls,
			FindingCount:         g.findingCount,
		})
	}

	// Final deterministic sort: AssetID first, then Plan ID
	slices.SortFunc(result, func(i, j Group) int {
		if n := cmp.Compare(i.AssetID.String(), j.AssetID.String()); n != 0 {
			return n
		}
		return cmp.Compare(i.RemediationPlan.ID, j.RemediationPlan.ID)
	})

	return result
}

// canonicalActionsHash generates a stable, short fingerprint for a set of actions.
func canonicalActionsHash(h ports.Hasher, actions []evaluation.RemediationAction) string {
	if len(actions) == 0 {
		return ""
	}

	// 1. Serialize actions into a sortable string format
	parts := make([]string, 0, len(actions))
	for _, a := range actions {
		// JSON ensures stable key ordering for map-based values
		val, _ := json.Marshal(a.Value)
		parts = append(parts, fmt.Sprintf("%s|%s|%s", a.ActionType, a.Path, val))
	}

	// 2. Sort to ensure order-independence
	slices.Sort(parts)

	// 3. Hash the canonical representation (first 16 hex chars for brevity + collision resistance)
	return string(h.HashDelimited(parts, '\n'))[:16]
}
