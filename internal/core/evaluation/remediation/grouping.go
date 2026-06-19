package remediation

import (
	"cmp"
	"log/slog"
	"slices"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
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
	for i := range groups {
		g := &groups[i]
		totalFindings += g.FindingCount
		if g.FindingCount > 1 {
			hasMulti = true
		}
	}
	return totalFindings, hasMulti
}

// PrepareForGrouping computes action fingerprints and stable group IDs
// on each finding's plan. Call before BuildGroups.
func PrepareForGrouping(h ports.Digester, gen ports.IdentityGenerator, findings []Finding) {
	for i := range findings {
		p := findings[i].RemediationPlan
		if p == nil {
			continue
		}
		p.ComputeFingerprint(h)
		p.ID = policy.StableRemediationGroupID(gen, findings[i].AssetID, p.ActionsFingerprint)
	}
}

// BuildGroups aggregates findings into groups by asset + action fingerprint.
// Findings must have been prepared via PrepareForGrouping first.
func BuildGroups(findings []Finding) []Group {
	acc := newAccumulator()
	for i := range findings {
		f := &findings[i]
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
	groups map[string]*groupEntry
	order  []string // Tracks insertion order for semi-determinism before final sort
}

func newAccumulator() *accumulator {
	return &accumulator{
		groups: make(map[string]*groupEntry),
	}
}

func (a *accumulator) add(f *Finding) {
	// An empty ActionsFingerprint would collapse every finding for
	// the same asset into one group, regardless of remediation
	// content — wholly unrelated rules would appear merged in the
	// output. Substitute the (per-finding-unique) FindingID so each
	// such row stays in its own group. An empty fingerprint is a
	// routine condition (a finding whose remediation plan has no
	// hashable actions) that the fallback handles correctly and the
	// operator cannot act on, so it is logged at Debug — visible under
	// -v for diagnosability, but not surfaced as a warning on every
	// normal run (which read as a failure to early adopters).
	fingerprint := f.RemediationPlan.ActionsFingerprint
	if fingerprint == "" {
		slog.Debug("remediation grouping: empty ActionsFingerprint; falling back to per-finding key",
			"control_id", f.ControlID, "asset_id", f.AssetID, "finding_id", f.FindingID)
		fingerprint = "no-fingerprint:" + string(f.FindingID)
	}
	key := string(f.AssetID) + ":" + fingerprint

	if g, ok := a.groups[key]; ok {
		g.controlSet[f.ControlID] = struct{}{}
		g.findingCount++
		return
	}

	plan := *f.RemediationPlan

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

	remediationGroups := make([]Group, 0, len(a.order))
	for _, key := range a.order {
		g := a.groups[key]

		// Convert control set to sorted slice
		controls := make([]kernel.ControlID, 0, len(g.controlSet))
		for id := range g.controlSet {
			controls = append(controls, id)
		}
		slices.Sort(controls)

		remediationGroups = append(remediationGroups, Group{
			AssetID:              g.assetID,
			AssetType:            g.assetType,
			RemediationPlan:      g.remediationPlan,
			ContributingControls: controls,
			FindingCount:         g.findingCount,
		})
	}

	// Final deterministic sort: AssetID first, then Plan ID
	slices.SortFunc(remediationGroups, func(i, j Group) int {
		if n := cmp.Compare(i.AssetID.String(), j.AssetID.String()); n != 0 {
			return n
		}
		return cmp.Compare(i.RemediationPlan.ID, j.RemediationPlan.ID)
	})

	return remediationGroups
}
