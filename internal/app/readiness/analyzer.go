package readiness

import (
	"maps"
	"slices"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// Analyze produces a Report describing how completely the supplied
// snapshots exercise the supplied controls + chains. It does NOT
// call the evaluation engine. It compares the observed asset
// types against each control's ApplicableAssetTypes declaration
// (the same field engine/lifecycles.go reads to filter assets
// per control).
//
// topN bounds the action plan output to the N highest-unlock
// missing asset types. A non-positive value emits no action plan.
func Analyze(controls []policy.ControlDefinition, chains []policy.ChainDefinition, snapshots []asset.Snapshot, topN int) Report {
	observedTypes, observationCount := observed(snapshots)
	catalogTypes := catalogAssetTypes(controls)

	controlForecast := classifyControls(controls, observedTypes)
	chainForecast := classifyChains(controls, chains, observedTypes)
	annotateForecastPercentages(&controlForecast)
	annotateForecastPercentages(&chainForecast)

	report := Report{
		ObservationCount:     observationCount,
		ObservedTypes:        observedTypes,
		CatalogTypes:         catalogTypes,
		Controls:             controlForecast,
		Chains:               chainForecast,
		ReadinessScore:       readinessScore(controlForecast),
		ReadinessDenominator: "can_fire + blocked (excludes indeterminate)",
	}
	if topN > 0 {
		report.Actions = rankActions(controls, chains, observedTypes, topN)
	}
	return report
}

// observed counts the distinct asset types that appear across
// all snapshots. Multiple snapshots may carry the same asset
// across time; per-type counts come from the latest snapshot to
// avoid inflating coverage with historical observations of the
// same asset.
func observed(snapshots []asset.Snapshot) (map[kernel.AssetType]int, int) {
	out := map[kernel.AssetType]int{}
	if len(snapshots) == 0 {
		return out, 0
	}
	// Find the latest snapshot for each unique Source.
	latestBySource := map[asset.SnapshotSource]*asset.Snapshot{}
	for i := range snapshots {
		s := &snapshots[i]
		prev, ok := latestBySource[s.Source]
		if !ok || s.CapturedAt.After(prev.CapturedAt) {
			latestBySource[s.Source] = s
		}
	}

	perTypeIDs := map[kernel.AssetType]map[asset.ID]struct{}{}
	for _, snap := range latestBySource {
		for j := range snap.Assets {
			a := &snap.Assets[j]
			ids, ok := perTypeIDs[a.Type]
			if !ok {
				ids = map[asset.ID]struct{}{}
				perTypeIDs[a.Type] = ids
			}
			ids[a.ID] = struct{}{}
		}
	}
	total := 0
	for t, ids := range perTypeIDs {
		out[t] = len(ids)
		total += len(ids)
	}
	return out, total
}

// catalogAssetTypes returns the union of every ApplicableAssetTypes
// declaration across the control catalog. This is the universe of
// asset types the analyzer knows how to track.
func catalogAssetTypes(controls []policy.ControlDefinition) map[kernel.AssetType]bool {
	out := map[kernel.AssetType]bool{}
	for i := range controls {
		for _, t := range controls[i].ApplicableAssetTypes {
			out[t] = true
		}
	}
	return out
}

// classifyControls walks the control catalog and assigns each
// control to one of three buckets. Controls without
// ApplicableAssetTypes are indeterminate: the analyzer cannot
// statically predict their firing behavior.
func classifyControls(controls []policy.ControlDefinition, observed map[kernel.AssetType]int) ControlForecast {
	forecast := ControlForecast{Total: len(controls)}
	for i := range controls {
		applicable := controls[i].ApplicableAssetTypes
		if len(applicable) == 0 {
			forecast.Indeterminate++
			continue
		}
		if anyObserved(applicable, observed) {
			forecast.CanFire++
			continue
		}
		forecast.Blocked++
	}
	return forecast
}

// classifyChains classifies every chain by whether all member
// controls can fire. A chain is blocked if any member is
// blocked. A chain is indeterminate if no member is blocked but
// at least one is indeterminate (the chain may or may not fire
// depending on engine-time evaluation).
func classifyChains(controls []policy.ControlDefinition, chains []policy.ChainDefinition, observed map[kernel.AssetType]int) ChainForecast {
	ctlIndex := indexControls(controls)
	forecast := ChainForecast{Total: len(chains)}

	for i := range chains {
		chain := &chains[i]
		blocked := false
		indeterminate := false

		for _, memberID := range chain.ControlIDs {
			ctl, ok := ctlIndex[memberID]
			if !ok {
				indeterminate = true
				continue
			}
			if len(ctl.ApplicableAssetTypes) == 0 {
				indeterminate = true
				continue
			}
			if !anyObserved(ctl.ApplicableAssetTypes, observed) {
				blocked = true
			}
		}

		switch {
		case blocked:
			forecast.Blocked++
		case indeterminate:
			forecast.Indeterminate++
		default:
			forecast.CanFire++
		}
	}
	return forecast
}

// rankActions uses a greedy weighted set cover to recommend the
// fewest missing asset types that unblock the most controls and
// chains. Each iteration selects the type with the highest
// marginal value (new chains unblocked, then new controls as
// tiebreaker). After selection, its coverage is subtracted from
// the remaining universe so overlapping types don't double-count.
func rankActions(controls []policy.ControlDefinition, chains []policy.ChainDefinition, observed map[kernel.AssetType]int, topN int) []Action {
	ctlIndex := indexControls(controls)

	// Collect candidate types: all applicable types not yet observed.
	candidates := map[kernel.AssetType]struct{}{}
	for i := range controls {
		for _, t := range controls[i].ApplicableAssetTypes {
			if observed[t] == 0 {
				candidates[t] = struct{}{}
			}
		}
	}
	if len(candidates) == 0 {
		return nil
	}

	// Simulate progressively observing types.
	simulated := maps.Clone(observed)
	var selected []Action

	for len(selected) < topN && len(candidates) > 0 {
		var bestType kernel.AssetType
		bestChains, bestControls := 0, 0

		for t := range candidates {
			mc, ms := marginalValue(t, controls, chains, ctlIndex, simulated)
			better := mc > bestChains ||
				(mc == bestChains && ms > bestControls) ||
				(mc == bestChains && ms == bestControls && (bestType == "" || t < bestType))
			if better {
				bestType = t
				bestChains = mc
				bestControls = ms
			}
		}

		if bestChains == 0 && bestControls == 0 {
			break
		}

		selected = append(selected, Action{
			AssetType:         bestType,
			ChainsUnblocked:   bestChains,
			ControlsUnblocked: bestControls,
			Description:       describeAction(bestType),
		})
		simulated[bestType] = 1
		delete(candidates, bestType)
	}
	return selected
}

// marginalValue computes how many NEW controls and chains become
// unblocked by adding assetType to the simulated observation set.
func marginalValue(
	assetType kernel.AssetType,
	controls []policy.ControlDefinition,
	chains []policy.ChainDefinition,
	ctlIndex map[kernel.ControlID]*policy.ControlDefinition,
	simulated map[kernel.AssetType]int,
) (newChains, newControls int) {
	// Controls unblocked: currently blocked, would fire with assetType.
	for i := range controls {
		applicable := controls[i].ApplicableAssetTypes
		if len(applicable) == 0 {
			continue
		}
		if anyObserved(applicable, simulated) {
			continue // already unblocked
		}
		if slices.Contains(applicable, assetType) {
			newControls++
		}
	}

	// Chains unblocked: currently blocked, ALL members would fire
	// after adding assetType to simulated.
	for i := range chains {
		chain := &chains[i]
		wasBlocked := false
		wouldBeUnblocked := true

		for _, memberID := range chain.ControlIDs {
			ctl, ok := ctlIndex[memberID]
			if !ok || len(ctl.ApplicableAssetTypes) == 0 {
				continue
			}
			if anyObserved(ctl.ApplicableAssetTypes, simulated) {
				continue // member already fires
			}
			wasBlocked = true
			// Would this member fire if assetType were added?
			memberFires := slices.Contains(ctl.ApplicableAssetTypes, assetType)
			if !memberFires {
				wouldBeUnblocked = false
				break
			}
		}
		if wasBlocked && wouldBeUnblocked {
			newChains++
		}
	}
	return newChains, newControls
}

// describeAction returns a one-line human-friendly description
// for collecting the given asset type. Phase 1 emits generic
// language; a follow-on registry mapping asset.Type → collector
// invocation will let this synthesize specific commands.
func describeAction(t kernel.AssetType) string {
	return "Collect " + string(t) + " observations and re-run stave readiness."
}

// readinessScore is the fraction of *declared-asset-type*
// controls that can fire — i.e. those whose applicable asset
// types include an observed type. Controls without a declaration
// are excluded from both numerator and denominator. The score is
// pure input completeness, not security posture: 100% means
// "every classifiable control can be evaluated against this
// snapshot," not "everything is safe."
func readinessScore(f ControlForecast) float64 {
	denom := f.CanFire + f.Blocked
	if denom == 0 {
		return 0
	}
	return float64(f.CanFire) / float64(denom)
}

// annotateForecastPercentages fills the *Pct fields on a forecast
// from its integer bucket counts. Computed once at Analyze time so
// every consumer (CLI text, JSON, pkg/stave) sees the same
// numbers without recomputing. The percentages are share-of-Total
// (scaled 0..100), distinct from ReadinessScore which is a
// share-of-classifiable. Showing both prevents the "41% ready"
// misread the original output enabled.
//
// We use a type that exposes the same field set across
// ControlForecast and ChainForecast via Go 1.18+ generics-like
// pattern, but because both structs are concrete and identical,
// a tiny duplicated helper is clearer than introducing a constraint.
func annotateForecastPercentages(f forecast) {
	total := f.totalCount()
	if total == 0 {
		return
	}
	t := float64(total)
	f.setPct(
		float64(f.canFireCount())*100/t,
		float64(f.blockedCount())*100/t,
		float64(f.indeterminateCount())*100/t,
	)
}

// forecast is the minimal interface annotateForecastPercentages
// needs over the two forecast structs. Defined here (not in
// types.go) because it is an implementation detail of analysis,
// not a public surface.
type forecast interface {
	totalCount() int
	canFireCount() int
	blockedCount() int
	indeterminateCount() int
	setPct(canFire, blocked, indet float64)
}

func (c *ControlForecast) totalCount() int         { return c.Total }
func (c *ControlForecast) canFireCount() int       { return c.CanFire }
func (c *ControlForecast) blockedCount() int       { return c.Blocked }
func (c *ControlForecast) indeterminateCount() int { return c.Indeterminate }
func (c *ControlForecast) setPct(canFire, blocked, indet float64) {
	c.CanFirePct = canFire
	c.BlockedPct = blocked
	c.IndeterminatePct = indet
}

func (c *ChainForecast) totalCount() int         { return c.Total }
func (c *ChainForecast) canFireCount() int       { return c.CanFire }
func (c *ChainForecast) blockedCount() int       { return c.Blocked }
func (c *ChainForecast) indeterminateCount() int { return c.Indeterminate }
func (c *ChainForecast) setPct(canFire, blocked, indet float64) {
	c.CanFirePct = canFire
	c.BlockedPct = blocked
	c.IndeterminatePct = indet
}

func indexControls(controls []policy.ControlDefinition) map[kernel.ControlID]*policy.ControlDefinition {
	out := make(map[kernel.ControlID]*policy.ControlDefinition, len(controls))
	for i := range controls {
		out[controls[i].ID] = &controls[i]
	}
	return out
}

func anyObserved(types []kernel.AssetType, observed map[kernel.AssetType]int) bool {
	for _, t := range types {
		if observed[t] > 0 {
			return true
		}
	}
	return false
}
