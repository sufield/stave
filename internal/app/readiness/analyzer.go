package readiness

import (
	"cmp"
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

	controlForecast, controlBlockers := classifyControls(controls, observedTypes)
	chainForecast, chainBlockers := classifyChains(controls, chains, observedTypes)
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
		report.Actions = rankActions(controlBlockers, chainBlockers, observedTypes, topN)
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
// control to one of three buckets. The blockers map collects,
// for each missing asset type, the count of declared-asset-type
// controls that would fire if it were observed. Controls
// without ApplicableAssetTypes are NOT added to the blockers
// map: the analyzer cannot statically predict their firing
// behavior, and inflating the action plan with them would
// mislead the operator.
func classifyControls(controls []policy.ControlDefinition, observed map[kernel.AssetType]int) (ControlForecast, map[kernel.AssetType]int) {
	forecast := ControlForecast{Total: len(controls)}
	blockers := map[kernel.AssetType]int{}
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
		// Every applicable type for this control is missing —
		// adding any one of them would unblock the control.
		for _, t := range applicable {
			blockers[t]++
		}
	}
	return forecast, blockers
}

// classifyChains classifies every chain by whether all member
// controls can fire. A chain is blocked if any member is
// blocked. A chain is indeterminate if no member is blocked but
// at least one is indeterminate (the chain may or may not fire
// depending on engine-time evaluation). The blockers map names
// the asset types that, if collected, would unblock the most
// chains.
func classifyChains(controls []policy.ControlDefinition, chains []policy.ChainDefinition, observed map[kernel.AssetType]int) (ChainForecast, map[kernel.AssetType]int) {
	ctlIndex := indexControls(controls)
	forecast := ChainForecast{Total: len(chains)}
	blockers := map[kernel.AssetType]int{}

	for i := range chains {
		chain := &chains[i]
		blocked := false
		indeterminate := false
		// Each chain member's missing asset types — collected
		// before classification, then attributed only if the
		// chain ends up blocked.
		chainMissing := map[kernel.AssetType]struct{}{}

		for _, memberID := range chain.ControlIDs {
			ctl, ok := ctlIndex[memberID]
			if !ok {
				// Member control not found in the loaded set —
				// treat as indeterminate rather than blocking.
				// The runtime chain loader emits its own warning
				// for this case.
				indeterminate = true
				continue
			}
			if len(ctl.ApplicableAssetTypes) == 0 {
				indeterminate = true
				continue
			}
			if !anyObserved(ctl.ApplicableAssetTypes, observed) {
				blocked = true
				for _, t := range ctl.ApplicableAssetTypes {
					chainMissing[t] = struct{}{}
				}
			}
		}

		switch {
		case blocked:
			forecast.Blocked++
			for t := range chainMissing {
				blockers[t]++
			}
		case indeterminate:
			forecast.Indeterminate++
		default:
			forecast.CanFire++
		}
	}
	return forecast, blockers
}

// rankActions merges the per-asset-type unblock counts from
// controls and chains and returns the top-N missing types ranked
// by (chains_unblocked desc, controls_unblocked desc, type asc).
// Chains rank first because they are the higher-leverage compound
// signal; controls break ties so the secondary unlock matters
// when chain counts equal.
func rankActions(controlBlockers, chainBlockers map[kernel.AssetType]int, observed map[kernel.AssetType]int, topN int) []Action {
	// Union of missing types referenced by either map.
	missing := map[kernel.AssetType]struct{}{}
	for t := range controlBlockers {
		if observed[t] == 0 {
			missing[t] = struct{}{}
		}
	}
	for t := range chainBlockers {
		if observed[t] == 0 {
			missing[t] = struct{}{}
		}
	}
	if len(missing) == 0 {
		return nil
	}
	actions := make([]Action, 0, len(missing))
	for t := range missing {
		actions = append(actions, Action{
			AssetType:         t,
			ChainsUnblocked:   chainBlockers[t],
			ControlsUnblocked: controlBlockers[t],
			Description:       describeAction(t),
		})
	}
	slices.SortFunc(actions, func(a, b Action) int {
		if n := cmp.Compare(b.ChainsUnblocked, a.ChainsUnblocked); n != 0 {
			return n
		}
		if n := cmp.Compare(b.ControlsUnblocked, a.ControlsUnblocked); n != 0 {
			return n
		}
		return cmp.Compare(a.AssetType, b.AssetType)
	})
	if len(actions) > topN {
		actions = actions[:topN]
	}
	return actions
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
