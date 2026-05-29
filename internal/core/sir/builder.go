package sir

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// ResourceFactGrouper is the seam between the SIR builder and
// the platform layer. The builder cannot import adapters
// (hexagonal); platform adapters (AWS S3, future per-service
// groupers) implement this interface and inject themselves via
// WithResourceFactGrouper.
//
// Iter L0 contract: the grouper takes raw snapshot assets and
// emits one ResourceFactGroup per resource it knows how to
// model. The grouper does NOT compose the inner vectors —
// composition is the solver's job. If a grouper finds itself
// writing if/switch on fact CONTENT (e.g.
// "if grant.IsPublic ..."), it has crossed into aggregation
// and must stop. Multiple groupers may be registered (one per
// service/vendor); their outputs are concatenated.
type ResourceFactGrouper interface {
	GroupResources(snapshots []asset.Snapshot, now time.Time) ([]ResourceFactGroup, error)
}

// LifecycleSource is the seam between the SIR builder and the
// engine's exposure-lifecycle pipeline. The lifecycle map is
// produced by engine.BuildLifecyclesPerControl, which itself
// requires a CEL evaluator the SIR core cannot import. Callers
// (the export-sir CLI, integration tests) build the lifecycle map
// outside the SIR package and inject it via WithLifecycleSource.
//
// The returned map is keyed (controlID → assetID → *ExposureLifecycle)
// — the exact shape engine.BuildLifecyclesPerControl emits — so the
// caller wires the engine call without translation. The builder
// walks the map, emits one ExposureWindow per (control, asset,
// archived-history-window), plus one window per still-active
// lifecycle terminating at EvaluatedAt.
type LifecycleSource interface {
	Lifecycles(controls []controldef.ControlDefinition, snapshots []asset.Snapshot) (map[kernel.ControlID]map[asset.ID]*asset.ExposureLifecycle, error)
}

// RoleChainSource is the seam between the SIR builder and the
// platform-side role-chain resolver (iam.ResolveChains). Role
// chains require AWS-specific principal/trust-policy/grant
// resolution that the SIR core cannot import. Platform adapters
// implement this interface, run iam.ResolveChains for every
// in-snapshot principal, translate the result into vendor-neutral
// RoleChainFact values, and return them keyed by principal ARN.
//
// The returned map is keyed by asset.ID (the principal's ARN
// in stave's ID vocabulary); the builder sorts each principal's
// chain list deterministically and attaches it to the matching
// IdentityFact.
type RoleChainSource interface {
	RoleChains(snapshots []asset.Snapshot) (map[asset.ID][]RoleChainFact, error)
}

// CoverageSource is the seam between the SIR builder and the
// engine's coverage validator. The validator's thresholds
// (continuity limit, minimum audit-window span) live on the
// engine.Assessor; SIR cannot import engine, so the platform
// adapter (sirbridge.EngineCoverageSource) reads them from the
// caller's configuration and translates the validator's
// per-lifecycle verdict into vendor-neutral CoverageGap rows.
//
// The lifecycle map is the same shape WithLifecycleSource
// produces; passing it here avoids re-running the engine.
type CoverageSource interface {
	Coverage(snapshots []asset.Snapshot, lifecycles map[kernel.ControlID]map[asset.ID]*asset.ExposureLifecycle) (CoverageReport, error)
}

// CoverageReport is the value returned by a CoverageSource. The
// Policy block reports the thresholds the validator graded
// against; Gaps enumerates the per-asset intervals where the
// observed cadence fell short. The builder sorts Gaps by
// (AssetID, Start) before exposing them; callers may return
// unordered input.
type CoverageReport struct {
	Policy CoveragePolicy
	Gaps   []CoverageGap
}

// Option configures a Builder.
type Option func(*Builder)

// WithResourceFactGrouper registers a per-service grouper that
// populates Document.ResourceGroups. May be called multiple
// times; groupers run in registration order and their outputs
// are concatenated. Iter L0: the AWS S3 grouper from L4
// replaces the retired EffectivePermissionAggregator pattern.
func WithResourceFactGrouper(g ResourceFactGrouper) Option {
	return func(b *Builder) { b.groupers = append(b.groupers, g) }
}

// WithLifecycleSource registers the lifecycle pipeline that
// hydrates Temporal.Windows. Without this option, the SIR's
// temporal grid contains observation timestamps but no exposure
// windows.
func WithLifecycleSource(s LifecycleSource) Option {
	return func(b *Builder) { b.lifecycles = s }
}

// WithRoleChainSource registers the platform-side role-chain
// resolver that hydrates IdentityFact.RoleChains. Without this
// option, identities export with empty chain lists — the solver
// will not see transitive cross-account paths.
func WithRoleChainSource(s RoleChainSource) Option {
	return func(b *Builder) { b.roleChains = s }
}

// WithCoverageSource registers the platform-side coverage
// validator that hydrates Temporal.Coverage and Temporal.Gaps.
// Without this option, those fields stay at zero-value — the
// SIR cannot distinguish observed-safe from unobserved.
func WithCoverageSource(s CoverageSource) Option {
	return func(b *Builder) { b.coverage = s }
}

// Builder assembles a Document from controls + snapshots. Construct
// via NewBuilder; the zero value is not usable because options must
// flow through the constructor.
type Builder struct {
	groupers   []ResourceFactGrouper
	lifecycles LifecycleSource
	roleChains RoleChainSource
	coverage   CoverageSource
}

// NewBuilder returns a Builder configured with the supplied options.
func NewBuilder(opts ...Option) *Builder {
	b := &Builder{}
	for _, o := range opts {
		o(b)
	}
	return b
}

// Build produces the SIR Document for the given inputs. now is the
// caller-supplied evaluation time — typically the resolved value of
// the `--now` flag — and is recorded directly as Document.EvaluatedAt.
// Build never reads the process wall clock; determinism for the same inputs
// is guaranteed.
//
// Build returns an error only when an aggregator does. Translation
// from controls/snapshots to facts is total: every input shape is
// handled.
func (b *Builder) Build(controls []controldef.ControlDefinition, snapshots []asset.Snapshot, now time.Time) (*Document, error) {
	doc := &Document{EvaluatedAt: now}

	driftMap, err := computeDriftMap(snapshots)
	if err != nil {
		return nil, fmt.Errorf("compute drift: %w", err)
	}

	doc.Controls = buildControlFacts(controls)
	doc.Assets = buildAssetFacts(snapshots, driftMap)

	chainMap, err := b.collectRoleChains(snapshots)
	if err != nil {
		return nil, fmt.Errorf("role chains: %w", err)
	}
	doc.Identities = buildIdentityFacts(snapshots, chainMap)

	lifecycles, err := b.collectLifecycles(controls, snapshots)
	if err != nil {
		return nil, fmt.Errorf("lifecycles: %w", err)
	}
	coverage, err := b.collectCoverage(snapshots, lifecycles)
	if err != nil {
		return nil, fmt.Errorf("coverage: %w", err)
	}
	doc.Temporal = buildTemporalFacts(snapshots, lifecycles, coverage, now)

	for i, grouper := range b.groupers {
		groups, gerr := grouper.GroupResources(snapshots, now)
		if gerr != nil {
			return nil, fmt.Errorf("grouper %d: %w", i, gerr)
		}
		doc.ResourceGroups = append(doc.ResourceGroups, groups...)
	}
	sortResourceGroups(doc.ResourceGroups)

	return doc, nil
}

// collectRoleChains runs the registered RoleChainSource (if any)
// and returns its keyed output. Empty map (not nil) means "source
// supplied but yielded no chains" — the IdentityFact builder
// distinguishes "no source" from "source ran clean."
func (b *Builder) collectRoleChains(snapshots []asset.Snapshot) (map[asset.ID][]RoleChainFact, error) {
	if b.roleChains == nil {
		return nil, nil
	}
	return b.roleChains.RoleChains(snapshots)
}

// collectLifecycles runs the registered LifecycleSource (if any).
// Returns nil-map / nil-error in adapter-free configurations; the
// TemporalFacts builder treats nil as "no exposure windows to
// emit" rather than as a degenerate failure.
func (b *Builder) collectLifecycles(controls []controldef.ControlDefinition, snapshots []asset.Snapshot) (map[kernel.ControlID]map[asset.ID]*asset.ExposureLifecycle, error) {
	if b.lifecycles == nil {
		return nil, nil
	}
	return b.lifecycles.Lifecycles(controls, snapshots)
}

// collectCoverage runs the registered CoverageSource (if any).
// Returns a zero-value report (zero-policy, nil gaps) when no
// source is registered — buildTemporalFacts forwards both to the
// resulting Document so the SIR shape is uniform whether or not
// coverage hydration ran.
func (b *Builder) collectCoverage(snapshots []asset.Snapshot, lifecycles map[kernel.ControlID]map[asset.ID]*asset.ExposureLifecycle) (CoverageReport, error) {
	if b.coverage == nil {
		return CoverageReport{}, nil
	}
	return b.coverage.Coverage(snapshots, lifecycles)
}

// buildControlFacts translates a control catalog into deterministic,
// ID-sorted ControlFact rows.
func buildControlFacts(controls []controldef.ControlDefinition) []ControlFact {
	if len(controls) == 0 {
		return nil
	}
	out := make([]ControlFact, 0, len(controls))
	for i := range controls {
		ctl := &controls[i]
		fact := ControlFact{
			ID:              string(ctl.ID),
			Type:            ctl.Type.String(),
			Severity:        ctl.Severity.String(),
			Predicate:       predicateFactFromTopLevel(&ctl.UnsafePredicate, string(ctl.ID)),
			IntentRationale: ctl.IntentRationale,
			Source:          SourceRef{Kind: "control", ID: string(ctl.ID)},
		}
		if ctl.HasMaxUnsafeDuration() {
			h := ctl.MaxUnsafeDuration().Hours()
			fact.ThresholdHours = &h
		}
		if !ctl.ForbiddenState.IsEmpty() {
			fb := forbiddenStateFact(&ctl.ForbiddenState, string(ctl.ID))
			fact.ForbiddenState = &fb
		}
		out = append(out, fact)
	}
	slices.SortFunc(out, func(a, b ControlFact) int { return cmp.Compare(a.ID, b.ID) })
	return out
}

// forbiddenStateFact translates a control's ForbiddenState
// invariant into the SIR's nested predicate shape. Reuses the
// same Any/All collapse logic as the unsafe-predicate path so
// authors can express invariants with the predicate vocabulary
// they already know. The Path prefix differs ("forbidden_state"
// rather than "unsafe_predicate") so a SourceRef trace can tell
// the two sources apart.
func forbiddenStateFact(p *controldef.UnsafePredicate, controlID string) PredicateFact {
	if p == nil || p.IsEmpty() {
		return PredicateFact{}
	}
	if len(p.Any) > 0 && len(p.All) == 0 {
		return PredicateFact{
			Logic: "any",
			Rules: rulesFrom(p.Any, controlID, []string{"forbidden_state", "any"}),
		}
	}
	if len(p.All) > 0 && len(p.Any) == 0 {
		return PredicateFact{
			Logic: "all",
			Rules: rulesFrom(p.All, controlID, []string{"forbidden_state", "all"}),
		}
	}
	return PredicateFact{
		Logic: "all",
		Rules: []RuleFact{
			{
				Nested: &PredicateFact{
					Logic: "any",
					Rules: rulesFrom(p.Any, controlID, []string{"forbidden_state", "any"}),
				},
				Source: SourceRef{Kind: "control", ID: controlID, Path: []string{"forbidden_state", "any"}},
			},
			{
				Nested: &PredicateFact{
					Logic: "all",
					Rules: rulesFrom(p.All, controlID, []string{"forbidden_state", "all"}),
				},
				Source: SourceRef{Kind: "control", ID: controlID, Path: []string{"forbidden_state", "all"}},
			},
		},
	}
}

// predicateFactFromTopLevel collapses controldef.UnsafePredicate's
// (Any, All) pair into a single PredicateFact node. When both are
// populated the SIR represents the implicit AND by wrapping the Any
// branch as a nested rule under an outer "all" — the Z3 translator
// handles either shape uniformly. The common case (only one of Any
// / All set) emits a flat node.
func predicateFactFromTopLevel(p *controldef.UnsafePredicate, controlID string) PredicateFact {
	if p == nil || p.IsEmpty() {
		return PredicateFact{}
	}
	if len(p.Any) > 0 && len(p.All) == 0 {
		return PredicateFact{
			Logic: "any",
			Rules: rulesFrom(p.Any, controlID, []string{"unsafe_predicate", "any"}),
		}
	}
	if len(p.All) > 0 && len(p.Any) == 0 {
		return PredicateFact{
			Logic: "all",
			Rules: rulesFrom(p.All, controlID, []string{"unsafe_predicate", "all"}),
		}
	}
	// Both populated: the controldef contract is implicit AND.
	return PredicateFact{
		Logic: "all",
		Rules: []RuleFact{
			{
				Nested: &PredicateFact{
					Logic: "any",
					Rules: rulesFrom(p.Any, controlID, []string{"unsafe_predicate", "any"}),
				},
				Source: SourceRef{Kind: "control", ID: controlID, Path: []string{"unsafe_predicate", "any"}},
			},
			{
				Nested: &PredicateFact{
					Logic: "all",
					Rules: rulesFrom(p.All, controlID, []string{"unsafe_predicate", "all"}),
				},
				Source: SourceRef{Kind: "control", ID: controlID, Path: []string{"unsafe_predicate", "all"}},
			},
		},
	}
}

func rulesFrom(rules []controldef.PredicateRule, controlID string, base []string) []RuleFact {
	if len(rules) == 0 {
		return nil
	}
	out := make([]RuleFact, 0, len(rules))
	for i := range rules {
		path := append(append([]string{}, base...), strconv.Itoa(i))
		out = append(out, ruleFactFrom(&rules[i], controlID, path))
	}
	return out
}

func ruleFactFrom(r *controldef.PredicateRule, controlID string, path []string) RuleFact {
	src := SourceRef{Kind: "control", ID: controlID, Path: path}

	// Nested any/all blocks take precedence over the field shape
	// because controldef accepts either, but never both, on a single
	// rule (validated upstream).
	if len(r.Any) > 0 {
		return RuleFact{
			Nested: &PredicateFact{Logic: "any", Rules: rulesFrom(r.Any, controlID, append(path, "any"))},
			Source: src,
		}
	}
	if len(r.All) > 0 {
		return RuleFact{
			Nested: &PredicateFact{Logic: "all", Rules: rulesFrom(r.All, controlID, append(path, "all"))},
			Source: src,
		}
	}

	return RuleFact{
		Field:    r.Field.String(),
		Operator: string(r.Op),
		Value:    r.Value.Raw(),
		Source:   src,
	}
}

// buildAssetFacts collects every asset across all snapshots,
// deduplicating by ID (last-snapshot-wins on collision so the
// most-recent observation drives the SIR view), and emits an
// ID-sorted slice. Properties is carried by reference; callers
// must not mutate the SIR after Build returns. driftMap (when
// non-nil) supplies the provisioned/decommissioned transition
// state from the latest snapshot pair; first/last-seen times come
// from walking every snapshot regardless.
func buildAssetFacts(snapshots []asset.Snapshot, driftMap map[asset.ID]asset.DriftType) []AssetFact {
	if len(snapshots) == 0 {
		return nil
	}
	seen := make(map[asset.ID]AssetFact)
	firstSeen := make(map[asset.ID]time.Time)
	lastSeen := make(map[asset.ID]time.Time)
	for i := range snapshots {
		ts := snapshots[i].CapturedAt
		for j := range snapshots[i].Assets {
			a := &snapshots[i].Assets[j]
			seen[a.ID] = AssetFact{
				ID:         string(a.ID),
				Type:       string(a.Type),
				Vendor:     string(a.Vendor),
				Properties: a.Properties,
				Source:     SourceRef{Kind: "asset", ID: string(a.ID)},
			}
			if !ts.IsZero() {
				if existing, ok := firstSeen[a.ID]; !ok || ts.Before(existing) {
					firstSeen[a.ID] = ts
				}
				if existing, ok := lastSeen[a.ID]; !ok || ts.After(existing) {
					lastSeen[a.ID] = ts
				}
			}
		}
	}
	out := make([]AssetFact, 0, len(seen))
	for id, f := range seen {
		f.Lifecycle = lifecycleFromDrift(driftMap[id], firstSeen[id], lastSeen[id])
		out = append(out, f)
	}
	slices.SortFunc(out, func(a, b AssetFact) int { return cmp.Compare(a.ID, b.ID) })
	return out
}

// lifecycleFromDrift assembles an AssetLifecycleFact from the
// drift transition (if any) for an asset and its first/last seen
// timestamps. Returns nil for assets that have no transition AND
// no observation timestamps — in that degenerate case the SIR
// omits the lifecycle block entirely rather than emitting an
// all-zero one that the solver would have to special-case.
func lifecycleFromDrift(driftKind asset.DriftType, firstSeen, lastSeen time.Time) *AssetLifecycleFact {
	if driftKind == "" && firstSeen.IsZero() && lastSeen.IsZero() {
		return nil
	}
	return &AssetLifecycleFact{
		Provisioned:    driftKind == asset.DriftProvisioned,
		Decommissioned: driftKind == asset.DriftDecommissioned,
		FirstSeen:      firstSeen,
		LastSeen:       lastSeen,
	}
}

// computeDriftMap calls asset.ComputeDrift on the most recent
// snapshot pair and returns a per-asset transition map. Snapshots
// are sorted by CapturedAt inside ComputeDrift / GetStateTransition,
// so callers do not need to pre-sort. Single-snapshot inputs
// produce an empty map (no transition is observable from one
// point in time).
//
// asset.ErrInsufficientSnapshots and asset.ErrSnapshotsNotOrdered
// are non-fatal here — they signal "no comparable transition
// data" rather than a corrupted input. The SIR proceeds without
// drift transitions; first/last-seen still populates from the
// observation timestamps.
func computeDriftMap(snapshots []asset.Snapshot) (map[asset.ID]asset.DriftType, error) {
	if len(snapshots) < 2 {
		return nil, nil
	}
	prev, curr, err := asset.GetStateTransition(snapshots)
	if err != nil {
		if errors.Is(err, asset.ErrInsufficientSnapshots) || errors.Is(err, asset.ErrSnapshotsNotOrdered) {
			return nil, nil
		}
		return nil, err
	}
	drift, err := asset.ComputeDrift(prev, curr)
	if err != nil {
		return nil, err
	}
	out := make(map[asset.ID]asset.DriftType, len(drift.Changes))
	for i := range drift.Changes {
		out[drift.Changes[i].AssetID] = drift.Changes[i].Action
	}
	return out, nil
}

// buildIdentityFacts collects identities across snapshots,
// deduplicating by ID, attaches role-chain hydration when a
// RoleChainSource is registered, and emits a PrincipalID-sorted
// slice. Validity windows are still empty in 1.3; future
// iterations populate them from the resolved-permissions
// pipeline.
func buildIdentityFacts(snapshots []asset.Snapshot, chains map[asset.ID][]RoleChainFact) []IdentityFact {
	if len(snapshots) == 0 {
		return nil
	}
	seen := make(map[asset.ID]struct{})
	out := make([]IdentityFact, 0)
	for i := range snapshots {
		for j := range snapshots[i].Identities {
			ci := &snapshots[i].Identities[j]
			id := ci.ID
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			fact := IdentityFact{
				PrincipalID: string(id),
				Source:      SourceRef{Kind: "identity", ID: string(id)},
			}
			// Clone Properties so a downstream consumer that
			// mutates the SIR fact's map cannot leak edits back
			// into the original observation snapshot. Empty maps
			// are dropped (omitempty on the JSON tag handles the
			// wire side; this skips the allocation on the Go side).
			if len(ci.Properties) > 0 {
				props := make(map[string]any, len(ci.Properties))
				maps.Copy(props, ci.Properties)
				fact.Properties = props
			}
			if chain, ok := chains[id]; ok && len(chain) > 0 {
				cloned := make([]RoleChainFact, len(chain))
				copy(cloned, chain)
				sortRoleChains(cloned)
				fact.RoleChains = cloned
			}
			out = append(out, fact)
		}
	}
	slices.SortFunc(out, func(a, b IdentityFact) int { return cmp.Compare(a.PrincipalID, b.PrincipalID) })
	return out
}

// sortRoleChains imposes a total order on a single principal's
// chain list: by FinalRoleARN, then by hop count, then by the
// FromARN of the first hop. Stability matters because the chain
// list flows directly into JSON; without sorting, map iteration
// in the source could leak nondeterminism.
func sortRoleChains(chains []RoleChainFact) {
	slices.SortFunc(chains, func(a, b RoleChainFact) int {
		if n := cmp.Compare(a.FinalRoleARN, b.FinalRoleARN); n != 0 {
			return n
		}
		if n := cmp.Compare(len(a.Hops), len(b.Hops)); n != 0 {
			return n
		}
		switch {
		case len(a.Hops) == 0 && len(b.Hops) == 0:
			return 0
		case len(a.Hops) == 0:
			return -1
		case len(b.Hops) == 0:
			return 1
		}
		return cmp.Compare(a.Hops[0].From, b.Hops[0].From)
	})
}

// buildTemporalFacts records the snapshot capture grid AND, when a
// LifecycleSource is registered, the per-(control, asset) exposure
// windows derived from the engine's lifecycle pipeline. One window
// per archived history entry plus one window per still-active
// lifecycle (terminating at `now` rather than being dropped — Z3
// needs to see in-progress exposure to grade dwell-time).
//
// ContributingControls always carries exactly the one control ID
// whose lifecycle produced the window. Cross-control merging
// (combining overlapping windows from different controls into one
// window with multiple contributors) is intentionally NOT done
// here — it would be re-implementing logic that doesn't yet exist
// upstream, violating the "DO NOT re-implement" constraint. A
// future merger can run as a downstream pass if needed.
func buildTemporalFacts(snapshots []asset.Snapshot, lifecycles map[kernel.ControlID]map[asset.ID]*asset.ExposureLifecycle, coverage CoverageReport, now time.Time) TemporalFacts {
	temporal := TemporalFacts{}
	if len(snapshots) > 0 {
		obs := make([]time.Time, 0, len(snapshots))
		for i := range snapshots {
			if snapshots[i].HasTimestamp() {
				obs = append(obs, snapshots[i].CapturedAt)
			}
		}
		slices.SortFunc(obs, func(a, b time.Time) int { return a.Compare(b) })
		temporal.Observations = obs
	}
	temporal.Windows = exposureWindowsFromLifecycles(lifecycles, now)
	temporal.Coverage = coverage.Policy
	if len(coverage.Gaps) > 0 {
		gaps := make([]CoverageGap, len(coverage.Gaps))
		copy(gaps, coverage.Gaps)
		slices.SortFunc(gaps, func(a, b CoverageGap) int {
			if n := cmp.Compare(a.AssetID, b.AssetID); n != 0 {
				return n
			}
			if n := a.Start.Compare(b.Start); n != 0 {
				return n
			}
			return cmp.Compare(a.Reason, b.Reason)
		})
		temporal.Gaps = gaps
	}
	return temporal
}

// exposureWindowsFromLifecycles walks a per-control lifecycle map
// and emits one ExposureWindow per archived history entry plus one
// per still-active lifecycle. The emitted slice is sorted by
// (AssetID, Start, ContributingControls[0]) for determinism.
func exposureWindowsFromLifecycles(lifecycles map[kernel.ControlID]map[asset.ID]*asset.ExposureLifecycle, now time.Time) []ExposureWindow {
	if len(lifecycles) == 0 {
		return nil
	}
	out := make([]ExposureWindow, 0)
	for controlID, perAsset := range lifecycles {
		for assetID, lc := range perAsset {
			if lc == nil {
				continue
			}
			for _, w := range lc.History().Windows() {
				out = append(out, ExposureWindow{
					AssetID:                string(assetID),
					Start:                  w.OpenedAt(),
					End:                    w.ResolvedAt(),
					UnsafePredicateMatched: true,
					ContributingControls:   []string{string(controlID)},
				})
			}
			if lc.HasActiveWindow() {
				out = append(out, ExposureWindow{
					AssetID:                string(assetID),
					Start:                  lc.FirstExposedAt(),
					End:                    now,
					UnsafePredicateMatched: true,
					ContributingControls:   []string{string(controlID)},
				})
			}
		}
	}
	slices.SortFunc(out, func(a, b ExposureWindow) int {
		if n := cmp.Compare(a.AssetID, b.AssetID); n != 0 {
			return n
		}
		if n := a.Start.Compare(b.Start); n != 0 {
			return n
		}
		switch {
		case len(a.ContributingControls) == 0 && len(b.ContributingControls) == 0:
			return 0
		case len(a.ContributingControls) == 0:
			return -1
		case len(b.ContributingControls) == 0:
			return 1
		}
		return cmp.Compare(a.ContributingControls[0], b.ContributingControls[0])
	})
	return out
}

// sortResourceGroups enforces a total order on the per-resource
// fact groups so identical inputs produce byte-identical output.
// Sort key: (Vendor, ServiceArea, AssetID). Inner-vector
// ordering is the grouper's / extractor's responsibility — they
// preserve original positional indices (StatementIndex,
// ACL Grants[i], etc.) which are part of the SourceRef contract.
func sortResourceGroups(groups []ResourceFactGroup) {
	slices.SortFunc(groups, func(a, b ResourceFactGroup) int {
		if n := cmp.Compare(a.Vendor, b.Vendor); n != 0 {
			return n
		}
		if n := cmp.Compare(a.ServiceArea, b.ServiceArea); n != 0 {
			return n
		}
		return cmp.Compare(a.AssetID, b.AssetID)
	})
}
