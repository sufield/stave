// Package readiness produces a pre-evaluation report describing
// what Stave's catalog CAN'T detect against a given observation
// snapshot, due to missing collector domains. The report is
// advisory: it does not gate stave apply, and it does not run
// the evaluation engine. It answers "is the snapshot rich enough
// to exercise Stave's detection capability?" not "is the
// snapshot finding violations?"
//
// Phase 1 scope: observation-coverage and chain-effectiveness
// only. Two further dimensions named in the original design —
// intent declarations (data_classification tags, role-type
// labels, vendor_registry.yaml presence) and foundational
// configurations (CloudTrail enabled, IMDSv2 enforced, GuardDuty
// baseline) — are deferred. Both require per-control predicate
// inspection or a separate "foundational requirements" registry
// that the current catalog does not expose, and shipping them
// before that data is in place would produce false-precision
// output.
package readiness

import (
	"slices"

	"github.com/sufield/stave/internal/core/kernel"
)

// ReadinessScore encapsulates a readiness capability score (0.0 to 1.0).
type ReadinessScore float64

// Value returns the raw float64 readiness score ratio (between 0.0 and 1.0).
func (rs ReadinessScore) Value() float64 {
	return float64(rs)
}

// Percentage returns the readiness score expressed as a percentage value (0.0 to 100.0).
func (rs ReadinessScore) Percentage() float64 {
	return float64(rs) * 100.0
}

// IsFullReadiness reports whether the readiness score is 1.0 (100% ready).
func (rs ReadinessScore) IsFullReadiness() bool {
	return rs >= 1.0
}

// IsZero reports whether the readiness score is zero.
func (rs ReadinessScore) IsZero() bool {
	return rs == 0.0
}

// ObservedAssetTypes is a domain collection mapping observed asset types to their occurrence counts.
type ObservedAssetTypes map[kernel.AssetType]int

// Len returns the number of distinct observed asset types.
func (o ObservedAssetTypes) Len() int {
	return len(o)
}

// TotalAssets returns the sum of occurrence counts across all observed asset types.
func (o ObservedAssetTypes) TotalAssets() int {
	total := 0
	for _, count := range o {
		total += count
	}
	return total
}

// SortedTypes returns the list of observed asset types sorted alphabetically.
func (o ObservedAssetTypes) SortedTypes() []kernel.AssetType {
	if len(o) == 0 {
		return nil
	}
	types := make([]kernel.AssetType, 0, len(o))
	for t := range o {
		types = append(types, t)
	}
	slices.Sort(types)
	return types
}

// CountFor returns the occurrence count for a specific asset type, or 0 if not present.
func (o ObservedAssetTypes) CountFor(at kernel.AssetType) int {
	if o == nil {
		return 0
	}
	return o[at]
}

// Contains reports whether the given asset type is present in observed asset types.
func (o ObservedAssetTypes) Contains(at kernel.AssetType) bool {
	if o == nil {
		return false
	}
	_, ok := o[at]
	return ok
}

// AnyObserved reports whether any of the given asset types has observed resources.
func (o ObservedAssetTypes) AnyObserved(types []kernel.AssetType) bool {
	for _, t := range types {
		if o[t] > 0 {
			return true
		}
	}
	return false
}

// CatalogAssetTypes is a domain collection of asset types declared in the control catalog.
type CatalogAssetTypes map[kernel.AssetType]bool

// Len returns the number of catalog asset types.
func (c CatalogAssetTypes) Len() int {
	return len(c)
}

// SortedTypes returns the catalog asset types sorted alphabetically.
func (c CatalogAssetTypes) SortedTypes() []kernel.AssetType {
	if len(c) == 0 {
		return nil
	}
	types := make([]kernel.AssetType, 0, len(c))
	for t := range c {
		types = append(types, t)
	}
	slices.Sort(types)
	return types
}

// Contains reports whether the given asset type is declared in the catalog.
func (c CatalogAssetTypes) Contains(at kernel.AssetType) bool {
	if c == nil {
		return false
	}
	return c[at]
}

// Report is the analyzer's output: a snapshot of what the
// catalog can evaluate against the supplied observations.
type Report struct {
	// Snapshot summary.
	ObservationCount int                `json:"observation_count"`
	ObservedTypes    ObservedAssetTypes `json:"observed_asset_types"`
	CatalogTypes     CatalogAssetTypes  `json:"catalog_asset_types"`

	// Per-control verdict counts.
	Controls ControlForecast `json:"controls"`

	// Per-chain verdict counts.
	Chains ChainForecast `json:"chains"`

	// Action plan: ranked unblockers.
	Actions Actions `json:"actions,omitempty"`

	// ReadinessScore = can_fire / (can_fire + blocked).
	// Indeterminate controls (those without applicable_asset_types)
	// are excluded from BOTH numerator and denominator because the
	// analyzer cannot statically classify them. ReadinessDenominator
	// names the bucket set explicitly so a consumer reading this
	// number alongside Controls.Total / Controls.Indeterminate cannot
	// mistake it for a whole-catalog fraction.
	ReadinessScore ReadinessScore `json:"readiness_score"`

	// ReadinessDenominator self-documents what the score divides
	// by. Constant string; the analyzer always sets it the same
	// way. Present so JSON consumers don't need to read this file's
	// godoc to know what 0.41 means.
	ReadinessDenominator string `json:"readiness_denominator"`
}

// ControlForecast classifies every control into one of three
// buckets. "Indeterminate" is the honest bucket for controls
// that declare no applicable_asset_types — the engine fires
// them on any asset, but the analyzer cannot predict whether
// they will produce findings.
//
// ForecastPercentage represents a bucket-share percentage between 0.0 and 100.0.
type ForecastPercentage float64

// Float64 returns the raw float64 percentage value.
func (p ForecastPercentage) Float64() float64 {
	return float64(p)
}

// Ratio returns the percentage expressed as a ratio between 0.0 and 1.0.
func (p ForecastPercentage) Ratio() float64 {
	return float64(p) / 100.0
}

// IsZero reports whether the percentage is zero.
func (p ForecastPercentage) IsZero() bool {
	return p == 0.0
}

// IsComplete reports whether the percentage represents 100% full coverage.
func (p ForecastPercentage) IsComplete() bool {
	return p >= 100.0
}

// The three *Pct fields are bucket-share-of-Total, scaled 0..100
// (so 41.4 reads as 41.4%, not 0.414). They are derived from the
// integer counts at Analyze time so JSON consumers can render
// percentages without recomputing the math — and so the text
// renderer can show the same numbers a JSON consumer sees.
type ControlForecast struct {
	Total            int                `json:"total"`
	CanFire          int                `json:"can_fire"`
	Blocked          int                `json:"blocked"`
	Indeterminate    int                `json:"indeterminate"`
	CanFirePct       ForecastPercentage `json:"can_fire_pct"`
	BlockedPct       ForecastPercentage `json:"blocked_pct"`
	IndeterminatePct ForecastPercentage `json:"indeterminate_pct"`
}

// ActiveTotal returns the total count of classifiable controls (CanFire + Blocked).
func (cf ControlForecast) ActiveTotal() int {
	return cf.CanFire + cf.Blocked
}

// HasBlocked reports whether any controls are blocked.
func (cf ControlForecast) HasBlocked() bool {
	return cf.Blocked > 0
}

// HasIndeterminate reports whether any controls have indeterminate applicability.
func (cf ControlForecast) HasIndeterminate() bool {
	return cf.Indeterminate > 0
}

// IsFullyReady reports whether all classifiable controls can fire and at least one can fire.
func (cf ControlForecast) IsFullyReady() bool {
	return cf.Blocked == 0 && cf.CanFire > 0
}

// ChainForecast classifies every chain. A chain can fire only
// if every member control can fire — one blocked member breaks
// the compound. *Pct fields use the same scale as ControlForecast.
type ChainForecast struct {
	Total            int                `json:"total"`
	CanFire          int                `json:"can_fire"`
	Blocked          int                `json:"blocked"`
	Indeterminate    int                `json:"indeterminate"`
	CanFirePct       ForecastPercentage `json:"can_fire_pct"`
	BlockedPct       ForecastPercentage `json:"blocked_pct"`
	IndeterminatePct ForecastPercentage `json:"indeterminate_pct"`
}

// ActiveTotal returns the total count of classifiable chains (CanFire + Blocked).
func (cf ChainForecast) ActiveTotal() int {
	return cf.CanFire + cf.Blocked
}

// HasBlocked reports whether any chains are blocked.
func (cf ChainForecast) HasBlocked() bool {
	return cf.Blocked > 0
}

// HasIndeterminate reports whether any chains have indeterminate applicability.
func (cf ChainForecast) HasIndeterminate() bool {
	return cf.Indeterminate > 0
}

// IsFullyReady reports whether all classifiable chains can fire and at least one can fire.
func (cf ChainForecast) IsFullyReady() bool {
	return cf.Blocked == 0 && cf.CanFire > 0
}

// Action is one unblocking step the operator can take. Ordered
// by combined chain + control unlock count (descending) in the
// output. Phase 1 emits asset-type-level actions ("collect IAM
// observations") and does not synthesize per-resource AWS CLI
// commands; that level of specificity belongs to a follow-on
// iteration with a registered collector vocabulary.
type Action struct {
	AssetType         kernel.AssetType `json:"asset_type"`
	ChainsUnblocked   int              `json:"chains_unblocked"`
	ControlsUnblocked int              `json:"controls_unblocked"`
	Description       string           `json:"description"`
}

// Actions represents a collection of readiness Action recommendations with query and summary methods.
type Actions []Action

// Len returns the number of actions.
func (a Actions) Len() int {
	return len(a)
}

// TotalControlsUnblocked returns the sum of controls unblocked across all actions.
func (a Actions) TotalControlsUnblocked() int {
	total := 0
	for _, act := range a {
		total += act.ControlsUnblocked
	}
	return total
}

// TotalChainsUnblocked returns the sum of chains unblocked across all actions.
func (a Actions) TotalChainsUnblocked() int {
	total := 0
	for _, act := range a {
		total += act.ChainsUnblocked
	}
	return total
}
