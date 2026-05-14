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
	"github.com/sufield/stave/internal/core/kernel"
)

// Report is the analyzer's output: a snapshot of what the
// catalog can evaluate against the supplied observations.
type Report struct {
	// Snapshot summary.
	ObservationCount int                          `json:"observation_count"`
	ObservedTypes    map[kernel.AssetType]int     `json:"observed_asset_types"`
	CatalogTypes     map[kernel.AssetType]bool    `json:"catalog_asset_types"`

	// Per-control verdict counts.
	Controls ControlForecast `json:"controls"`

	// Per-chain verdict counts.
	Chains ChainForecast `json:"chains"`

	// Action plan: ranked unblockers.
	Actions []Action `json:"actions,omitempty"`

	// ReadinessScore = controls_can_fire / total_controls.
	// Phase 1 is honest about what it measures: it is the
	// fraction of declared-asset-type controls whose assets are
	// observed. Controls without applicable_asset_types are
	// excluded from the denominator since the analyzer cannot
	// statically classify them.
	ReadinessScore float64 `json:"readiness_score"`
}

// ControlForecast classifies every control into one of three
// buckets. "Indeterminate" is the honest bucket for controls
// that declare no applicable_asset_types — the engine fires
// them on any asset, but the analyzer cannot predict whether
// they will produce findings.
type ControlForecast struct {
	Total         int `json:"total"`
	CanFire       int `json:"can_fire"`
	Blocked       int `json:"blocked"`
	Indeterminate int `json:"indeterminate"`
}

// ChainForecast classifies every chain. A chain can fire only
// if every member control can fire — one blocked member breaks
// the compound.
type ChainForecast struct {
	Total         int `json:"total"`
	CanFire       int `json:"can_fire"`
	Blocked       int `json:"blocked"`
	Indeterminate int `json:"indeterminate"`
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
