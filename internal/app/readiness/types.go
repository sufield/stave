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
	ObservationCount int                       `json:"observation_count"`
	ObservedTypes    map[kernel.AssetType]int  `json:"observed_asset_types"`
	CatalogTypes     map[kernel.AssetType]bool `json:"catalog_asset_types"`

	// Per-control verdict counts.
	Controls ControlForecast `json:"controls"`

	// Per-chain verdict counts.
	Chains ChainForecast `json:"chains"`

	// Action plan: ranked unblockers.
	Actions []Action `json:"actions,omitempty"`

	// ReadinessScore = can_fire / (can_fire + blocked).
	// Indeterminate controls (those without applicable_asset_types)
	// are excluded from BOTH numerator and denominator because the
	// analyzer cannot statically classify them. ReadinessDenominator
	// names the bucket set explicitly so a consumer reading this
	// number alongside Controls.Total / Controls.Indeterminate cannot
	// mistake it for a whole-catalog fraction.
	ReadinessScore float64 `json:"readiness_score"`

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
// The three *Pct fields are bucket-share-of-Total, scaled 0..100
// (so 41.4 reads as 41.4%, not 0.414). They are derived from the
// integer counts at Analyze time so JSON consumers can render
// percentages without recomputing the math — and so the text
// renderer can show the same numbers a JSON consumer sees.
type ControlForecast struct {
	Total            int     `json:"total"`
	CanFire          int     `json:"can_fire"`
	Blocked          int     `json:"blocked"`
	Indeterminate    int     `json:"indeterminate"`
	CanFirePct       float64 `json:"can_fire_pct"`
	BlockedPct       float64 `json:"blocked_pct"`
	IndeterminatePct float64 `json:"indeterminate_pct"`
}

// ChainForecast classifies every chain. A chain can fire only
// if every member control can fire — one blocked member breaks
// the compound. *Pct fields use the same scale as ControlForecast.
type ChainForecast struct {
	Total            int     `json:"total"`
	CanFire          int     `json:"can_fire"`
	Blocked          int     `json:"blocked"`
	Indeterminate    int     `json:"indeterminate"`
	CanFirePct       float64 `json:"can_fire_pct"`
	BlockedPct       float64 `json:"blocked_pct"`
	IndeterminatePct float64 `json:"indeterminate_pct"`
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
